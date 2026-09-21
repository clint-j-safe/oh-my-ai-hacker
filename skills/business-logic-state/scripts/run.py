#!/usr/bin/env python3
"""
run.py -- business-logic-state entry point.

Tests multi-step workflows for logic flaws: race conditions (bounded concurrent
execution), step-skipping (omitting a required step such as payment), and
parameter tampering (negative quantity / price manipulation).

SAFETY MODEL (the highest-blast-radius battery -- guardrails are load-bearing)
------------------------------------------------------------------------------
* HARD MUTATION GATE. Business-logic testing mutates application state by
  nature. The skill refuses to send any non-GET step unless
  config.authorize_mutations is explicitly true; otherwise it returns a fatal
  artifact requesting mutation authorization (an explicit mutation budget). It
  never turns this on by itself.
* Bounded. Race concurrency is capped (config.race_count, hard max
  config.race_max, default 50). Nothing runs unbounded.
* Accountable. Every mutating request is appended to a mutation ledger
  (meta.mutations) with its workflow, for the cleanup report.
* Isolated + scoped. Each test runs in a FRESH session; only in-scope hosts are
  driven; full transaction logs are offloaded to the spill store.

CONTRACT
--------
* Input  : {"target_base": "https://app", "workflows": [ {steps:[...], ...} ],
            "session_spill_id": "...", "scope_policy_spill_id": "...",
            "config": {"authorize_mutations": false, "race_count": 20}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).

A workflow step is a request template:
  {"name","method","url","body":{...},"type":"json|form|query",
   "success":"<regex>"(optional)}
Workflow keys: name, steps[], race_step, race_single_use(default true),
skip_steps[], tamper:{step, fields[]}, state_check_url, success_indicator.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

try:
    import httpx  # type: ignore
except ImportError:  # pragma: no cover
    httpx = None

try:
    from spill_store import read_spill, write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill, write_spill  # type: ignore

REQ_TIMEOUT = float(os.environ.get("LOGIC_TIMEOUT", "20"))
DEFAULT_RACE = int(os.environ.get("LOGIC_RACE_COUNT", "20"))
RACE_HARD_MAX = int(os.environ.get("LOGIC_RACE_MAX", "50"))
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_NEG_TOTAL = re.compile(r"(total|amount|price|balance|qty|quantity)\D{0,6}-\d", re.I)
_ERROR_SIG = re.compile(r"error|invalid|reject|not allowed|forbidden|must be|too (large|small)", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


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


class LogicTester:
    def __init__(self, workflows: List[dict], target_base: str = "",
                 session: Optional[dict] = None, scope_policy_spill_id: Optional[str] = None,
                 config: Optional[dict] = None):
        self.workflows = workflows or []
        self.base = (target_base or "").strip()
        self.session = session or {}
        self.config = config or {}
        self.authorized = bool(self.config.get("authorize_mutations", False))
        self.race_count = min(int(self.config.get("race_count", DEFAULT_RACE)),
                              int(self.config.get("race_max", RACE_HARD_MAX)))
        self.errors: List[Dict[str, str]] = []
        self.mutations: List[dict] = []
        hosts = []
        for wf in self.workflows:
            for st in wf.get("steps", []):
                hosts.append(_host_of(self._abs(st.get("url", ""))))
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
        return urljoin(self.base + ("/" if self.base and not self.base.endswith("/") else ""), url.lstrip("/"))

    def _session_cookies(self) -> Dict[str, str]:
        return {c.get("name"): c.get("value", "") for c in self.session.get("cookies", []) if c.get("name")}

    # -- step execution --------------------------------------------------------
    async def _do_step(self, client, step: dict, workflow: str,
                       overrides: Optional[dict] = None) -> Tuple[int, str]:
        url = self._abs(step.get("url", ""))
        if not self.scope.allowed(_host_of(url)):
            return 0, "__SCOPE__"
        method = (step.get("method") or "GET").upper()
        body = dict(step.get("body") or {})
        if overrides:
            body.update(overrides)
        if method not in SAFE_METHODS:
            self.mutations.append({"workflow": workflow, "step": step.get("name"),
                                   "method": method, "url": url, "body": body, "at": _now_iso()})
        try:
            ctype = (step.get("type") or "json").lower()
            if method in SAFE_METHODS:
                r = await client.request(method, url, params=body or None)
            elif ctype == "form":
                r = await client.request(method, url, data=body)
            elif ctype == "query":
                r = await client.request(method, url, params=body)
            else:
                r = await client.request(method, url, json=body)
            return r.status_code, r.text
        except Exception as exc:  # noqa: BLE001
            return 0, f"__ERROR__:{exc}"

    def _client(self):
        return httpx.AsyncClient(timeout=REQ_TIMEOUT, follow_redirects=True,
                                 cookies=self._session_cookies())

    @staticmethod
    def _success(step_or_indicator: Any, status: int, body: str) -> bool:
        rgx = step_or_indicator if isinstance(step_or_indicator, str) else \
            (step_or_indicator or {}).get("success")
        if rgx:
            return re.search(rgx, body or "") is not None
        return 200 <= status < 300 and not body.startswith("__")

    # -- race conditions -------------------------------------------------------
    async def test_race_conditions(self, wf: dict) -> Optional[dict]:
        race_name = wf.get("race_step")
        if not race_name:
            return None
        steps = {s["name"]: s for s in wf.get("steps", [])}
        race_step = steps.get(race_name)
        if not race_step:
            return None
        single_use = wf.get("race_single_use", True)
        async with self._client() as client:
            # prelude: run steps before the race step, in order
            transcript = []
            for s in wf.get("steps", []):
                if s["name"] == race_name:
                    break
                st, body = await self._do_step(client, s, wf.get("name", "wf"))
                transcript.append({"step": s["name"], "status": st, "body": body[:2000]})
            # fire N concurrent copies of the race step
            results = await asyncio.gather(*[
                self._do_step(client, race_step, wf.get("name", "wf"))
                for _ in range(self.race_count)])
            successes = sum(1 for st, body in results if self._success(race_step, st, body))
            state = ""
            if wf.get("state_check_url"):
                _, state = await self._do_step(
                    client, {"method": "GET", "url": wf["state_check_url"]}, wf.get("name", "wf"))
            anomaly = (single_use and successes > 1) or bool(_NEG_TOTAL.search(state))
            if anomaly:
                return {
                    "flaw_type": "race_condition", "workflow": [s["name"] for s in wf.get("steps", [])],
                    "confidence": "confirmed",
                    "detail": {"race_step": race_name, "concurrent": self.race_count,
                               "successes": successes, "single_use_expected": single_use},
                    "evidence_spill_id": write_spill({
                        "kind": "race_condition", "workflow": wf.get("name"), "race_step": race_name,
                        "concurrent": self.race_count, "successes": successes,
                        "prelude": transcript, "race_results": [
                            {"status": st, "body": b[:1500]} for st, b in results],
                        "final_state": state[:3000], "captured_at": _now_iso()}),
                }
        return None

    # -- step skipping ---------------------------------------------------------
    async def test_step_skipping(self, wf: dict) -> Optional[dict]:
        skip = set(wf.get("skip_steps", []))
        if not skip:
            return None
        indicator = wf.get("success_indicator")
        async with self._client() as client:
            transcript = []
            terminal_ok = False
            for s in wf.get("steps", []):
                if s["name"] in skip:
                    transcript.append({"step": s["name"], "SKIPPED": True})
                    continue
                st, body = await self._do_step(client, s, wf.get("name", "wf"))
                transcript.append({"step": s["name"], "status": st, "body": body[:2000]})
                if self._success(s.get("success") or indicator, st, body):
                    terminal_ok = True
            # check final state too
            state = ""
            if wf.get("state_check_url"):
                _, state = await self._do_step(
                    client, {"method": "GET", "url": wf["state_check_url"]}, wf.get("name", "wf"))
            final_ok = terminal_ok or (indicator and re.search(indicator, state or ""))
            if final_ok:
                return {
                    "flaw_type": "step_skipping",
                    "workflow": [s["name"] for s in wf.get("steps", [])],
                    "confidence": "confirmed",
                    "detail": {"skipped": sorted(skip), "reached_success_without_them": True},
                    "evidence_spill_id": write_spill({
                        "kind": "step_skipping", "workflow": wf.get("name"),
                        "skipped": sorted(skip), "transcript": transcript,
                        "final_state": state[:3000], "captured_at": _now_iso()}),
                }
        return None

    # -- parameter tampering ---------------------------------------------------
    async def test_parameter_tampering(self, wf: dict) -> List[dict]:
        tamper = wf.get("tamper") or {}
        tname = tamper.get("step")
        fields = tamper.get("fields", [])
        if not tname or not fields:
            return []
        steps = {s["name"]: s for s in wf.get("steps", [])}
        tstep = steps.get(tname)
        if not tstep:
            return []
        findings = []
        for field in fields:
            is_price = any(k in field.lower() for k in ("price", "amount", "cost", "total"))
            neg_value = -1 if not is_price else -0.01
            async with self._client() as client:
                transcript = []
                for s in wf.get("steps", []):
                    if s["name"] == tname:
                        st, body = await self._do_step(client, s, wf.get("name", "wf"),
                                                       overrides={field: neg_value})
                        transcript.append({"step": s["name"], "tampered_field": field,
                                           "value": neg_value, "status": st, "body": body[:2000]})
                        break
                    st, body = await self._do_step(client, s, wf.get("name", "wf"))
                    transcript.append({"step": s["name"], "status": st, "body": body[:2000]})
                # accepted if the tamper step returned 2xx without a validation error
                last = transcript[-1]
                accepted = (200 <= (last.get("status") or 0) < 300 and
                            not _ERROR_SIG.search(last.get("body", "")))
                state = ""
                if wf.get("state_check_url"):
                    _, state = await self._do_step(
                        client, {"method": "GET", "url": wf["state_check_url"]}, wf.get("name", "wf"))
                neg_reflected = bool(_NEG_TOTAL.search(state)) or bool(_NEG_TOTAL.search(last.get("body", "")))
                # accepting a negative value at all is the flaw; reflection in
                # state confirms it, otherwise it is a strong suspicion.
                if accepted:
                    findings.append({
                        "flaw_type": "price_manipulation" if is_price else "negative_quantity",
                        "workflow": [s["name"] for s in wf.get("steps", [])],
                        "confidence": "confirmed" if neg_reflected else "suspected",
                        "detail": {"step": tname, "field": field, "value": neg_value,
                                   "negative_reflected_in_state": neg_reflected},
                        "evidence_spill_id": write_spill({
                            "kind": "parameter_tampering", "workflow": wf.get("name"),
                            "step": tname, "field": field, "value": neg_value,
                            "transcript": transcript, "final_state": state[:3000],
                            "captured_at": _now_iso()}),
                    })
        return findings

    # -- orchestration ---------------------------------------------------------
    def _has_mutating_steps(self) -> bool:
        for wf in self.workflows:
            for s in wf.get("steps", []):
                if (s.get("method") or "GET").upper() not in SAFE_METHODS:
                    return True
        return False

    async def run(self) -> dict:
        started = time.time()
        if httpx is None:
            self.errors.append({"stage": "http", "error": "httpx not installed"})
            return self._artifact([], started, fatal=True)
        if not self.workflows:
            self.errors.append({"stage": "input", "error": "no workflows supplied"})
            return self._artifact([], started, fatal=True)
        # HARD MUTATION GATE
        if self._has_mutating_steps() and not self.authorized:
            self.errors.append({"stage": "authorization", "error":
                                "mutating workflow steps require config.authorize_mutations=true "
                                "(explicit mutation budget); refusing to run"})
            return self._artifact([], started, fatal=True, gated=True)

        findings: List[dict] = []
        try:
            for wf in self.workflows:
                r = await self.test_race_conditions(wf)
                if r:
                    findings.append(r)
                r = await self.test_step_skipping(wf)
                if r:
                    findings.append(r)
                findings += await self.test_parameter_tampering(wf)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "run", "error": repr(exc)})
        return self._artifact(findings, started)

    def _artifact(self, findings: List[dict], started: float,
                  fatal: bool = False, gated: bool = False) -> dict:
        return {
            "findings": findings,
            "meta": {
                "skill": "business-logic-state", "version": "1.0", "phase": "5",
                "status": "error" if fatal else "ok",
                "authorization_required": gated,
                "generated_at": _now_iso(),
                "duration_seconds": round(time.time() - started, 2),
                "workflows": [w.get("name") for w in self.workflows],
                "race_count": self.race_count,
                "findings_count": len(findings),
                "safety": {"mutations_authorized": self.authorized,
                           "race_capped_at": self.race_count,
                           "race_hard_max": RACE_HARD_MAX},
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
        raise ValueError("no input: expected JSON {\"workflows\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {
        "findings": [],
        "meta": {"skill": "business-logic-state", "version": "1.0", "phase": "5",
                 "status": "error", "generated_at": _now_iso()},
        "errors": [{"stage": "init", "error": message}],
    }


async def _amain(argv: List[str]) -> int:
    try:
        payload = _load_input(argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    workflows = payload.get("workflows") or []
    if not isinstance(workflows, list) or not workflows:
        print(json.dumps(_error_artifact("need non-empty 'workflows' list")))
        return 2
    session = None
    if payload.get("session_spill_id"):
        try:
            data = read_spill(payload["session_spill_id"])
            pool = data.get("session_pool", data) if isinstance(data, dict) else data
            session = pool[0] if isinstance(pool, list) and pool else (pool if isinstance(pool, dict) else None)
        except Exception:  # noqa: BLE001
            session = None
    tester = LogicTester(workflows, target_base=payload.get("target_base", ""),
                         session=session, scope_policy_spill_id=payload.get("scope_policy_spill_id"),
                         config=payload.get("config"))
    artifact = await tester.run()
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


def main() -> int:
    return asyncio.run(_amain(sys.argv))


if __name__ == "__main__":
    raise SystemExit(main())

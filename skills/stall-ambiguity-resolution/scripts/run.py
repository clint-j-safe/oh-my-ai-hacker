#!/usr/bin/env python3
"""
run.py -- stall-ambiguity-resolution entry point.

The Stall Detector's recovery brain. When the loop has produced N consecutive
near-zero-gain observations, this skill reads the trace, diagnoses WHY the loop
stalled (tool broken, hypothesis wrong, WAF blocking, target down, ambiguous
output), and reformulates the plan into a NEW action that differs from the
stalled one -- it never just restarts. It also emits a one-sentence lesson for
the Provenance Ledger.

DOES NOT TOUCH THE TARGET. It analyses a trace that already happened; it sends
no requests and mutates nothing. `meta.target_interaction:"none"`.

CLASSIFICATION PRECEDENCE (most specific first)
-----------------------------------------------
1. TARGET_DOWN     -- every step is a server-unavailable failure (502/503/504 or
                      timeout/reset) across the trace, and it is NOT explained by
                      a WAF signature.
2. WAF_BLOCKING    -- 403/429 (or 503 carrying a WAF signature) appears: payloads
                      are being blocked before the app.
3. TOOL_BROKEN     -- the SAME action repeats and every attempt hits an identical
                      tool/infra error (timeout, connection reset, tool_error).
4. HYPOTHESIS_WRONG-- >=2 DISTINCT payloads all yield the identical response: the
                      target is indifferent to this class; the hypothesis is refuted.
5. AMBIGUOUS_OUTPUT-- responses move but give no clear signal (fallback).

CONTRACT
--------
* Input  : {"loop_trace":[{step,action,observation,info_gain,status?,response_hash?,
             error_type?,cost_tokens?,tool?}],
            "current_hypothesis":{id,claim}, "stall_type":"stalled_repetitive",
            "config":{"fallback_tools":{...},"next_hypotheses":[...],"zero_gain_epsilon":0}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

CAUSES = ["TOOL_BROKEN", "HYPOTHESIS_WRONG", "WAF_BLOCKING", "TARGET_DOWN", "AMBIGUOUS_OUTPUT"]
ACTION_FOR = {
    "TOOL_BROKEN": "quarantine_tool",
    "HYPOTHESIS_WRONG": "kill_hypothesis",
    "WAF_BLOCKING": "switch_to_waf_evasion",
    "TARGET_DOWN": "pause_and_cooldown",
    "AMBIGUOUS_OUTPUT": "switch_detection_method",
}
DOWN_STATUS = {502, 503, 504}
WAF_STATUS = {403, 429}
TOOL_ERRORS = {"timeout", "connection_reset", "connection_refused", "tool_error"}

_WAF_SIG = re.compile(r"cloudflare|attention required|access denied|request blocked|"
                      r"incapsula|mod_security|not acceptable|forbidden|akamai|"
                      r"sucuri|waf|406", re.I)
_ATTACK = re.compile(r"['\"]|\bunion\b|\bselect\b|\bsleep\b|\bor\b\s+\d|<script|<img|"
                     r"\.\./|\{\{|\$\{|%27|--|;|\bexec\b|\bwaitfor\b|onerror", re.I)
_STATUS_WORDS = [
    (r"gateway timeout", 504), (r"service unavailable", 503), (r"bad gateway", 502),
    (r"internal server error", 500), (r"forbidden", 403), (r"too many requests", 429),
    (r"not acceptable", 406), (r"not found", 404), (r"unauthorized", 401),
    (r"\bok\b", 200), (r"no content", 204),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def est_tokens(text: str) -> int:
    if not text:
        return 0
    return max(len(text) // 4, len(text.split()))


def _parse_status(obs: str, explicit: Any) -> Optional[int]:
    if isinstance(explicit, int):
        return explicit
    if explicit and str(explicit).isdigit():
        return int(explicit)
    m = re.search(r"\b([1-5]\d{2})\b", obs or "")
    if m:
        return int(m.group(1))
    low = (obs or "").lower()
    for pat, code in _STATUS_WORDS:
        if re.search(pat, low):
            return code
    return None


def _parse_error(obs: str, explicit: Any) -> Optional[str]:
    if explicit:
        e = str(explicit).lower().replace(" ", "_")
        if "timeout" in e or "timed_out" in e:
            return "timeout"
        if "reset" in e:
            return "connection_reset"
        if "refus" in e:
            return "connection_refused"
        return "tool_error"
    low = (obs or "").lower()
    if "timeout" in low or "timed out" in low:
        return "timeout"
    if "connection reset" in low or "reset by peer" in low:
        return "connection_reset"
    if "connection refused" in low or "could not connect" in low or "failed to connect" in low:
        return "connection_refused"
    return None


class StallResolver:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.trace_in = list(self.payload.get("loop_trace", []) or [])
        self.hypothesis = self.payload.get("current_hypothesis", {}) or {}
        self.stall_type = str(self.payload.get("stall_type", "") or "stalled_repetitive")
        self.epsilon = float(self.config.get("zero_gain_epsilon", 0))
        self.notes: List[str] = []
        self.errors: List[Dict[str, str]] = []
        self.trace = [self._norm(i, s) for i, s in enumerate(self.trace_in)]

    def _norm(self, idx: int, s: dict) -> dict:
        obs = str(s.get("observation", "") or "")
        action = str(s.get("action", "") or "")
        status = _parse_status(obs, s.get("status"))
        error = _parse_error(obs, s.get("error_type"))
        rhash = s.get("response_hash")
        if not rhash:
            # hash the normalized observation (numbers stripped so ids don't add noise)
            norm = re.sub(r"\d+", "#", obs.lower()).strip()
            rhash = hashlib.sha256((str(status) + "|" + norm).encode()).hexdigest()[:16]
        waf = bool(status in WAF_STATUS or (status == 503 and _WAF_SIG.search(obs))
                   or (status in (None, 200) and _WAF_SIG.search(obs) and _ATTACK.search(action)))
        return {"step": s.get("step", idx + 1), "action": action, "observation": obs,
                "info_gain": float(s.get("info_gain", 0) or 0), "status": status,
                "error": error, "hash": rhash, "is_attack": bool(_ATTACK.search(action)),
                "waf": waf, "cost_tokens": int(s.get("cost_tokens", 0) or 0),
                "tool": s.get("tool")}

    # -- classification -----------------------------------------------------
    def classify_root_cause(self) -> str:
        t = self.trace
        if not t:
            return "AMBIGUOUS_OUTPUT"
        n = len(t)
        distinct_actions = len({s["action"] for s in t})
        distinct_hashes = len({s["hash"] for s in t})
        waf_hits = [s for s in t if s["waf"]]
        down_hits = [s for s in t if (s["status"] in DOWN_STATUS) or (s["error"] in
                     ("timeout", "connection_reset", "connection_refused"))]

        # 1. TARGET_DOWN: every step is server-unavailable, not a WAF block
        if down_hits and len(down_hits) == n and not waf_hits:
            # a repeated single action timing out is a tool problem, not the target
            if distinct_actions == 1 and all(s["error"] in TOOL_ERRORS for s in t):
                return "TOOL_BROKEN"
            return "TARGET_DOWN"

        # 2. WAF_BLOCKING: any 403/429 or 503+signature
        if waf_hits:
            return "WAF_BLOCKING"

        # 3. TOOL_BROKEN: same action, identical tool/infra error every time
        if distinct_actions == 1 and n >= 2:
            errs = {s["error"] for s in t}
            if len(errs) == 1 and next(iter(errs)) in TOOL_ERRORS:
                return "TOOL_BROKEN"
            statuses = {s["status"] for s in t}
            if statuses == {500} and all(s["error"] is None for s in t):
                # same action, repeated clean 500 with no injection variation -> tool/app fault
                return "TOOL_BROKEN"

        # 4. HYPOTHESIS_WRONG: distinct payloads, identical responses, success-ish
        if distinct_actions >= 2 and distinct_hashes == 1:
            if all((s["status"] in (200, 204, 302, 404, None)) for s in t):
                return "HYPOTHESIS_WRONG"

        # 5. fallback
        return "AMBIGUOUS_OUTPUT"

    # -- diagnosis ----------------------------------------------------------
    def generate_diagnosis(self, cause: str) -> str:
        return {
            "TOOL_BROKEN": "Tool infrastructure failure, not target behavior: the same action "
                           "repeatedly hit an identical tool/infra error.",
            "HYPOTHESIS_WRONG": "Target is not vulnerable to this class. Distinct payloads all "
                                "produced the identical response; the hypothesis is refuted.",
            "WAF_BLOCKING": "WAF is actively blocking. Payloads are returning 403/429 (or a "
                            "signature-bearing 503) and are not reaching the app.",
            "TARGET_DOWN": "Target may be down or globally rate-limiting: every request returned "
                           "502/503/504 or timed out regardless of payload.",
            "AMBIGUOUS_OUTPUT": "Observations are noisy: responses change but give no clear signal, "
                                "so the current method can neither confirm nor refute.",
        }[cause]

    # -- revised plan -------------------------------------------------------
    def _endpoint(self) -> str:
        m = re.search(r"(https?://[^\s]+|/[^\s?'\"]+)", " ".join(s["action"] for s in self.trace))
        return m.group(1) if m else str(self.hypothesis.get("claim", "the target"))

    def _fallback_tool(self) -> Optional[str]:
        cur = next((s["tool"] for s in self.trace if s.get("tool")), None)
        fb = self.config.get("fallback_tools", {}) or {}
        if cur and cur in fb:
            return fb[cur]
        builtin = {"sqlmap": "manual-httpx-differential", "httpx": "curl",
                   "requests": "httpx", "curl": "httpx", "playwright": "httpx",
                   "nuclei": "manual-probe"}
        if cur and cur in builtin:
            return builtin[cur]
        return fb.get("default") or (builtin.get(cur) if cur else "manual-httpx-differential")

    def _next_hypothesis(self) -> Optional[dict]:
        nxt = self.config.get("next_hypotheses") or []
        cur_id = self.hypothesis.get("id")
        for h in nxt:
            if isinstance(h, dict) and h.get("id") != cur_id:
                return h
        return None

    def formulate_revised_plan(self, cause: str) -> dict:
        action = ACTION_FOR[cause]
        ep = self._endpoint()
        plan: Dict[str, Any] = {"action": action, "new_hypothesis": None, "new_tool": None}
        if cause == "TOOL_BROKEN":
            tool = self._fallback_tool()
            plan["new_tool"] = tool
            plan["reason"] = (f"Quarantine the failing tool and retry {ep} with fallback "
                              f"'{tool}'. The error is tool-side, so the hypothesis stays open.")
        elif cause == "HYPOTHESIS_WRONG":
            nh = self._next_hypothesis()
            plan["new_hypothesis"] = nh
            plan["reason"] = (f"Kill hypothesis '{self.hypothesis.get('id','?')}' "
                              f"({self.hypothesis.get('claim','')}) — refuted on {ep} — and "
                              + (f"advance to '{nh.get('id')}'." if nh else
                                 "request the next hypothesis from the plan."))
        elif cause == "WAF_BLOCKING":
            plan["reason"] = (f"Route the payloads for {ep} through waf-evasion-mastery to derive "
                              f"encodings that reach the app; keep the hypothesis open.")
        elif cause == "TARGET_DOWN":
            cd = int(self.config.get("cooldown_s", 60))
            plan["reason"] = (f"Pause the loop and notify the Budget Governor; {ep} is unreachable. "
                              f"Resume after a {cd}s cooldown and re-baseline before probing.")
            plan["cooldown_s"] = cd
        else:  # AMBIGUOUS_OUTPUT
            plan["reason"] = (f"Switch detection method on {ep} (e.g. time-based blind instead of "
                              f"error-based) to get a cleaner signal than the current noisy one.")
        return plan

    # -- lesson -------------------------------------------------------------
    def record_lesson(self, cause: str, plan: dict) -> str:
        ep = self._endpoint()
        hid = self.hypothesis.get("id", "?")
        return {
            "TOOL_BROKEN": f"Stall resolved: tool failure (not target) while probing {ep}; "
                           f"quarantined the tool and switched to '{plan.get('new_tool')}'.",
            "HYPOTHESIS_WRONG": f"Stall resolved: hypothesis {hid} refuted on {ep} — distinct "
                                f"payloads gave identical responses; moved to the next lead.",
            "WAF_BLOCKING": f"Stall resolved: WAF blocking payloads on {ep}; switched to "
                            f"waf-evasion-mastery for encoding mutations.",
            "TARGET_DOWN": f"Stall resolved: {ep} unreachable (5xx/timeout globally); paused loop "
                           f"and scheduled a cooldown before resuming.",
            "AMBIGUOUS_OUTPUT": f"Stall resolved: noisy observations on {ep}; switched detection "
                                f"method (e.g. time-based) for a cleaner signal.",
        }[cause]

    # -- accounting ---------------------------------------------------------
    def _stall_duration(self) -> int:
        run = 0
        for s in reversed(self.trace):
            if s["info_gain"] <= self.epsilon:
                run += 1
            else:
                break
        return run or len(self.trace)

    def _tokens_wasted(self) -> int:
        total = 0
        for s in self.trace:
            if s["info_gain"] <= self.epsilon:
                total += s["cost_tokens"] or est_tokens(s["action"] + " " + s["observation"])
        return total

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        cause = self.classify_root_cause()
        diagnosis = self.generate_diagnosis(cause)
        plan = self.formulate_revised_plan(cause)
        lesson = self.record_lesson(cause, plan)
        stalled_action = None
        if self.trace:
            from collections import Counter
            stalled_action = Counter(s["action"] for s in self.trace).most_common(1)[0][0]
        # invariant: the revised plan is a CHANGE, never a repeat/restart
        differs = plan["action"] in set(ACTION_FOR.values())
        return {
            "root_cause": cause,
            "diagnosis": diagnosis,
            "revised_plan": {"action": plan["action"], "reason": plan["reason"],
                             "new_hypothesis": plan.get("new_hypothesis"),
                             "new_tool": plan.get("new_tool"),
                             **({"cooldown_s": plan["cooldown_s"]} if "cooldown_s" in plan else {})},
            "lesson_learned": lesson,
            "stall_duration_steps": self._stall_duration(),
            "tokens_wasted": self._tokens_wasted(),
            "meta": {
                "skill": "stall-ambiguity-resolution", "version": "1.0", "phase": "any",
                "loop_component": "8-stall-detector", "trigger": "stalled_repetitive",
                "target_interaction": "none", "status": "ok", "generated_at": _now_iso(),
                "stall_type": self.stall_type, "trace_len": len(self.trace),
                "distinct_actions": len({s["action"] for s in self.trace}),
                "stalled_action": stalled_action,
                "revised_differs_from_stalled": differs,
                "no_restart": True, "sends_traffic": False, "notes": self.notes,
            },
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
        raise ValueError('no input: expected JSON {"loop_trace": [...]}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"root_cause": "AMBIGUOUS_OUTPUT",
            "diagnosis": f"input error: {msg}",
            "revised_plan": {"action": "switch_detection_method",
                             "reason": "could not parse a trace; re-baseline with a clean probe.",
                             "new_hypothesis": None, "new_tool": None},
            "lesson_learned": "Stall handler received an unparseable trace; re-baselined.",
            "stall_duration_steps": 0, "tokens_wasted": 0,
            "meta": {"skill": "stall-ambiguity-resolution", "version": "1.0",
                     "loop_component": "8-stall-detector", "target_interaction": "none",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"{exc}")))
        return 2
    art = StallResolver(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

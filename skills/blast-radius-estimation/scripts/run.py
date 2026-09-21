#!/usr/bin/env python3
"""
run.py -- blast-radius-estimation entry point.

The Proposer's impact governor. Given a proposed action, it classifies the
blast radius (read_only / mutating / destructive / account_creating) from the
HTTP method + vulnerability class + payload verbs, then selects the GENTLEST
probe that still confirms the vulnerability -- a benign, minimal, ideally
reversible or purely-observational action -- and reports the mutation cost the
loop's budget should charge. Advisory only: it recommends, the deterministic
Safety Gate and mutation budget enforce.

CORE PRINCIPLE
--------------
Confirm, don't exploit. The cheapest proof that a bug exists is almost never the
same as maximally exploiting it. A time/boolean delay proves SQLi without
touching a row; one canary account proves broken registration without creating
a hundred; an OOB DNS callback proves RCE without running a command. This skill
turns "prove it hard" into "prove it gently".

SAFETY
------
* Never upgrades risk. The gentle probe's grade is always <= the proposed
  action's grade.
* Destructive proposals are never passed through as-is: they are downgraded to a
  read-only / OOB confirmation, and `meta.recommend_abort_original` is set.
* Probes are benign by construction -- no shell/OS weaponization, no data
  exfiltration, no mass mutation. A generated probe is asserted free of
  destructive tokens before it is emitted.
* No traffic. This skill reasons only.

CONTRACT
--------
* Input  : {"proposed_action": {"url","method","payload","vuln_class"},
            "config": {"oob_domain": "abc.oast.pro"}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- risk model --------------------------------------------------------------
GRADES = ["read_only", "account_creating", "mutating", "destructive"]
_ORD = {g: i for i, g in enumerate(GRADES)}  # ordinal for "never upgrade"
SEVERITY = {"read_only": "low", "account_creating": "medium",
            "mutating": "medium", "destructive": "critical"}

READ_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
WRITE_METHODS = {"POST", "PUT", "PATCH"}
DESTRUCTIVE_METHODS = {"DELETE"}

# SQL / data verbs -> grade
SQL_READ = re.compile(r"\b(select|union|sleep|benchmark|pg_sleep|waitfor)\b", re.I)
SQL_MUTATE = re.compile(r"\b(insert|update|replace|merge|grant)\b", re.I)
SQL_DESTROY = re.compile(r"\b(drop|delete|truncate|alter|shutdown|xp_cmdshell)\b", re.I)

# any generated probe must be free of these (defense in depth)
DESTRUCTIVE_TOKEN = re.compile(
    r"\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b|\bdrop\s+table\b|"
    r"\bdelete\s+from\b|\btruncate\b|\|\s*sh\b|;\s*rm\b|/etc/shadow", re.I)

# vuln_class -> intrinsic grade when the payload verb is not decisive
CLASS_BASE_GRADE = {
    "sqli": "read_only", "sql_injection": "read_only",
    "xss": "read_only", "reflected_xss": "read_only", "dom_xss": "read_only",
    "stored_xss": "mutating",
    "ssrf": "read_only", "ssti": "read_only", "xxe": "read_only",
    "nosqli": "read_only", "nosql_injection": "read_only",
    "idor": "read_only", "bola": "read_only", "access_control": "read_only",
    "lfi": "read_only", "path_traversal": "read_only", "open_redirect": "read_only",
    "file_upload": "mutating", "business_logic": "mutating", "csrf": "mutating",
    "mass_assignment": "mutating",
    "rce": "destructive", "command_injection": "destructive",
    "deserialization": "destructive", "sql_stacked": "destructive",
    "account_creation": "account_creating", "registration": "account_creating",
    "signup": "account_creating",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canary(url: str, payload: str) -> str:
    h = hashlib.sha256((url + "|" + payload).encode("utf-8", "replace")).hexdigest()
    return "BR" + h[:8]


def _norm_class(v: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (v or "").strip().lower()).strip("_")


class BlastRadiusEstimator:
    def __init__(self, action: dict, config: Optional[dict] = None):
        self.action = action or {}
        self.config = config or {}
        self.url = str(self.action.get("url", "") or "")
        self.method = str(self.action.get("method", "GET") or "GET").upper()
        self.payload = str(self.action.get("payload", "") or "")
        self.vuln_class = _norm_class(self.action.get("vuln_class", ""))
        self.oob = str(self.config.get("oob_domain", "") or "oob.canary.invalid")
        self.canary = _canary(self.url, self.payload)
        self.notes: List[str] = []

    # -- classification -----------------------------------------------------
    def classify_risk(self) -> Tuple[str, str]:
        """Return (risk_grade, driver) — the grade of the PROPOSED action."""
        # 1. account creation is its own category, detected by class or URL
        if self.vuln_class in ("account_creation", "registration", "signup") or \
           re.search(r"/(register|signup|sign-up|users?/create|accounts?)\b", self.url, re.I):
            return "account_creating", "account-creation endpoint"

        # 2. payload verb is the strongest signal for injection classes
        if self.payload:
            if SQL_DESTROY.search(self.payload):
                return "destructive", "destructive SQL/command verb in payload"
            if SQL_MUTATE.search(self.payload):
                return "mutating", "state-mutating SQL verb in payload"

        # 3. intrinsic grade of the vuln class
        base = CLASS_BASE_GRADE.get(self.vuln_class)

        # 4. HTTP method baseline
        if self.method in DESTRUCTIVE_METHODS:
            method_grade = "destructive"
        elif self.method in WRITE_METHODS:
            method_grade = "mutating"
        else:
            method_grade = "read_only"

        if base is None:
            return method_grade, f"HTTP method {self.method} (unknown vuln_class)"
        # take the *higher* of class-intrinsic and method baseline
        grade = base if _ORD[base] >= _ORD[method_grade] else method_grade
        driver = f"vuln_class '{self.vuln_class}' (base {base}) vs method {self.method}"
        return grade, driver

    # -- gentle probe -------------------------------------------------------
    def select_gentle_probe(self, grade: str) -> Dict[str, Any]:
        c, oob = self.canary, self.oob
        vc = self.vuln_class
        probe: Dict[str, Any]

        if vc in ("sqli", "sql_injection", "sql_stacked"):
            probe = {"payload": "' AND 1=1-- -", "method": "GET",
                     "technique": "boolean-differential",
                     "detail": {"true": "' AND 1=1-- -", "false": "' AND 1=2-- -",
                                "time_fallback": "' AND SLEEP(5)-- -"},
                     "confirms": "SQLi via boolean/time differential — reads nothing, writes nothing"}
        elif vc in ("xss", "reflected_xss", "dom_xss", "stored_xss"):
            probe = {"payload": f"<img src=x onerror=console.log('{c}')>", "method": self.method,
                     "technique": "benign-execution-marker",
                     "confirms": "JS execution via a console marker — no cookie/session exfiltration"}
        elif vc in ("ssrf",):
            probe = {"payload": f"http://{c}.{oob}/", "method": "GET", "requires_oob": True,
                     "technique": "oob-callback",
                     "confirms": "SSRF via OOB callback to a controlled canary — NOT cloud metadata/internal"}
        elif vc in ("ssti",):
            probe = {"payload": "{{7*7}}", "method": self.method,
                     "technique": "arithmetic-marker", "expect": "49",
                     "confirms": "template evaluation via 7*7=49 — no system calls"}
        elif vc in ("xxe",):
            probe = {"payload": f'<!DOCTYPE r [<!ENTITY x SYSTEM "http://{c}.{oob}/e">]><r>&x;</r>',
                     "method": self.method, "requires_oob": True, "technique": "oob-entity",
                     "confirms": "XXE via OOB external entity — no local sensitive-file read"}
        elif vc in ("rce", "command_injection", "deserialization"):
            probe = {"payload": f"nslookup {c}.{oob}", "method": self.method, "requires_oob": True,
                     "technique": "oob-dns-callback",
                     "confirms": "code/command execution via a benign DNS lookup — no command output, "
                                 "no filesystem or process side effects"}
        elif vc in ("idor", "bola", "access_control"):
            probe = {"payload": "", "method": "GET", "technique": "cross-user-read",
                     "confirms": "broken object-level auth by READING one other-user resource — never delete/modify"}
        elif vc in ("nosqli", "nosql_injection"):
            probe = {"payload": '{"$ne": null}', "method": self.method, "technique": "boolean-operator",
                     "confirms": "NoSQL operator injection via a true/false differential — no data change"}
        elif vc in ("lfi", "path_traversal"):
            probe = {"payload": "../../../../etc/hostname", "method": "GET", "technique": "benign-file-read",
                     "confirms": "path traversal by reading a non-sensitive marker file (hostname), NOT /etc/shadow"}
        elif vc in ("open_redirect",):
            probe = {"payload": f"https://{c}.{oob}/", "method": "GET", "technique": "benign-redirect-target",
                     "confirms": "open redirect to a harmless canary host"}
        elif vc in ("file_upload",):
            probe = {"payload": f"filename=br_{c}.txt; content='CANARY {c}'", "method": "POST",
                     "technique": "benign-file", "mutation_units": 1,
                     "confirms": "upload path via a benign .txt canary — no webshell/executable"}
        elif vc in ("business_logic", "csrf", "mass_assignment"):
            probe = {"payload": f"single-iteration; canary={c}; DO NOT complete payment/commit", "method": self.method,
                     "technique": "single-reversible-step", "mutation_units": 1,
                     "confirms": "logic flaw with exactly ONE transaction, aborted before the irreversible commit"}
        elif grade == "account_creating":
            probe = {"payload": f"username=brcanary_{c}&email={c}@canary.invalid", "method": self.method or "POST",
                     "technique": "single-test-account", "mutation_units": 1,
                     "confirms": "creates EXACTLY ONE clearly-labelled test account — never a batch"}
        else:
            # unknown class: downgrade to the safest observational form of the same request
            safe_method = "GET" if self.method not in READ_METHODS else self.method
            probe = {"payload": "", "method": safe_method, "technique": "downgrade-to-read",
                     "confirms": f"re-issue as a read-only {safe_method} to observe without mutating"}

        # enforce benignity on whatever we generated
        blob = json.dumps(probe)
        if DESTRUCTIVE_TOKEN.search(blob):
            self.notes.append("generated probe contained a destructive token; neutralized to read-only")
            probe = {"payload": "", "method": "GET", "technique": "downgrade-to-read",
                     "confirms": "probe neutralized: destructive token detected"}
        return probe

    # -- cost ---------------------------------------------------------------
    def _probe_grade(self, probe: dict) -> str:
        if probe.get("requires_oob") or probe.get("technique") in (
                "boolean-differential", "arithmetic-marker", "boolean-operator",
                "benign-file-read", "cross-user-read", "benign-execution-marker",
                "benign-redirect-target", "oob-callback", "oob-entity",
                "oob-dns-callback", "downgrade-to-read"):
            return "read_only"
        if probe.get("technique") == "single-test-account":
            return "account_creating"
        return "mutating"

    def _mutation_cost(self, probe: dict, probe_grade: str) -> int:
        if "mutation_units" in probe:
            try:
                return int(probe["mutation_units"])
            except Exception:  # noqa: BLE001
                pass
        return 0 if probe_grade == "read_only" else 1

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        if not self.url and not self.payload and not self.vuln_class:
            return self._err("empty proposed_action")
        grade, driver = self.classify_risk()
        probe = self.select_gentle_probe(grade)

        # never upgrade: clamp the probe grade to <= proposed grade
        probe_grade = self._probe_grade(probe)
        if _ORD[probe_grade] > _ORD[grade]:
            probe_grade = grade
        cost = self._mutation_cost(probe, probe_grade)

        recommend_abort = grade == "destructive"
        just = (f"Proposed action graded '{grade}' ({SEVERITY[grade]}) because {driver}. "
                f"Selected gentle probe '{probe.get('technique')}' — {probe.get('confirms')} — "
                f"which is '{probe_grade}' and costs {cost} state mutation(s). ")
        if recommend_abort:
            just += ("The original is DESTRUCTIVE and must not be executed as-is; confirm with the "
                     "gentle probe and route any real exploitation through the sandbox/PoC path.")
        else:
            just += "Prefer the probe over the raw action to keep the blast radius minimal."

        gentle_out = {"payload": str(probe.get("payload", "")), "method": str(probe.get("method", "GET"))}
        return {
            "risk_grade": grade,
            "gentle_probe": gentle_out,
            "justification": just,
            "estimated_mutation_cost": cost,
            "meta": {
                "skill": "blast-radius-estimation", "version": "1.0", "phase": "5",
                "loop_component": "2-proposer", "advisory_only": True, "status": "ok",
                "generated_at": _now_iso(),
                "vuln_class": self.vuln_class, "method": self.method,
                "severity": SEVERITY[grade],
                "proposed_grade": grade, "probe_grade": probe_grade,
                "probe_detail": probe, "canary": self.canary,
                "requires_oob": bool(probe.get("requires_oob", False)),
                "recommend_abort_original": recommend_abort,
                "original_impact": "irreversible" if recommend_abort else "bounded",
                "mutation_budget_units": cost, "sends_traffic": False,
                "final_authority": "deterministic-safety-gate + mutation-budget",
                "notes": self.notes,
            },
            "errors": [],
        }

    def _err(self, msg: str) -> dict:
        return {"risk_grade": "read_only",
                "gentle_probe": {"payload": "", "method": "GET"},
                "justification": f"error: {msg}; defaulting to read-only advice",
                "estimated_mutation_cost": 0,
                "meta": {"skill": "blast-radius-estimation", "version": "1.0", "phase": "5",
                         "loop_component": "2-proposer", "advisory_only": True,
                         "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
                "errors": [{"stage": "classify", "error": msg}]}


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"proposed_action": {...}}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"risk_grade": "read_only", "gentle_probe": {"payload": "", "method": "GET"},
            "justification": msg, "estimated_mutation_cost": 0,
            "meta": {"skill": "blast-radius-estimation", "version": "1.0", "phase": "5",
                     "advisory_only": True, "status": "error", "generated_at": _now_iso(),
                     "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    action = payload.get("proposed_action")
    if not isinstance(action, dict):
        print(json.dumps(_error_artifact("need proposed_action object")))
        return 2
    est = BlastRadiusEstimator(action, config=payload.get("config"))
    print(json.dumps(est.return_artifact(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

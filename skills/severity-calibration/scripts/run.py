#!/usr/bin/env python3
"""
run.py -- severity-calibration entry point.

Scores verified findings from DEMONSTRATED impact, not theoretical maximum. It
takes what the loop actually proved -- data actually read, commands actually run,
sessions actually hijacked, pivots actually made, and how many times the Oracle
reproduced the PoC -- and produces a calibrated CVSS 3.1 score, a confidence
grade, and a reproducibility grade. It computes the theoretical-max score too and
explains the gap, so a bug that was confirmed-but-not-exploited is graded on the
proof, not the fantasy.

CORE RULE
---------
CVSS Confidentiality/Integrity/Availability are set from ACTUAL evidence, never
the theoretical ceiling. A PoC that only proved a vuln EXISTS (a benign probe,
an OOB callback, 7*7=49) with no data/commands/session/pivot demonstrated is
capped at Medium, and the gap to its theoretical max is stated explicitly.

DOES NOT TOUCH THE TARGET. Pure scoring over evidence already collected.

CONTRACT
--------
* Input  : {"verified_findings":[{vuln_class, evidence_spill_id?, chain_id?, id?,
             assets_affected?, data_accessed?, commands_executed?, session_hijacked?,
             internal_pivot?, service_impact?, oracle_verifications?, oracle_verdict?,
             methods?, poc_verdict?, reproducibility?}], "config":{...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from spill_store import read_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import read_spill  # type: ignore

# --- CVSS 3.1 base score -----------------------------------------------------
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss_base(m: Dict[str, str]) -> Tuple[float, str]:
    s = m["S"]
    isc = 1 - ((1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]]))
    if s == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[s][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        base = 0.0
    elif s == "U":
        base = _roundup(min(impact + expl, 10))
    else:
        base = _roundup(min(1.08 * (impact + expl), 10))
    vec = (f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}/S:{m['S']}/"
           f"C:{m['C']}/I:{m['I']}/A:{m['A']}")
    return round(base, 1), vec


def severity_of(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


_SEV_ORD = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# theoretical-max profiles (full metric vector) per vuln class
_PROFILE = {
    "sqli": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
             "Full database read and modification, potential DoS", "C"),
    "rce": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
            "Arbitrary code execution, full host compromise", "I"),
    "command_injection": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
                          "OS command execution on the host", "I"),
    "deserialization": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
                        "Object-injection leading to RCE", "I"),
    "ssti": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
             "Template injection leading to RCE", "I"),
    "reflected_xss": ({"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
                      "Script execution in a victim's browser (session/data theft)", "C"),
    "dom_xss": ({"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
                "Client-side script execution", "C"),
    "stored_xss": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "N"},
                   "Persistent script execution against all viewers", "C"),
    "ssrf": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "L", "A": "N"},
             "Internal service access / cloud metadata theft", "C"),
    "idor": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
             "Cross-tenant object read and modification", "C"),
    "bola": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
             "Broken object-level authorization across tenants", "C"),
    "lfi": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
            "Arbitrary local file read", "C"),
    "path_traversal": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
                       "Arbitrary file read via traversal", "C"),
    "xxe": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
            "Local file read / SSRF via external entities", "C"),
    "open_redirect": ({"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "N", "A": "N"},
                      "Redirection to attacker sites (phishing)", "C"),
    "file_upload": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
                    "Malicious file upload leading to RCE", "I"),
    "business_logic": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
                       "Abuse of application logic / state", "I"),
    "csrf": ({"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "H", "A": "N"},
             "Forced state-changing action", "I"),
    "nosqli": ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
               "NoSQL query manipulation / auth bypass", "C"),
    "mass_assignment": ({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
                        "Unauthorized attribute modification", "I"),
}
_ALIASES = {"sql_injection": "sqli", "nosql_injection": "nosqli", "access_control": "idor",
            "xss": "reflected_xss"}
_DEFAULT_PROFILE = ({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
                    "Unspecified high-impact web vulnerability", "C")

_SENSITIVE = re.compile(
    r"password|secret|token|api[_-]?key|ssn|social security|credit card|\bpii\b|private key|"
    r"credential|/etc/passwd|/etc/shadow|shadow|dump|all users|all rows|customer data|"
    r"session cookie|jwt|admin", re.I)
_BENIGN_CMD = re.compile(r"nslookup|dns callback|oob|canary|benign|7\*7|49|whoami-only|id-only|sleep", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_class(v: str) -> str:
    k = re.sub(r"[^a-z0-9]+", "_", (v or "").strip().lower()).strip("_")
    return _ALIASES.get(k, k)


class SeverityCalibrator:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.findings = list(self.payload.get("verified_findings", []) or [])
        self.errors: List[Dict[str, str]] = []

    def _hydrate(self, f: dict) -> dict:
        sid = f.get("evidence_spill_id")
        if sid:
            try:
                ev = read_spill(sid)
                if isinstance(ev, dict):
                    merged = dict(ev)
                    merged.update({k: v for k, v in f.items() if v not in (None, "", [])})
                    return merged
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "hydrate", "error": str(exc)})
        return f

    # -- demonstrated impact -----------------------------------------------
    def assess_demonstrated_impact(self, f: dict, primary_dim: str) -> dict:
        data = str(f.get("data_accessed", "") or "")
        cmds = f.get("commands_executed", "")
        cmds_s = " ".join(cmds) if isinstance(cmds, list) else str(cmds or "")
        session = str(f.get("session_hijacked", "") or "")
        pivot = f.get("internal_pivot")
        svc = str(f.get("service_impact", "") or "")
        rows = int(f.get("rows_read", 0) or 0)

        C = I = A = "N"
        scope = "U"
        shown: List[str] = []

        # confidentiality from data actually read
        if data or rows:
            if _SENSITIVE.search(data) or rows > 100:
                C = "H"; shown.append(f"read sensitive data ({data or str(rows)+' rows'})")
            else:
                C = "L"; shown.append(f"read limited data ({data or str(rows)+' rows'})")

        # integrity/confidentiality from commands actually executed
        if cmds_s and not _BENIGN_CMD.search(cmds_s):
            I = "H"; C = "H" if C == "N" else C
            scope = "C"
            shown.append(f"executed commands ({cmds_s[:60]})")
        elif cmds_s:
            shown.append("triggered a benign OOB/existence probe (no real command output)")

        # session hijack
        if session:
            if re.search(r"admin|root|super", session, re.I):
                C = "H"; I = "H" if I == "N" else I
                shown.append(f"hijacked a privileged session ({session})")
            else:
                C = "L" if C == "N" else C
                shown.append(f"hijacked a session ({session})")

        # internal pivot -> scope change
        if pivot:
            scope = "C"
            C = "L" if C == "N" else C
            depth = pivot if isinstance(pivot, (int, str)) else "yes"
            shown.append(f"pivoted internally (depth {depth})")

        # availability
        if svc:
            if re.search(r"down|crash|dos|outage|unavailable", svc, re.I):
                A = "H"; shown.append(f"impacted availability ({svc})")
            else:
                A = "L"; shown.append(f"partial availability impact ({svc})")

        demonstrated = any(x != "N" for x in (C, I, A))
        existence_only = not demonstrated
        if existence_only:
            # proved the vuln fires but not its impact -> minimal on the primary dim, cap Medium
            if primary_dim == "C":
                C = "L"
            elif primary_dim == "I":
                I = "L"
            else:
                A = "L"
            shown.append("existence proven (benign probe); impact not demonstrated")

        return {"C": C, "I": I, "A": A, "S": scope, "existence_only": existence_only,
                "shown": shown}

    # -- confidence ---------------------------------------------------------
    def assign_confidence(self, f: dict) -> str:
        v = int(f.get("oracle_verifications", f.get("oracle_verified_count", 0)) or 0)
        verdict = str(f.get("oracle_verdict", "") or "").lower()
        methods = f.get("methods") or f.get("detection_methods") or []
        dual = len(methods) >= 2
        if verdict == "flaky":
            return "low"
        if v >= 2:
            return "confirmed"
        if v == 1 and dual:
            return "high"
        if v >= 1:
            return "medium"
        return "low"

    # -- reproducibility ----------------------------------------------------
    def assign_reproducibility(self, f: dict) -> str:
        explicit = str(f.get("reproducibility", "") or "").lower()
        if explicit in ("deterministic", "conditional", "unstable"):
            return explicit
        # a flaky Oracle verdict is, by definition, not reproducible
        if str(f.get("oracle_verdict", "") or "").lower() == "flaky":
            return "unstable"
        pv = str(f.get("poc_verdict", f.get("hardening_verdict", "")) or "").lower()
        if pv == "reproduced":
            return "deterministic"
        if pv == "flaky":
            return "unstable"
        if pv == "regressed":
            return "conditional"
        blob = json.dumps(f).lower()
        if re.search(r"race|timing|non-?deterministic|intermittent|flaky", blob):
            return "unstable"
        if re.search(r"time-based|stateful|requires |specific state|conditional", blob):
            return "conditional"
        if f.get("deterministic") is True:
            return "deterministic"
        return "conditional"

    # -- per finding --------------------------------------------------------
    def _calibrate(self, f_in: dict, idx: int) -> dict:
        f = self._hydrate(f_in)
        vc = _norm_class(f.get("vuln_class", ""))
        profile, theo_str, primary = _PROFILE.get(vc, _DEFAULT_PROFILE)
        fid = str(f.get("finding_id") or f.get("id") or f.get("chain_id") or f"finding-{idx+1}")

        theo_score, theo_vec = cvss_base(profile)
        imp = self.assess_demonstrated_impact(f, primary)
        dem_metrics = {**profile, "C": imp["C"], "I": imp["I"], "A": imp["A"], "S": imp["S"]}
        dem_score, dem_vec = cvss_base(dem_metrics)
        severity = severity_of(dem_score)

        # existence-only cap at Medium
        capped = False
        if imp["existence_only"] and _SEV_ORD[severity] > _SEV_ORD["medium"]:
            dem_score = min(dem_score, 6.9)
            severity = "medium"
            capped = True

        confidence = self.assign_confidence(f)
        reproducibility = self.assign_reproducibility(f)

        shown = imp["shown"] or ["no explicit impact evidence supplied"]
        demonstrated_impact = "; ".join(shown)
        gap = ""
        if dem_score < theo_score:
            gap = (f"Demonstrated CVSS {dem_score} < theoretical {theo_score}: only "
                   f"{demonstrated_impact}. Theoretical max assumes {theo_str.lower()} "
                   f"(C/I/A={profile['C']}/{profile['I']}/{profile['A']}) but the loop demonstrated "
                   f"C/I/A={imp['C']}/{imp['I']}/{imp['A']}"
                   + (" — capped at Medium (existence only)." if capped else "."))

        return {
            "finding_id": fid,
            "vuln_class": vc,
            "cvss_score": dem_score,
            "cvss_vector": dem_vec,
            "severity": severity,
            "confidence": confidence,
            "reproducibility": reproducibility,
            "demonstrated_impact": demonstrated_impact,
            "theoretical_max_impact": f"{theo_str} (CVSS {theo_score}, {theo_vec})",
            "gap_explanation": gap,
            "existence_only": imp["existence_only"],
        }

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        out = []
        for i, f in enumerate(self.findings):
            try:
                out.append(self._calibrate(f, i))
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": f"finding[{i}]", "error": str(exc)})
        return {
            "findings": out,
            "meta": {
                "skill": "severity-calibration", "version": "1.0", "phase": "9",
                "loop_component": "2-proposer", "status": "ok", "generated_at": _now_iso(),
                "scoring": "CVSS:3.1 base, C/I/A overridden by demonstrated evidence",
                "count": len(out), "target_interaction": "none", "sends_traffic": False,
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
        raise ValueError('no input: expected JSON {"verified_findings": [...]}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"findings": [],
            "meta": {"skill": "severity-calibration", "version": "1.0", "phase": "9",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = SeverityCalibrator(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
run.py -- adversarial-self-review entry point.

The final sweep before a report is written. It re-reads every verified finding as
a hostile reviewer: for each one it states the most likely way the finding is a
FALSE POSITIVE, then checks whether the collected evidence actually rules that out.
Findings whose critical false-positive scenarios cannot be ruled out are rejected
pre-report; findings with an unresolved rigor challenge are downgraded; only
findings that survive every challenge pass clean.

This is a skeptic, not a cheerleader. The default posture is doubt: a finding
survives only because the evidence forces it to.

DOES NOT TOUCH THE TARGET. Pure reasoning over evidence already collected.

CONTRACT
--------
* Input  : {"verified_findings":[{finding_id, vuln_class, evidence_spill_id?,
             poc_spill_id?, cvss_score?, confidence?, oracle_verifications?,
             oracle_verdict?, poc_verdict?, methods?, data_accessed?,
             commands_executed?, session_hijacked?, ...evidence...}], "config":{...}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import json
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

_ALIASES = {"sql_injection": "sqli", "nosql_injection": "nosqli", "access_control": "idor",
            "reflected_xss": "xss", "dom_xss": "xss", "stored_xss": "xss",
            "path_traversal": "lfi", "command_injection": "rce"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_class(v: str) -> str:
    k = re.sub(r"[^a-z0-9]+", "_", (v or "").strip().lower()).strip("_")
    return _ALIASES.get(k, k)


class AdversarialReviewer:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.findings = list(self.payload.get("verified_findings", []) or [])
        self.errors: List[Dict[str, str]] = []

    # -- evidence intake ----------------------------------------------------
    def _hydrate(self, f: dict) -> dict:
        merged = dict(f)
        for key in ("evidence_spill_id", "poc_spill_id"):
            sid = f.get(key)
            if not sid:
                continue
            try:
                blob = read_spill(sid)
                if isinstance(blob, dict):
                    for k, v in blob.items():
                        merged.setdefault(k, v)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": f"hydrate:{key}", "error": str(exc)})
        return merged

    def _signals(self, f: dict) -> Dict[str, Any]:
        blob = json.dumps(f, default=str).lower()
        methods = [str(m).lower() for m in (f.get("methods") or f.get("detection_methods") or [])]
        verifs = int(f.get("oracle_verifications", f.get("oracle_verified_count", 0)) or 0)
        verdicts = " ".join(str(f.get(k, "")) for k in ("oracle_verdict", "poc_verdict",
                                                         "hardening_verdict")).lower()
        flaky = "flaky" in verdicts
        reproduced = (verifs >= 2) or ("reproduced" in verdicts) or (verifs >= 1 and not flaky)
        has = lambda *ks: any(k in blob for k in ks)  # noqa: E731
        impact = bool(f.get("data_accessed") or f.get("commands_executed")
                      or f.get("session_hijacked") or f.get("internal_pivot")
                      or has("data read", "rows read", "extracted", "dumped"))
        differential = has("differential", "boolean", "time-based", "time based",
                           "1=1", "1=2", "sleep(", "waitfor", "true/false") or "boolean" in methods
        oob = has("oob", "out-of-band", "out of band", "interactsh", "oast",
                  "dns callback", "canary", "collaborator") or "oob" in methods
        execution = has("command output", "executed command", "js executed",
                        "javascript executed", "code execution confirmed", "callback received",
                        "shell", "= 49", "=49", "7*7") or bool(f.get("commands_executed"))
        return {
            "reproduced": reproduced, "flaky": flaky, "verifs": verifs,
            "differential": differential, "oob": oob, "execution": execution,
            "impact": impact, "dual_method": len(methods) >= 2,
            "cross_user": has("cross-account", "cross account", "other user", "two accounts",
                              "distinct accounts", "second tenant", "another tenant"),
            "no_interaction": (f.get("requires_user_interaction") is False)
                              or has("no user interaction", "no interaction required")
                              or (_norm_class(f.get("vuln_class", "")) == "xss"
                                  and str(f.get("xss_type", "")).lower() == "stored"),
            "eval_proof": has("= 49", "=49", "7*7", "template evaluated", "evaluation confirmed") or bool(f.get("commands_executed")),
            "confidence": str(f.get("confidence", "") or "").lower(),
            # status_only is the coherent complement of every substantive signal:
            # if none of differential/oob/execution/impact is present, all we have is a status/symptom.
            "status_only": not (differential or oob or execution or impact),
            "external_confirmed": has("external", "cross-origin", "different origin", "attacker.com"),
            "csrf_no_token": bool(f.get("csrf_no_token")) or has("no csrf token", "no anti-csrf", "samesite=none"),
        }

    # -- challenges ---------------------------------------------------------
    def generate_challenges(self, f: dict) -> List[dict]:
        vc = _norm_class(f.get("vuln_class", ""))
        cls = {
            "sqli": ("waf_misread",
                     "Could this SQLi be a WAF error page or a generic 500 misread as a SQL error, "
                     "rather than genuine injection?"),
            "nosqli": ("waf_misread",
                       "Could this NoSQLi be a generic error/500 rather than operator injection?"),
            "xss": ("self_xss",
                    "Could this XSS be a self-XSS that needs the victim to paste the payload, or "
                    "mere reflection without actual script execution?"),
            "ssrf": ("dns_rebinding",
                     "Could this SSRF be a DNS-rebinding artifact or an unrelated outbound request "
                     "rather than a server-side fetch you controlled?"),
            "rce": ("benign_echo",
                    "Could this RCE be a benign echo/reflection of the payload rather than actual "
                    "code/command execution?"),
            "deserialization": ("benign_echo",
                                "Could this be a parser exception rather than object-injection RCE?"),
            "xxe": ("parser_error",
                    "Could this XXE be a plain parser error rather than external-entity resolution "
                    "or an OOB fetch?"),
            "ssti": ("reflection_not_eval",
                     "Could this SSTI be string reflection of the braces rather than template "
                     "evaluation (e.g. is 7*7 actually rendered as 49)?"),
            "idor": ("same_tenant",
                     "Could this IDOR be same-tenant/public data, or a decoy returning identical "
                     "data for every id, rather than a real cross-user access break?"),
            "lfi": ("app_error_not_read",
                    "Could this be an application error containing the path rather than actual file "
                    "content being read?"),
            "open_redirect": ("not_followed",
                              "Could this redirect be same-origin or never actually followed by the "
                              "browser?"),
            "business_logic": ("intended_behavior",
                               "Could this be intended behavior or a documented feature rather than "
                               "a logic flaw?"),
            "csrf": ("samesite_protected",
                     "Could this be protected by SameSite cookies or an unverified anti-CSRF token, "
                     "making the cross-site request fail in a real browser?"),
            "file_upload": ("stored_not_executed",
                            "Could the uploaded file be stored but never executed or served with an "
                            "active content type?"),
        }.get(vc, ("generic_fp",
                   f"Could this {vc or 'finding'} be a false positive from noise, a coincidental "
                   f"response, or a misattributed signal?"))
        return [
            {"key": cls[0], "challenge": cls[1], "critical": True},
            {"key": "symptom_not_proof", "critical": True,
             "challenge": "Does the evidence prove the vulnerability itself, or just a symptom "
                          "(a 500, added latency, or a reflected string proves a crash/echo, not "
                          "necessarily the bug)?"},
            {"key": "manual_review", "critical": False,
             "challenge": "Would this finding survive a manual reviewer with full source-code "
                          "access and no benefit of the doubt?"},
        ]

    # -- evaluation ---------------------------------------------------------
    def evaluate_challenge(self, key: str, s: Dict[str, Any]) -> Tuple[str, str]:
        """Return (resolution, evidence_cited)."""
        def ok(cond: bool, cited: str, missing: str) -> Tuple[str, str]:
            return ("ruled_out", cited) if cond else ("unresolved", missing)

        if s["flaky"] and key in ("symptom_not_proof", "waf_misread", "benign_echo",
                                  "parser_error", "reflection_not_eval", "dns_rebinding"):
            return ("unresolved", "Oracle/PoC verdict is flaky — a non-reproducible signal cannot "
                                  "rule out a false positive.")
        R = s["reproduced"]
        if key == "waf_misread":
            return ok(R and (s["differential"] or s["oob"] or s["impact"]),
                      "A boolean/time differential (or OOB/data extraction), reproduced, "
                      "distinguishes true injection from a WAF/error page.",
                      "No differential, OOB, or data-extraction evidence — a bare error/500 cannot "
                      "be told apart from a WAF error page.")
        if key == "self_xss":
            return ok(s["execution"] and s["no_interaction"],
                      "Actual script execution was captured without requiring victim paste/interaction.",
                      "No proof of execution without user interaction — could be self-XSS or reflection only.")
        if key == "dns_rebinding":
            return ok(s["oob"],
                      "An exact-canary OOB callback correlated the request to the server-side fetch.",
                      "No correlated OOB canary — the outbound signal could be rebinding or unrelated.")
        if key == "benign_echo":
            return ok(s["oob"] or s["execution"],
                      "An OOB callback or real command output confirms execution, not an echo.",
                      "No OOB callback or command output — the payload may just be reflected.")
        if key == "parser_error":
            return ok(s["oob"] or s["impact"],
                      "An OOB fetch or actual file content confirms entity resolution.",
                      "No OOB/file-content evidence — could be a plain parser exception.")
        if key == "reflection_not_eval":
            return ok(s["eval_proof"],
                      "The template evaluated an expression (e.g. 7*7 rendered as 49), not reflected braces.",
                      "No evaluation proof — the braces may be reflected verbatim, not rendered.")
        if key == "same_tenant":
            return ok(s["cross_user"] or (s["dual_method"] and s["impact"]),
                      "Two distinct accounts returned each other's data — a real cross-user break.",
                      "No cross-account comparison — the data may be same-tenant or public.")
        if key == "app_error_not_read":
            return ok(s["impact"],
                      "Actual file content (not just the echoed path) was returned.",
                      "No file content captured — could be an app error containing the path.")
        if key == "not_followed":
            return ok(s["external_confirmed"],
                      "The redirect resolved to an external attacker-controlled origin.",
                      "No proof the redirect is external and browser-followed.")
        if key == "intended_behavior":
            return ok(R and s["impact"],
                      "Reproduced with a concrete adverse impact, not documented behavior.",
                      "No reproduced adverse impact — may be intended behavior.")
        if key == "samesite_protected":
            return ok(s["csrf_no_token"] or s["external_confirmed"],
                      "Confirmed cross-origin with no effective SameSite/anti-CSRF protection.",
                      "No confirmation the cross-site request succeeds under SameSite/token defenses.")
        if key == "stored_not_executed":
            return ok(s["execution"],
                      "The uploaded file was actually executed/served as active content.",
                      "No execution proof — the file may be stored inertly.")
        if key == "generic_fp":
            return ok(R and (s["oob"] or s["differential"] or s["impact"]),
                      "Reproduced with corroborating OOB/differential/impact evidence.",
                      "No reproduced corroboration — could be noise or coincidence.")
        if key == "symptom_not_proof":
            return ok(not s["status_only"] and R and not s["flaky"]
                      and (s["differential"] or s["oob"] or s["execution"] or s["impact"]),
                      "Evidence goes beyond a status code — a differential/OOB/execution/impact "
                      "signal, reproduced, proves the bug itself.",
                      "Evidence is essentially a status/symptom without a reproduced bug-specific signal.")
        if key == "manual_review":
            return ok(R and not s["flaky"] and s["confidence"] in ("confirmed", "high"),
                      "Reproduced with high/confirmed confidence — would hold up to source review.",
                      "Confidence below high or not firmly reproduced — a source reviewer might dispute it.")
        return ("unresolved", "unknown challenge")

    # -- verdict ------------------------------------------------------------
    def assign_verdict(self, results: List[dict]) -> Tuple[str, Optional[str], Optional[str]]:
        crit_unres = [r for r in results if r["_critical"] and r["resolution"] == "unresolved"]
        noncrit_unres = [r for r in results if not r["_critical"] and r["resolution"] == "unresolved"]
        if crit_unres:
            reason = ("Critical false-positive scenario not ruled out: "
                      f"\"{crit_unres[0]['challenge']}\" — {crit_unres[0]['evidence_cited']}")
            return "rejected", None, reason
        if noncrit_unres:
            adj = ("Reduce one severity band: rigor challenge unresolved — "
                   f"{noncrit_unres[0]['evidence_cited']}")
            return "downgraded", adj, None
        return "survives", None, None

    # -- per finding --------------------------------------------------------
    def _review(self, f_in: dict, idx: int) -> dict:
        f = self._hydrate(f_in)
        s = self._signals(f)
        fid = str(f.get("finding_id") or f.get("id") or f.get("chain_id") or f"finding-{idx+1}")
        challenges = self.generate_challenges(f)
        results = []
        for ch in challenges:
            res, cite = self.evaluate_challenge(ch["key"], s)
            results.append({"challenge": ch["challenge"], "resolution": res,
                            "evidence_cited": cite, "_critical": ch["critical"]})
        verdict, adj, reason = self.assign_verdict(results)
        return {
            "finding_id": fid,
            "vuln_class": _norm_class(f.get("vuln_class", "")),
            "verdict": verdict,
            "challenges": [{"challenge": r["challenge"], "resolution": r["resolution"],
                            "evidence_cited": r["evidence_cited"]} for r in results],
            "severity_adjustment": adj,
            "rejection_reason": reason,
        }

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        reviews = []
        for i, f in enumerate(self.findings):
            try:
                reviews.append(self._review(f, i))
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": f"finding[{i}]", "error": str(exc)})
        summary = {
            "total_reviewed": len(reviews),
            "survived": sum(1 for r in reviews if r["verdict"] == "survives"),
            "downgraded": sum(1 for r in reviews if r["verdict"] == "downgraded"),
            "rejected": sum(1 for r in reviews if r["verdict"] == "rejected"),
        }
        return {
            "reviews": reviews,
            "summary": summary,
            "meta": {
                "skill": "adversarial-self-review", "version": "1.0", "phase": "9",
                "loop_component": "2-proposer", "status": "ok", "generated_at": _now_iso(),
                "posture": "skeptical-by-default", "target_interaction": "none",
                "sends_traffic": False,
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
    return {"reviews": [], "summary": {"total_reviewed": 0, "survived": 0, "downgraded": 0, "rejected": 0},
            "meta": {"skill": "adversarial-self-review", "version": "1.0", "phase": "9",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = AdversarialReviewer(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

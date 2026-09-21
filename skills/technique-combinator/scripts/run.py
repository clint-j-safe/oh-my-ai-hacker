#!/usr/bin/env python3
"""
run.py -- technique-combinator entry point.

Combines techniques from DIFFERENT confirmed findings into composite attack
vectors that no single skill would produce. It models each vuln class (and each
extra capability, e.g. hashcat) by what artifact it PRODUCES and what it CONSUMES,
links a producer to a consumer when a produced artifact satisfies a consumed one,
enumerates the resulting chains, scores them by terminal impact
(RCE > PrivEsc > DataExfil > InfoDisclosure), and emits an explicit step-by-step
action plan with data flow.

PLANNING ONLY. This composes findings the loop already CONFIRMED; it sends no
traffic and executes nothing. Every step in a returned plan is still subject to
scope-discipline, blast-radius-estimation, and the deterministic Safety Gate
before it runs. `meta.sends_traffic:false`.

CONTRACT
--------
* Input  : {"confirmed_findings":[{vuln_class, output, target, finding_id?}],
            "capabilities":[{name, yields, consumes?}], "config":{max_len,max_chains}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

_ALIASES = {"sql_injection": "sqli", "nosql_injection": "sqli", "access_control": "idor",
            "reflected_xss": "xss", "dom_xss": "xss", "stored_xss": "xss",
            "command_injection": "rce", "lfi": "path_traversal"}

# technique I/O model: what each class CONSUMES (needs) and PRODUCES (yields)
TECH: Dict[str, Dict[str, Set[str]]] = {
    "ssrf": {"consumes": set(), "produces": {"internal_url", "internal_service", "file_read", "metadata_cred"}},
    "sqli": {"consumes": {"internal_service", "injectable_param"}, "produces": {"db_hash", "data", "cred", "admin_data"}},
    "xss": {"consumes": set(), "produces": {"session_cookie", "csrf_token"}},
    "idor": {"consumes": {"valid_session", "session_cookie"}, "produces": {"admin_data", "other_user_data", "cred"}},
    "bola": {"consumes": {"valid_session", "session_cookie"}, "produces": {"admin_data", "other_user_data", "cred"}},
    "file_upload": {"consumes": set(), "produces": {"file_path", "stored_file"}},
    "path_traversal": {"consumes": {"file_path"}, "produces": {"file_read", "source_code", "config", "cred"}},
    "xxe": {"consumes": set(), "produces": {"file_read", "internal_url"}},
    "deserialization": {"consumes": set(), "produces": {"shell"}},
    "rce": {"consumes": {"file_path", "stored_file"}, "produces": {"shell"}},
    "csrf": {"consumes": {"session_cookie"}, "produces": {"forced_action"}},
    "open_redirect": {"consumes": set(), "produces": {"phishing"}},
}

# built-in transformer capabilities (name keyword -> consumes/produces)
CAP_KB = {
    "hashcat": ({"db_hash"}, {"plaintext_cred"}),
    "john": ({"db_hash"}, {"plaintext_cred"}),
    "auth_bypass": ({"plaintext_cred", "cred", "session_cookie"}, {"elevated_session"}),
    "login": ({"plaintext_cred", "cred"}, {"elevated_session"}),
    "credential_stuffing": ({"plaintext_cred"}, {"elevated_session"}),
    "privilege_escalation": ({"elevated_session", "admin_data", "cred"}, {"admin_access"}),
    "privesc": ({"elevated_session", "admin_data"}, {"admin_access"}),
}

# output-string keyword -> produced artifact tokens (augment class produces)
_OUT_TOKENS = [
    (r"internal url|internal service|169\.254|localhost|127\.0\.0\.1|metadata", "internal_service"),
    (r"internal url|ssrf", "internal_url"),
    (r"cookie|session|jwt|bearer", "session_cookie"),
    (r"file path|upload path|/uploads/|stored at", "file_path"),
    (r"\bhash(es)?\b|bcrypt|md5|sha1|sha256|password hash", "db_hash"),
    (r"file read|/etc/passwd|file content|read file|arbitrary file", "file_read"),
    (r"source code|\.py|\.js source|config file|\.env", "config"),
    (r"credential|password|secret|api key|plaintext", "cred"),
    (r"admin|privileged row|role=admin", "admin_data"),
    (r"shell|command output|rce", "shell"),
]

IMPACT = [  # token -> (category, base score), most severe first
    ("shell", ("RCE", 100)),
    ("admin_access", ("PrivEsc", 80)),
    ("elevated_session", ("PrivEsc", 80)),
    ("plaintext_cred", ("DataExfil", 60)),
    ("cred", ("DataExfil", 60)),
    ("db_hash", ("DataExfil", 60)),
    ("admin_data", ("DataExfil", 60)),
    ("data", ("DataExfil", 60)),
    ("other_user_data", ("DataExfil", 60)),
    ("file_read", ("InfoDisclosure", 40)),
    ("source_code", ("InfoDisclosure", 40)),
    ("config", ("InfoDisclosure", 40)),
    ("internal_url", ("InfoDisclosure", 40)),
    ("internal_service", ("InfoDisclosure", 40)),
    ("forced_action", ("InfoDisclosure", 40)),
    ("phishing", ("InfoDisclosure", 40)),
]
_IMPACT_MAP = dict(IMPACT)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(v: str) -> str:
    k = re.sub(r"[^a-z0-9]+", "_", (v or "").strip().lower()).strip("_")
    return _ALIASES.get(k, k)


def _tokens_from_output(text: str) -> Set[str]:
    low = (text or "").lower()
    return {tok for pat, tok in _OUT_TOKENS if re.search(pat, low)}


class Node:
    __slots__ = ("id", "kind", "name", "consumes", "produces", "target", "output")

    def __init__(self, nid, kind, name, consumes, produces, target="", output=""):
        self.id, self.kind, self.name = nid, kind, name
        self.consumes, self.produces = set(consumes), set(produces)
        self.target, self.output = target, output


class TechniqueCombinator:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.max_len = int(self.config.get("max_len", 4))
        self.max_chains = int(self.config.get("max_chains", 25))
        self.findings = list(self.payload.get("confirmed_findings", []) or [])
        self.capabilities = list(self.payload.get("capabilities", []) or [])
        self.errors: List[Dict[str, str]] = []
        self.nodes: List[Node] = []

    # -- node model ---------------------------------------------------------
    def _build_nodes(self) -> None:
        for i, f in enumerate(self.findings):
            vc = _norm(f.get("vuln_class", ""))
            io = TECH.get(vc, {"consumes": set(), "produces": set()})
            produces = set(io["produces"]) | _tokens_from_output(f.get("output", ""))
            if not produces:
                produces = {"data"}  # a confirmed finding yields at least some data
            self.nodes.append(Node(f.get("finding_id") or f"F{i+1}", "finding", vc or "finding",
                                   io["consumes"], produces, f.get("target", ""), f.get("output", "")))
        for j, c in enumerate(self.capabilities):
            name = _norm(c.get("name", ""))
            cons, prod = set(), set()
            for kw, (kc, kp) in CAP_KB.items():
                if kw in name:
                    cons, prod = set(kc), set(kp)
                    break
            if c.get("consumes"):
                cons = {_norm(c["consumes"])} if isinstance(c["consumes"], str) else set(map(_norm, c["consumes"]))
            if c.get("yields"):
                prod |= _tokens_from_output(str(c["yields"])) | {_norm(c["yields"])}
            self.nodes.append(Node(c.get("name") or f"CAP{j+1}", "capability",
                                   c.get("name", name) or name, cons, prod))

    # -- compatibility matrix ----------------------------------------------
    def build_compatibility_matrix(self) -> Dict[str, List[Tuple[str, str]]]:
        """producer node id -> [(consumer node id, linking artifact)]."""
        matrix: Dict[str, List[Tuple[str, str]]] = {}
        for a in self.nodes:
            for b in self.nodes:
                if a.id == b.id:
                    continue
                link = a.produces & b.consumes
                if link:
                    matrix.setdefault(a.id, []).append((b.id, sorted(link)[0]))
        return matrix

    # -- chain enumeration --------------------------------------------------
    def identify_chains(self, matrix: Dict[str, List[Tuple[str, str]]]) -> List[List[Tuple[str, str]]]:
        by_id = {n.id: n for n in self.nodes}
        chains: List[List[Tuple[str, str]]] = []

        def dfs(path: List[Tuple[str, str]], visited: Set[str]):
            if len(chains) >= 5000:
                return
            cur = path[-1][0]
            if len(path) >= 2:
                chains.append(list(path))
            if len(path) >= self.max_len:
                return
            for (nxt, link) in matrix.get(cur, []):
                if nxt in visited:
                    continue
                dfs(path + [(nxt, link)], visited | {nxt})

        # a chain must START at a finding (a real confirmed foothold), not a bare transformer
        for n in self.nodes:
            if n.kind == "finding":
                dfs([(n.id, "initial")], {n.id})
        return chains

    # -- scoring ------------------------------------------------------------
    def _terminal_impact(self, last_id: str) -> Tuple[str, int]:
        by_id = {n.id: n for n in self.nodes}
        prod = by_id[last_id].produces
        best = ("InfoDisclosure", 30)
        for tok, (cat, sc) in IMPACT:
            if tok in prod and sc > best[1]:
                best = (cat, sc)
        return best

    def score_chain(self, chain: List[Tuple[str, str]]) -> Tuple[int, str]:
        cat, base = self._terminal_impact(chain[-1][0])
        bonus = min(len(chain) - 2, 3) * 5   # novelty bonus for longer composites
        return min(base + bonus, 100), cat

    # -- action plan --------------------------------------------------------
    def generate_action_plan(self, chain: List[Tuple[str, str]]) -> Tuple[List[dict], str]:
        by_id = {n.id: n for n in self.nodes}
        plan: List[dict] = []
        flow_parts: List[str] = []
        for i, (nid, link) in enumerate(chain):
            node = by_id[nid]
            nxt_link = chain[i + 1][1] if i + 1 < len(chain) else sorted(node.produces)[0] if node.produces else "result"
            inp = "initial access" + (f" @ {node.target}" if node.target else "") if i == 0 else link
            plan.append({"step": i + 1, "technique": node.name, "input": inp,
                         "expected_output": nxt_link})
            flow_parts.append(f"{node.name}({nxt_link})")
        plan.append({"step": len(chain) + 1, "technique": "verification",
                     "input": "combined artifacts", "expected_output": "composite result confirmed"})
        return plan, " → ".join(flow_parts)

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        self._build_nodes()
        matrix = self.build_compatibility_matrix()
        raw_chains = self.identify_chains(matrix)

        seen: Set[Tuple[str, ...]] = set()
        combos: List[dict] = []
        by_id = {n.id: n for n in self.nodes}
        for ch in raw_chains:
            techs = tuple(by_id[nid].name for nid, _ in ch)
            key = techs + tuple(link for _, link in ch)
            if key in seen:
                continue
            seen.add(key)
            score, cat = self.score_chain(ch)
            plan, flow = self.generate_action_plan(ch)
            cid = "chain-" + hashlib.sha256(("|".join(f"{n}:{l}" for n, l in ch)).encode()).hexdigest()[:10]
            combos.append({
                "chain_id": cid,
                "techniques": list(techs),
                "data_flow": flow,
                "impact_score": score,
                "impact_category": cat,
                "action_plan": plan,
            })
        # rank by impact, then by length (shorter first at equal impact), then id
        combos.sort(key=lambda c: (-c["impact_score"], len(c["techniques"]), c["chain_id"]))
        combos = combos[: self.max_chains]

        return {
            "combinations": combos,
            "meta": {
                "skill": "technique-combinator", "version": "1.0", "phase": "6",
                "loop_component": "33-technique-combinator", "status": "ok",
                "generated_at": _now_iso(),
                "findings_in": len(self.findings), "capabilities_in": len(self.capabilities),
                "nodes": len(self.nodes), "chains_found": len(combos),
                "scoring": "RCE=100 > PrivEsc=80 > DataExfil=60 > InfoDisclosure=40 (+5/extra hop)",
                "planning_only": True, "sends_traffic": False,
                "note": "Composite plans are advisory; every step is still subject to "
                        "scope-discipline, blast-radius-estimation, and the Safety Gate before execution.",
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
        raise ValueError('no input: expected JSON {"confirmed_findings": [...]}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"combinations": [],
            "meta": {"skill": "technique-combinator", "version": "1.0", "phase": "6",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = TechniqueCombinator(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

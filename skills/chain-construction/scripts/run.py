#!/usr/bin/env python3
"""
run.py -- chain-construction entry point.

Reads CONFIRMED Phase 5 findings and maps them into ranked multi-step exploit
chains by modelling, for each vulnerability class, the data it yields and the
data it consumes, then linking findings where one's output feeds another's
input (same target). Pure reasoning + graph mapping -- no network, no offensive
action, no state change.

SAFETY / FAITHFULNESS
---------------------
* Analytical only. This skill sends nothing and changes nothing.
* Grounded in confirmed findings. Chains are built strictly from the findings
  supplied; canonical attack "expansions" describe the standard steps a class
  implies, but no capability is invented that a finding did not establish.
* Scope-faithful. Findings are only chained when they share a target -- a
  handoff across unrelated hosts is not asserted.

CONTRACT
--------
* Input  : {"confirmed_findings": [{"vuln_class": "...", "output": "...",
             "target": "...", "endpoint": "..."}], "config": {"max_depth": 5}}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

# --- vulnerability ontology ---------------------------------------------------
# weight ~ impact tier (0-10): rce/priv-esc high, info-disclosure low.
# yields/consumes are data-type tokens; an edge A->B exists when
#   yields(A) & consumes(B) != {}.
# expansion = canonical attack steps [(action, yields_label)] for the narrative.
DATA = ("rce", "cloud_token", "session", "admin_session", "forged_token",
        "secret", "source_code", "db_creds", "user_data", "schema", "privilege",
        "internal_reach")

ONTOLOGY: Dict[str, dict] = {
    "rce": {"weight": 10, "yields": {"rce", "admin_session"}, "consumes": set(),
            "expansion": [("achieve remote code execution", "command execution on server")]},
    "cloud_metadata": {"weight": 9, "yields": {"cloud_token", "admin_session"}, "consumes": {"internal_reach"},
                       "expansion": [("SSRF to 169.254.169.254 metadata", "IMDS role credentials"),
                                     ("assume leaked cloud role", "cloud admin access")]},
    "ssrf_full": {"weight": 5, "yields": {"internal_reach"}, "consumes": set(),
                  "expansion": [("SSRF to internal service", "internal service response")]},
    "ssrf_blind": {"weight": 4, "yields": {"internal_reach"}, "consumes": set(),
                   "expansion": [("blind SSRF via OOB", "confirmed server-side request")]},
    "sqli": {"weight": 7, "yields": {"db_creds", "user_data", "secret"}, "consumes": set(),
             "expansion": [("inject to read the database", "DB credentials & records")]},
    "lfi": {"weight": 6, "yields": {"source_code", "secret"}, "consumes": set(),
            "expansion": [("read local files via traversal", "source code & secrets")]},
    "xxe": {"weight": 6, "yields": {"source_code", "secret", "internal_reach"}, "consumes": set(),
            "expansion": [("external-entity file read", "local files & secrets")]},
    "xss": {"weight": 6, "yields": {"session"}, "consumes": set(),
            "expansion": [("execute script in victim context", "victim session cookie")]},
    "weak_secret": {"weight": 8, "yields": {"forged_token", "admin_session"}, "consumes": {"secret", "source_code"},
                    "expansion": [("forge a JWT with the cracked/leaked secret", "arbitrary/admin session")]},
    "mass_assignment": {"weight": 8, "yields": {"admin_session", "privilege"}, "consumes": {"schema"},
                        "expansion": [("over-post a privileged field", "elevated account")]},
    "idor": {"weight": 6, "yields": {"user_data"}, "consumes": {"session", "admin_session", "forged_token"},
             "expansion": [("access others' objects with the acquired identity", "cross-tenant data")]},
    "id_enumeration": {"weight": 4, "yields": {"user_data"}, "consumes": {"session"},
                       "expansion": [("enumerate sequential IDs", "bulk records")]},
    "introspection": {"weight": 2, "yields": {"schema"}, "consumes": set(),
                      "expansion": [("dump the hidden API schema", "full API surface map")]},
    "batching": {"weight": 3, "yields": set(), "consumes": set(),
                 "expansion": [("batch/alias queries", "rate-limit bypass")]},
    "logic": {"weight": 6, "yields": {"privilege"}, "consumes": set(),
              "expansion": [("abuse multi-step workflow state", "financial / logic impact")]},
    "ssti": {"weight": 9, "yields": {"rce", "admin_session"}, "consumes": set(),
             "expansion": [("template injection to code execution", "RCE-capable sink")]},
    "unknown": {"weight": 3, "yields": set(), "consumes": set(),
                "expansion": [("exploit the finding", "impact")]},
}

# raw vuln_class strings (from Phase 5 artifacts) -> canonical ontology key
NORMALIZE = {
    "rce": "rce", "rfi": "rce", "malicious_upload": "rce", "deserialization": "rce",
    "deserialization_rce": "rce", "urldns": "rce", "pickle": "rce",
    "cloud_metadata": "cloud_metadata",
    "full_response": "ssrf_full", "blind_oob": "ssrf_blind",
    "sqli": "sqli", "boolean": "sqli", "error": "sqli", "time": "sqli", "union": "sqli",
    "oob": "sqli", "nosql": "sqli",
    "lfi": "lfi", "xxe": "xxe",
    "xss": "xss", "reflected": "xss", "stored": "xss", "dom": "xss",
    "weak_secret_cracked": "weak_secret", "none_alg_possible": "weak_secret",
    "alg_confusion_possible": "weak_secret", "jku_injection": "weak_secret", "kid_injection": "weak_secret",
    "mass_assignment": "mass_assignment",
    "idor": "idor", "bola": "idor", "horizontal": "idor", "vertical": "idor",
    "id_enumeration": "id_enumeration",
    "graphql_introspection": "introspection", "batching_abuse": "batching",
    "ssti": "ssti",
    "race_condition": "logic", "step_skipping": "logic",
    "negative_quantity": "logic", "price_manipulation": "logic",
}

TIER_NAME = {10: "remote code execution", 9: "remote code execution", 8: "privilege escalation",
             7: "data exfiltration", 6: "data exfiltration", 5: "internal access",
             4: "enumeration", 3: "info disclosure", 2: "info disclosure"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canon(vuln_class: str) -> str:
    v = (vuln_class or "").strip().lower()
    if v in NORMALIZE:
        return NORMALIZE[v]
    for key, canon in NORMALIZE.items():
        if key in v:
            return canon
    return "unknown"


def _output_types(output: str) -> Set[str]:
    """Refine yields from the finding's actual output text (data-driven handoff)."""
    o = (output or "").lower()
    t: Set[str] = set()
    if any(k in o for k in ("secret", "api_key", "apikey", "password", "private key", "credential")):
        t.add("secret")
    if any(k in o for k in ("jwt", "bearer", "token")):
        t.add("forged_token")
    if any(k in o for k in ("cookie", "session")):
        t.add("session")
    if any(k in o for k in ("source", "\\.php", "\\.py", "config")):
        t.add("source_code")
    if "schema" in o:
        t.add("schema")
    if any(k in o for k in ("root:", "instance-id", "ami-id", "metadata")):
        t.add("cloud_token")
    return t


class ChainConstructor:
    def __init__(self, findings: List[dict], config: Optional[dict] = None):
        self.config = config or {}
        self.max_depth = int(self.config.get("max_depth", 5))
        self.errors: List[Dict[str, str]] = []
        self.nodes: List[dict] = []
        for i, f in enumerate(findings or []):
            if not isinstance(f, dict):
                continue
            canon = _canon(f.get("vuln_class", ""))
            spec = ONTOLOGY.get(canon, ONTOLOGY["unknown"])
            yields = set(spec["yields"]) | _output_types(f.get("output", ""))
            self.nodes.append({
                "idx": i, "canon": canon, "raw": f.get("vuln_class", ""),
                "target": (f.get("target") or f.get("endpoint") or "").strip(),
                "endpoint": f.get("endpoint", ""), "output": f.get("output", ""),
                "weight": spec["weight"], "yields": yields,
                "consumes": set(spec["consumes"]), "expansion": spec["expansion"],
            })

    # -- graph -----------------------------------------------------------------
    def build_graph(self) -> Dict[int, List[int]]:
        adj: Dict[int, List[int]] = {n["idx"]: [] for n in self.nodes}
        by_idx = {n["idx"]: n for n in self.nodes}
        for a in self.nodes:
            for b in self.nodes:
                if a["idx"] == b["idx"]:
                    continue
                # same-target only, and A's output must feed B's input
                if a["target"] and b["target"] and a["target"] != b["target"]:
                    continue
                if a["yields"] & b["consumes"]:
                    adj[a["idx"]].append(b["idx"])
        return adj

    # -- path enumeration ------------------------------------------------------
    def _paths(self, adj: Dict[int, List[int]]) -> List[List[int]]:
        paths: List[List[int]] = []

        def dfs(node: int, trail: List[int]):
            trail = trail + [node]
            extended = False
            for nxt in adj.get(node, []):
                if nxt not in trail and len(trail) < self.max_depth:
                    extended = True
                    dfs(nxt, trail)
            if len(trail) >= 2:
                paths.append(trail)
            if not extended and len(trail) == 1:
                paths.append(trail)   # standalone node
        for n in self.nodes:
            dfs(n["idx"], [])
        # dedup identical ordered paths; drop paths that are a prefix of a longer one
        uniq = {tuple(p): p for p in paths}
        result = list(uniq.values())
        longer = [p for p in result if len(p) >= 2]

        def is_prefix(short, longs):
            ts = tuple(short)
            return any(len(l) > len(short) and tuple(l[:len(short)]) == ts for l in longs)
        pruned = [p for p in result if not (len(p) >= 2 and is_prefix(p, longer))]
        return pruned

    # -- scoring & assembly ----------------------------------------------------
    def rank_chains(self) -> List[dict]:
        by_idx = {n["idx"]: n for n in self.nodes}
        adj = self.build_graph()
        chains = []
        for path in self._paths(adj):
            findings_in = [by_idx[i] for i in path]
            steps = []
            for node in findings_in:
                for action, yields_label in node["expansion"]:
                    steps.append({"vuln_class": node["raw"] or node["canon"],
                                  "action": action, "yields": yields_label,
                                  "endpoint": node["endpoint"]})
            max_w = max(n["weight"] for n in findings_in)
            links = len(findings_in) - 1
            impact = min(100, max_w * 10 + 6 * links)
            tier = TIER_NAME.get(max_w, "impact")
            handoffs = []
            for a, b in zip(findings_in, findings_in[1:]):
                shared = a["yields"] & b["consumes"]
                handoffs.append(f"{a['canon']} → {b['canon']} via {'/'.join(sorted(shared)) or 'data'}")
            rationale = (("Standalone: " if links == 0 else "Chain: ") +
                         " then ".join(f"{n['canon']}" for n in findings_in) +
                         (f". Handoffs: {'; '.join(handoffs)}." if handoffs else ".") +
                         f" Peak impact: {tier}" +
                         (f"; {links} linked finding(s) compound the severity." if links else "."))
            cid = "chain-" + hashlib.sha256(str(path).encode()).hexdigest()[:8]
            chains.append({
                "chain_id": cid, "steps": steps, "impact_score": impact,
                "rationale": rationale,
                "targets": sorted({n["target"] for n in findings_in if n["target"]}),
                "links": links, "finding_indices": path,
            })
        chains.sort(key=lambda c: (c["impact_score"], c["links"]), reverse=True)
        return chains

    def run(self) -> dict:
        started = datetime.now(timezone.utc)
        if not self.nodes:
            self.errors.append({"stage": "input", "error": "no confirmed_findings supplied"})
            return self._artifact([], started, fatal=True)
        chains = self.rank_chains()
        return self._artifact(chains, started)

    def _artifact(self, chains, started, fatal=False) -> dict:
        multi = [c for c in chains if c["links"] >= 1]
        return {
            "chains": chains,
            "meta": {
                "skill": "chain-construction", "version": "1.0", "phase": "6",
                "status": "error" if fatal else "ok",
                "generated_at": _now_iso(),
                "findings_ingested": len(self.nodes),
                "chains_total": len(chains),
                "multi_step_chains": len(multi),
                "top_impact": chains[0]["impact_score"] if chains else 0,
                "analytical_only": True, "sends_traffic": False, "mutates": False,
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
        raise ValueError("no input: expected JSON {\"confirmed_findings\":[...]}")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(message: str) -> dict:
    return {"chains": [],
            "meta": {"skill": "chain-construction", "version": "1.0", "phase": "6",
                     "status": "error", "generated_at": _now_iso()},
            "errors": [{"stage": "init", "error": message}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    findings = payload.get("confirmed_findings") or []
    if not isinstance(findings, list) or not findings:
        print(json.dumps(_error_artifact("need non-empty 'confirmed_findings' list")))
        return 2
    cc = ChainConstructor(findings, config=payload.get("config"))
    print(json.dumps(cc.run(), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

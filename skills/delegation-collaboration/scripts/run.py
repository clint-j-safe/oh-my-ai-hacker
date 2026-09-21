#!/usr/bin/env python3
"""
run.py -- delegation-collaboration entry point.

The Loop Registry's delegation brain. It decides whether a task is handled INLINE
by the current loop or DELEGATEd to a spawned sub-agent with its own isolated
context and budget; when it delegates it writes a full sub-agent spec (scope,
entry-state query, budget, exit condition, mailbox id), persists it, and registers
it. On the other side of the lifecycle it runs the MERGE protocol: it reads a
completed sub-agent's findings, de-duplicates them against the parent graph, and
merges only the unique ones with preserved provenance.

TARGET INTERACTION: indirect. This skill itself sends no requests; the sub-agents
it specs do the probing, always under the scope/budget this skill hands them.
`meta.sends_traffic:false`.

CONTRACT
--------
* Decide : {"action":"decide", "current_task":{description,estimated_endpoints,
             estimated_tokens,parallelizable?,sequential?,requires_history?,
             scope?,endpoint_pattern?,vuln_class?},
             "current_context_budget_remaining_pct":30,
             "active_sub_agents":2, "max_concurrent_sub_agents":5, "config":{...}}
* Merge  : {"action":"merge", "mailbox_id":"...", "sub_agent_id":"...",
             "sub_agent_findings":[...], "parent_findings":[...]}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md).
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from spill_store import write_spill
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from spill_store import write_spill  # type: ignore

_SPILL_DIR = os.environ.get("SPILL_STORE_DIR", "/tmp/spill_store")
SUBAGENT_DIR = os.path.join(_SPILL_DIR, "subagents")

# thresholds (overridable via config)
INLINE_TOKENS = 10000
DELEGATE_TOKENS = 20000
DELEGATE_ENDPOINTS = 20
LOW_BUDGET_PCT = 40


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_ep(e: str) -> str:
    e = str(e or "").strip()
    e = re.sub(r"[#?].*$", "", e)              # drop query/fragment
    e = re.sub(r"^https?://[^/]+", "", e)       # drop scheme+host
    e = e.lower().rstrip("/") or "/"
    return e


def _common_prefix(paths: List[str]) -> str:
    paths = [p for p in paths if p]
    if not paths:
        return ""
    segs = [p.strip("/").split("/") for p in paths]
    out: List[str] = []
    for parts in zip(*segs):
        if len(set(parts)) == 1 and "*" not in parts[0]:
            out.append(parts[0])
        else:
            break
    return "/" + "/".join(out) if out else "/"


class DelegationManager:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.action = str(self.payload.get("action", "decide") or "decide").lower()
        self.task = self.payload.get("current_task", {}) or {}
        self.budget_pct = float(self.payload.get("current_context_budget_remaining_pct", 100) or 100)
        self.active = int(self.payload.get("active_sub_agents", 0) or 0)
        self.max_concurrent = int(self.payload.get("max_concurrent_sub_agents", 5) or 5)
        self.errors: List[Dict[str, str]] = []
        self.notes: List[str] = []

    # -- decision -----------------------------------------------------------
    def should_delegate(self) -> Tuple[bool, str]:
        t = self.task
        tokens = int(t.get("estimated_tokens", 0) or 0)
        endpoints = int(t.get("estimated_endpoints", 0) or 0)
        # hard inline: work that needs the live conversation cannot be isolated
        if t.get("requires_history") or t.get("sequential"):
            return False, ("INLINE: task depends on current conversation history / is "
                           "sequential, so it cannot run in an isolated sub-agent context.")
        if tokens and tokens < INLINE_TOKENS:
            return False, (f"INLINE: estimated {tokens} tokens < {INLINE_TOKENS}; spawning "
                           f"overhead is not worth it.")
        # delegation triggers
        if tokens > DELEGATE_TOKENS and self.budget_pct < LOW_BUDGET_PCT:
            return True, (f"DELEGATE: {tokens} tokens > {DELEGATE_TOKENS} and context budget "
                          f"{self.budget_pct:.0f}% < {LOW_BUDGET_PCT}% — isolate it to protect "
                          f"the parent context.")
        if endpoints > DELEGATE_ENDPOINTS:
            return True, (f"DELEGATE: {endpoints} independent endpoints > {DELEGATE_ENDPOINTS}; "
                          f"parallelizable and context-isolated.")
        if t.get("parallelizable") and tokens > DELEGATE_TOKENS:
            return True, (f"DELEGATE: task is parallelizable and large ({tokens} tokens).")
        return False, (f"INLINE: neither the token/budget nor the endpoint-count threshold is "
                       f"met (tokens={tokens}, endpoints={endpoints}, budget={self.budget_pct:.0f}%).")

    # -- sub-agent spec -----------------------------------------------------
    def _scope(self) -> dict:
        sc = self.task.get("scope") or {}
        endpoints = list(sc.get("endpoints", []) or [])
        parameters = list(sc.get("parameters", []) or [])
        roles = list(sc.get("roles", []) or [])
        if not endpoints:
            pat = self.task.get("endpoint_pattern")
            if not pat:
                m = re.search(r"(/[\w\-/*]+)", str(self.task.get("description", "")))
                pat = m.group(1) if m else ""
            if pat:
                endpoints = [pat]
        return {"endpoints": endpoints, "parameters": parameters, "roles": roles}

    def _entry_query(self, scope: dict) -> str:
        eps = [e.replace("*", "") for e in scope.get("endpoints", [])]
        prefix = _common_prefix([_norm_ep(e) for e in eps]) if eps else ""
        if prefix and prefix != "/":
            cond = f"e.path STARTS WITH '{prefix}'"
        elif eps:
            joined = ", ".join(f"'{_norm_ep(e)}'" for e in eps)
            cond = f"e.path IN [{joined}]"
        else:
            cond = "true"
        roles = scope.get("roles", [])
        role_clause = ""
        if roles:
            rl = ", ".join(f"'{r}'" for r in roles)
            role_clause = f" OPTIONAL MATCH (r:Role) WHERE r.name IN [{rl}] WITH e, collect(r.name) AS roles"
        return (f"MATCH (e:Endpoint) WHERE {cond}{role_clause} "
                f"OPTIONAL MATCH (e)<-[:ABOUT]-(h:Hypothesis {{status:'open'}}) "
                f"RETURN e.path AS endpoint, collect(DISTINCT h.id) AS open_hypotheses"
                + (", roles" if roles else ""))

    def build_sub_agent_spec(self) -> dict:
        scope = self._scope()
        tokens = int(self.task.get("estimated_tokens", 0) or 0)
        cap = int(self.config.get("max_sub_agent_tokens", 120000))
        max_tokens = min(int(tokens * 1.25) or DELEGATE_TOKENS, cap)
        max_time = int(self.config.get("sub_agent_time_s", 900))
        cov = float(self.config.get("coverage_threshold", 0.95))
        n = int(self.task.get("estimated_endpoints", len(scope["endpoints"])) or len(scope["endpoints"]))
        vuln = str(self.task.get("vuln_class", "") or "the target hypothesis")
        mailbox_id = "mbx-" + uuid.uuid4().hex[:12]
        sub_agent_id = "sub-agent-" + uuid.uuid4().hex[:8]
        exit_cond = (f"coverage >= {cov:.2f} of {n} endpoint(s) OR '{vuln}' confirmed/refuted "
                     f"OR budget ({max_tokens} tokens / {max_time}s) exhausted")
        return {
            "mailbox_id": mailbox_id,
            "sub_agent_id": sub_agent_id,
            "objective": str(self.task.get("description", "")),
            "scope": scope,
            "budget": {"max_tokens": max_tokens, "max_time_seconds": max_time},
            "exit_condition": exit_cond,
            "entry_state_query": self._entry_query(scope),
            "vuln_class": self.task.get("vuln_class", ""),
            "created_at": _now_iso(),
            "status": "spawned",
            "parent_context_isolated": True,
        }

    def register_sub_agent(self, spec: dict) -> str:
        os.makedirs(SUBAGENT_DIR, exist_ok=True)
        path = os.path.join(SUBAGENT_DIR, f"{spec['mailbox_id']}.json")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(spec, fh, indent=2, sort_keys=True)
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "spec_write", "error": str(exc)})
        spec["spill_id"] = write_spill(spec)
        self._registry_neo4j(spec)
        return spec["mailbox_id"]

    def _registry_neo4j(self, spec: dict) -> None:
        cfg = self.config.get("neo4j")
        if not cfg:
            return
        try:
            from neo4j import GraphDatabase
            drv = GraphDatabase.driver(cfg["uri"], auth=(cfg.get("user"), cfg.get("password")))
            with drv.session(database=cfg.get("database", "neo4j")) as s:
                s.run("MERGE (a:SubAgent {mailbox_id:$mid}) "
                      "SET a.status='spawned', a.objective=$obj, a.created_at=$ts, "
                      "a.max_tokens=$mt",
                      mid=spec["mailbox_id"], obj=spec["objective"], ts=spec["created_at"],
                      mt=spec["budget"]["max_tokens"])
            drv.close()
            self.notes.append("registered sub-agent in Neo4j Loop Registry")
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "neo4j_register", "error": str(exc)})

    # -- merge --------------------------------------------------------------
    def _read_mailbox(self, mailbox_id: str) -> List[dict]:
        inline = self.payload.get("sub_agent_findings")
        if inline is not None:
            return list(inline)
        cfg = self.config.get("neo4j")
        if cfg:
            try:
                from neo4j import GraphDatabase
                drv = GraphDatabase.driver(cfg["uri"], auth=(cfg.get("user"), cfg.get("password")))
                with drv.session(database=cfg.get("database", "neo4j")) as s:
                    q = ("MATCH (m:SubAgentMailbox {mailbox_id:$mid})-[:REPORTED]->(f:Finding) "
                         "RETURN f.vuln_class AS vuln_class, f.endpoint AS endpoint, "
                         "f.severity AS severity, f.id AS id")
                    out = [dict(r) for r in s.run(q, mid=mailbox_id)]
                drv.close()
                return out
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"stage": "mailbox_read", "error": str(exc)})
        return []

    @staticmethod
    def _key(f: dict) -> Tuple[str, str]:
        return (str(f.get("vuln_class", "")).strip().lower(), _norm_ep(f.get("endpoint", "")))

    def deduplicate_findings(self, findings: List[dict],
                             parent: List[dict]) -> Tuple[List[dict], int]:
        seen = {self._key(f) for f in parent}
        unique: List[dict] = []
        dupes = 0
        for f in findings:
            k = self._key(f)
            if k in seen:
                dupes += 1
                continue
            seen.add(k)
            unique.append(f)
        return unique, dupes

    def merge_sub_agent_results(self, mailbox_id: str) -> dict:
        sub_id = str(self.payload.get("sub_agent_id", "") or mailbox_id)
        findings = self._read_mailbox(mailbox_id)
        parent = list(self.payload.get("parent_findings", []) or [])
        unique, dupes = self.deduplicate_findings(findings, parent)
        provenance = f"discovered_by: sub-agent-{sub_id.replace('sub-agent-','')}"
        merged = self._merge_neo4j(unique, provenance, mailbox_id)
        return {"findings_merged": len(unique), "duplicates_removed": dupes,
                "provenance_tag": provenance, "unique_findings": unique,
                "persisted": merged}

    def _merge_neo4j(self, unique: List[dict], provenance: str, mailbox_id: str) -> bool:
        cfg = self.config.get("neo4j")
        if not cfg or not unique:
            return False
        try:
            from neo4j import GraphDatabase
            drv = GraphDatabase.driver(cfg["uri"], auth=(cfg.get("user"), cfg.get("password")))
            with drv.session(database=cfg.get("database", "neo4j")) as s:
                for f in unique:
                    s.run("MERGE (f:Finding {vuln_class:$vc, endpoint:$ep}) "
                          "SET f.severity=$sev, f.discovered_by=$prov, f.merged_at=$ts "
                          "WITH f MATCH (a:SubAgent {mailbox_id:$mid}) MERGE (a)-[:FOUND]->(f)",
                          vc=f.get("vuln_class", ""), ep=_norm_ep(f.get("endpoint", "")),
                          sev=f.get("severity", ""), prov=provenance, ts=_now_iso(), mid=mailbox_id)
                s.run("MATCH (a:SubAgent {mailbox_id:$mid}) SET a.status='merged'", mid=mailbox_id)
            drv.close()
            self.notes.append(f"merged {len(unique)} finding(s) into parent Neo4j graph")
            return True
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "neo4j_merge", "error": str(exc)})
            return False

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        if self.action == "merge":
            mid = str(self.payload.get("mailbox_id", "") or "")
            if not mid:
                return self._err("merge action requires mailbox_id")
            mp = self.merge_sub_agent_results(mid)
            return self._wrap("delegate",
                              f"Merging completed sub-agent {mid}: {mp['findings_merged']} unique "
                              f"finding(s) merged, {mp['duplicates_removed']} duplicate(s) dropped.",
                              sub_agent_spec=None, merge_protocol={
                                  "findings_merged": mp["findings_merged"],
                                  "duplicates_removed": mp["duplicates_removed"],
                                  "provenance_tag": mp["provenance_tag"],
                                  "persisted": mp["persisted"], "unique_findings": mp["unique_findings"]},
                              mailbox_id=mid)

        delegate, reason = self.should_delegate()
        # concurrency cap: want to delegate but no capacity -> handle inline now
        if delegate and self.active >= self.max_concurrent:
            self.notes.append("delegation deferred: concurrency cap reached")
            return self._wrap("inline",
                              f"Would delegate, but {self.active}/{self.max_concurrent} sub-agents "
                              f"are already active — handling inline to avoid over-subscription. "
                              f"({reason})", sub_agent_spec=None, merge_protocol=None)
        if not delegate:
            return self._wrap("inline", reason, sub_agent_spec=None, merge_protocol=None)

        spec = self.build_sub_agent_spec()
        self.register_sub_agent(spec)
        return self._wrap("delegate", reason, sub_agent_spec=spec, merge_protocol=None,
                          mailbox_id=spec["mailbox_id"])

    def _wrap(self, decision: str, reason: str, sub_agent_spec, merge_protocol,
              mailbox_id: str = "") -> dict:
        return {
            "decision": decision,
            "reason": reason,
            "sub_agent_spec": sub_agent_spec,
            "merge_protocol": merge_protocol,
            "meta": {
                "skill": "delegation-collaboration", "version": "1.0", "phase": "5-6",
                "loop_component": "29-loop-registry", "target_interaction": "indirect",
                "status": "ok", "generated_at": _now_iso(), "action": self.action,
                "active_sub_agents": self.active, "max_concurrent_sub_agents": self.max_concurrent,
                "context_budget_remaining_pct": self.budget_pct,
                "mailbox_id": mailbox_id, "sends_traffic": False, "notes": self.notes,
            },
            "errors": self.errors,
        }

    def _err(self, msg: str) -> dict:
        return {"decision": "inline", "reason": f"error: {msg}",
                "sub_agent_spec": None, "merge_protocol": None,
                "meta": {"skill": "delegation-collaboration", "version": "1.0",
                         "loop_component": "29-loop-registry", "target_interaction": "indirect",
                         "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
                "errors": self.errors + [{"stage": "run", "error": msg}]}


# --- entry point -------------------------------------------------------------
def _load_input(argv: List[str]) -> dict:
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"current_task": {...}}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"decision": "inline", "reason": msg, "sub_agent_spec": None, "merge_protocol": None,
            "meta": {"skill": "delegation-collaboration", "version": "1.0",
                     "loop_component": "29-loop-registry", "target_interaction": "indirect",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    if payload.get("action", "decide") == "decide" and not payload.get("current_task"):
        print(json.dumps(_error_artifact("decide action requires current_task")))
        return 2
    art = DelegationManager(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

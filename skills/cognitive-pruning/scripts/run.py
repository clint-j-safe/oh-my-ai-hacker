#!/usr/bin/env python3
"""
run.py -- cognitive-pruning entry point.

The Semantic Compactor's pruning pass. When the context budget is exceeded, this
skill scores every OPEN hypothesis by evidence strength vs cost-so-far, kills the
dead ends, folds CLOSED threads into dense (<50-token) memory paragraphs, and
returns a pruned hypothesis graph plus the token savings. It manages the agent's
own cognitive state only.

DOES NOT TOUCH THE TARGET. No HTTP, no payloads, no network to any scope. Pure
in-memory reasoning over the hypothesis graph (optionally read from / written
back to Neo4j WorkingMemory when configured).

THE LOAD-BEARING RULE
---------------------
Surviving (PRESERVED) hypotheses are NEVER compressed. They keep their full
claim, full evidence counts, and their next-step plan verbatim -- they are not
compaction food. Only closed/refuted threads and killed dead ends are
compressed or dropped. If we cannot preserve a hypothesis faithfully, we keep it
as-is rather than risk losing a load-bearing lead.

SCORING
-------
score = (evidence_for - evidence_against) / (cost_tokens / 1000)
  cost_tokens == 0 -> 999 (cannot judge cost yet -> preserve)
  score <  threshold (default 0.5) -> KILL
  score >= threshold               -> PRESERVE

CONTRACT
--------
* Input  : {"context_budget_remaining_pct", "open_hypotheses":[...],
            "closed_threads":[...], "conversation_summary",
            "config": {"kill_threshold": 0.5, "fold_max_tokens": 50,
                       "neo4j": {"uri","user","password","database"}}}
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
    import tiktoken  # optional, for accurate token counts
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:  # noqa: BLE001
    _ENC = None

DEFAULT_THRESHOLD = 0.5
DEFAULT_FOLD_MAX = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def est_tokens(text: str) -> int:
    if not text:
        return 0
    if _ENC is not None:
        try:
            return len(_ENC.encode(text))
        except Exception:  # noqa: BLE001
            pass
    # heuristic: ~4 chars/token, with a floor tied to word count
    return max(len(text) // 4, len(text.split()))


def _clip_tokens(text: str, max_tokens: int) -> str:
    """Trim to STRICTLY < max_tokens on a word boundary (compaction food only)."""
    if est_tokens(text) < max_tokens:
        return text
    words = text.split()
    out: List[str] = []
    for w in words:
        trial = " ".join(out + [w]) + " …"
        if est_tokens(trial) >= max_tokens:
            break
        out.append(w)
    clipped = (" ".join(out) + " …").strip() if out else text[: max(1, (max_tokens - 1)) * 4]
    # hard guarantee: never return >= max_tokens
    while out and est_tokens(clipped) >= max_tokens:
        out.pop()
        clipped = (" ".join(out) + " …").strip()
    return clipped


class CognitivePruner:
    def __init__(self, payload: dict):
        self.payload = payload or {}
        self.config = self.payload.get("config", {}) or {}
        self.threshold = float(self.config.get("kill_threshold", DEFAULT_THRESHOLD))
        self.fold_max = int(self.config.get("fold_max_tokens", DEFAULT_FOLD_MAX))
        self.budget_pct = self.payload.get("context_budget_remaining_pct")
        self.conversation_summary = str(self.payload.get("conversation_summary", "") or "")
        self.notes: List[str] = []
        self.errors: List[Dict[str, str]] = []
        self.source = "input"

    # -- load ---------------------------------------------------------------
    def load_hypotheses(self) -> Tuple[List[dict], List[dict]]:
        opens = self.payload.get("open_hypotheses")
        closed = self.payload.get("closed_threads")
        if opens is None and self.config.get("neo4j"):
            opens, closed = self._load_from_neo4j()
            self.source = "neo4j"
        return list(opens or []), list(closed or [])

    def _load_from_neo4j(self) -> Tuple[List[dict], List[dict]]:
        cfg = self.config.get("neo4j", {})
        try:
            from neo4j import GraphDatabase  # optional dependency
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "neo4j_import", "error": str(exc)})
            return [], []
        try:
            drv = GraphDatabase.driver(cfg["uri"], auth=(cfg.get("user"), cfg.get("password")))
            db = cfg.get("database", "neo4j")
            with drv.session(database=db) as s:
                oq = ("MATCH (h:Hypothesis {status:'open'}) "
                      "RETURN h.id AS id, h.claim AS claim, "
                      "coalesce(h.evidence_for,0) AS evidence_for, "
                      "coalesce(h.evidence_against,0) AS evidence_against, "
                      "coalesce(h.cost_tokens,0) AS cost_tokens, h.next_step AS next_step")
                opens = [dict(r) for r in s.run(oq)]
                cq = ("MATCH (t:Thread {status:'closed'}) "
                      "RETURN t.id AS id, t.summary AS summary, t.outcome AS outcome, "
                      "t.method AS method, coalesce(t.tokens,0) AS tokens")
                closed = [dict(r) for r in s.run(cq)]
            drv.close()
            return opens, closed
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "neo4j_query", "error": str(exc)})
            return [], []

    def _write_kills_to_neo4j(self, killed: List[dict]) -> None:
        cfg = self.config.get("neo4j")
        if not cfg or not killed:
            return
        try:
            from neo4j import GraphDatabase
            drv = GraphDatabase.driver(cfg["uri"], auth=(cfg.get("user"), cfg.get("password")))
            with drv.session(database=cfg.get("database", "neo4j")) as s:
                for k in killed:
                    s.run("MATCH (h:Hypothesis {id:$id}) "
                          "SET h.status='killed', h.kill_reason=$r, h.killed_at=$ts",
                          id=k["id"], r=k["kill_reason"], ts=_now_iso())
            drv.close()
            self.notes.append(f"persisted {len(killed)} kills to Neo4j")
        except Exception as exc:  # noqa: BLE001
            self.errors.append({"stage": "neo4j_write", "error": str(exc)})

    # -- scoring ------------------------------------------------------------
    @staticmethod
    def score_hypothesis(h: dict) -> float:
        ef = int(h.get("evidence_for", 0) or 0)
        ea = int(h.get("evidence_against", 0) or 0)
        cost_k = float(h.get("cost_tokens", 0) or 0) / 1000.0
        if cost_k == 0:
            return 999.0
        return (ef - ea) / cost_k

    def _footprint(self, h: dict) -> int:
        """Estimated context tokens this hypothesis occupies going forward."""
        blob = " ".join(str(h.get(k, "")) for k in
                        ("id", "claim", "next_step")) + f" for{h.get('evidence_for',0)} against{h.get('evidence_against',0)}"
        return est_tokens(blob) + 8  # small structural overhead

    def kill_dead_ends(self, hyps: List[dict]) -> Tuple[List[dict], List[dict]]:
        surviving: List[dict] = []
        killed: List[dict] = []
        for h in hyps:
            hid = str(h.get("id", "") or f"hyp-{len(surviving)+len(killed)}")
            score = self.score_hypothesis(h)
            if score < self.threshold:
                ef = int(h.get("evidence_for", 0) or 0)
                ea = int(h.get("evidence_against", 0) or 0)
                cost = int(h.get("cost_tokens", 0) or 0)
                probes = ef + ea
                reason = (f"Killed: {probes} probe(s) yielded evidence_for={ef}/"
                          f"evidence_against={ea} (score {score:.2f} < {self.threshold}). "
                          f"Cost: {cost} tokens.")
                killed.append({"id": hid, "claim": str(h.get("claim", "")),
                               "kill_reason": reason, "tokens_saved": self._footprint(h),
                               "survival_score": round(score, 3)})
            else:
                # PRESERVE verbatim -- never truncate a load-bearing hypothesis
                ns = h.get("next_step")
                if not ns:
                    ns = f"Continue: gather differentiating evidence for '{str(h.get('claim',''))[:80]}'"
                    self.notes.append(f"synthesized next_step for {hid} (none supplied)")
                surviving.append({
                    "id": hid,
                    "claim": str(h.get("claim", "")),
                    "evidence_for": int(h.get("evidence_for", 0) or 0),
                    "evidence_against": int(h.get("evidence_against", 0) or 0),
                    "cost_tokens": int(h.get("cost_tokens", 0) or 0),
                    "survival_score": round(score, 3),
                    "next_step": str(ns),
                })
        surviving.sort(key=lambda x: x["survival_score"], reverse=True)
        killed.sort(key=lambda x: x["tokens_saved"], reverse=True)
        return surviving, killed

    # -- folding ------------------------------------------------------------
    def fold_closed_threads(self, threads: List[dict]) -> Tuple[List[str], int]:
        folded: List[str] = []
        saved = 0
        for t in threads:
            tid = str(t.get("id", "") or "THREAD")
            label = tid if tid.upper().startswith("THREAD") else f"THREAD-{tid}"
            outcome = str(t.get("outcome", "") or "").upper() or "CLOSED"
            summary = str(t.get("summary", "") or "")
            method = str(t.get("method", "") or "")
            dense = f"[{label}] {summary} → {outcome}"
            if method:
                dense += f" via {method}"
            dense += "."
            dense = re.sub(r"\s+", " ", dense).strip()
            dense = _clip_tokens(dense, self.fold_max)
            folded.append(dense)
            original = int(t.get("tokens", 0) or 0) or est_tokens(summary)
            saved += max(0, original - est_tokens(dense))
        return folded, saved

    # -- savings ------------------------------------------------------------
    def estimate_savings(self, killed: List[dict], fold_saved: int) -> int:
        return sum(int(k.get("tokens_saved", 0)) for k in killed) + int(fold_saved)

    # -- orchestration ------------------------------------------------------
    def return_artifact(self) -> dict:
        opens, closed = self.load_hypotheses()
        surviving, killed = self.kill_dead_ends(opens)
        folded, fold_saved = self.fold_closed_threads(closed)
        savings = self.estimate_savings(killed, fold_saved)
        self._write_kills_to_neo4j(killed)

        return {
            "pruned_hypotheses": surviving,
            "killed_hypotheses": killed,
            "folded_memory": folded,
            "context_savings_estimate": int(savings),
            "meta": {
                "skill": "cognitive-pruning", "version": "1.0", "phase": "any",
                "loop_component": "13-semantic-compactor",
                "trigger": "context_budget_exceeded", "target_interaction": "none",
                "status": "ok", "generated_at": _now_iso(),
                "source": self.source,
                "context_budget_remaining_pct": self.budget_pct,
                "kill_threshold": self.threshold, "fold_max_tokens": self.fold_max,
                "counts": {"open_in": len(opens), "preserved": len(surviving),
                           "killed": len(killed), "closed_folded": len(folded)},
                "fold_tokens_saved": int(fold_saved),
                "kill_tokens_saved": int(savings - fold_saved),
                "sends_traffic": False, "notes": self.notes,
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
        raise ValueError('no input: expected JSON {"open_hypotheses": [...]}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict:
    return {"pruned_hypotheses": [], "killed_hypotheses": [], "folded_memory": [],
            "context_savings_estimate": 0,
            "meta": {"skill": "cognitive-pruning", "version": "1.0", "phase": "any",
                     "loop_component": "13-semantic-compactor", "target_interaction": "none",
                     "status": "error", "generated_at": _now_iso(), "sends_traffic": False},
            "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    art = CognitivePruner(payload).return_artifact()
    print(json.dumps(art, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

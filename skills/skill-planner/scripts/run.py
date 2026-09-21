#!/usr/bin/env python3
"""run.py -- skill-planner entry point (thin CLI over the in-process SkillPlanner).

Reads the attack-surface CONTEXT (phase + graph summary + available skills) as JSON and proposes
a sequenced Skill Execution Plan via the frontier-tier LLM. The plan is a PROPOSAL — it must pass
the deterministic SkillPlanValidator (and the SafetyGate, per action) before any coordinator
dispatches it.

This is a REASONER, not an executor: it reads graph state and sends NO target traffic. Offline
(no LLM key) it returns an empty plan — a typed no-op, never a deterministic class->skill
fallback (that fallback is exactly what Milestone 14 purged).

CONTRACT
--------
* Input  : {"phase": 5, "graph_summary": {...}, "available_skills": [{"name": "...", ...}]}
* Output : one strict JSON artifact on stdout (references/ARTIFACT_SCHEMA.md); its ``plan`` field
           is the SkillExecutionPlan array. No prose; logs go to stderr.

In the running framework the coordinators call
``core.loop_engine.skill_planner.SkillPlanner.propose_plan(phase)`` directly (it reads Neo4j
itself); this CLI shares the identical LLM path via ``plan_from_context``.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

# The reasoner lives in the repo's core plane; add the repo root (four levels up:
# skills/skill-planner/scripts/run.py) so this CLI can import it when run standalone.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _meta(status: str) -> dict[str, Any]:
    """Return the artifact ``meta`` block."""
    return {
        "skill": "skill-planner",
        "version": "1.0",
        "phase": "1-6",
        "loop_component": "35-skill-planner",
        "status": status,
        "generated_at": _now_iso(),
        "sends_traffic": False,
    }


async def _plan(payload: dict[str, Any]) -> dict[str, Any]:
    """Build the plan from the supplied context and return the artifact."""
    from core.loop_engine.skill_planner import SkillPlanner

    phase = int(payload.get("phase", 5) or 5)
    graph_summary = payload.get("graph_summary") if isinstance(payload.get("graph_summary"), dict) \
        else {}
    available_skills = [
        s for s in (payload.get("available_skills") or []) if isinstance(s, dict)
    ]
    planner = SkillPlanner()
    plan = await planner.plan_from_context(graph_summary, available_skills, phase)
    return {
        "plan": plan,
        "meta": {**_meta("ok"), "phase_planned": phase, "step_count": len(plan)},
        "errors": [],
    }


def _load_input(argv: list[str]) -> dict[str, Any]:
    """Load the JSON input from argv[1] or stdin."""
    raw = ""
    if len(argv) > 1 and argv[1].strip():
        raw = argv[1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    raw = raw.strip()
    if not raw:
        raise ValueError('no input: expected JSON {"phase": int, "graph_summary": {...}, ...}')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    return obj


def _error_artifact(msg: str) -> dict[str, Any]:
    """Return a schema-valid error artifact (empty plan)."""
    return {"plan": [], "meta": {**_meta("error")}, "errors": [{"stage": "init", "error": msg}]}


def main() -> int:
    """Parse input, propose the plan, and print one strict JSON artifact."""
    try:
        payload = _load_input(sys.argv)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_error_artifact(f"input error: {exc}")))
        return 2
    try:
        artifact = asyncio.run(_plan(payload))
    except Exception as exc:  # noqa: BLE001 - a reasoning fault still emits a valid empty artifact
        print(json.dumps(_error_artifact(f"planning error: {exc}")))
        return 1
    print(json.dumps(artifact, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

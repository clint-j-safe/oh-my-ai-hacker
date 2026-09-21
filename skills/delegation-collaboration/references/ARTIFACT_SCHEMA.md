# Artifact Contract — `delegation-collaboration`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Loop Registry.
This skill's **target interaction is indirect** (`meta.target_interaction:
"indirect"`, `meta.sends_traffic:false`): it sends no requests itself; the
sub-agents it specs do the probing, always under the scope and budget handed to
them here.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "delegation-collaboration artifact",
  "type": "object",
  "required": ["decision"],
  "properties": {
    "decision": { "enum": ["inline", "delegate"] },
    "reason": { "type": "string" },
    "sub_agent_spec": {
      "type": ["object", "null"],
      "required": ["mailbox_id", "scope", "budget", "exit_condition"],
      "properties": {
        "mailbox_id": { "type": "string" },
        "scope": { "type": "object", "properties": {
          "endpoints": {"type":"array","items":{"type":"string"}},
          "parameters": {"type":"array","items":{"type":"string"}},
          "roles": {"type":"array","items":{"type":"string"}} } },
        "budget": { "type": "object", "properties": {
          "max_tokens": {"type":"integer"}, "max_time_seconds": {"type":"integer"} } },
        "exit_condition": { "type": "string" },
        "entry_state_query": { "type": "string" }
      }
    },
    "merge_protocol": {
      "type": ["object", "null"],
      "properties": {
        "findings_merged": { "type": "integer" },
        "duplicates_removed": { "type": "integer" },
        "provenance_tag": { "type": "string" }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

**Decide mode** (`action:"decide"`, default):

```json
{
  "action": "decide",
  "current_task": {"description": "Test all /api/admin/* endpoints for IDOR",
                   "estimated_endpoints": 45, "estimated_tokens": 80000,
                   "parallelizable": true, "vuln_class": "IDOR",
                   "scope": {"endpoints": ["/api/admin/users", "/api/admin/roles"],
                             "parameters": ["id"], "roles": ["user", "admin"]}},
  "current_context_budget_remaining_pct": 30,
  "active_sub_agents": 2, "max_concurrent_sub_agents": 5,
  "config": {"max_sub_agent_tokens": 120000, "sub_agent_time_s": 900, "coverage_threshold": 0.95}
}
```

**Merge mode** (`action:"merge"`):

```json
{
  "action": "merge", "mailbox_id": "mbx-ab12cd34ef56", "sub_agent_id": "sub-agent-9f2a1c7b",
  "sub_agent_findings": [{"vuln_class": "IDOR", "endpoint": "/api/admin/users?id=2", "severity": "high"}],
  "parent_findings":    [{"vuln_class": "IDOR", "endpoint": "/api/admin/roles", "severity": "medium"}]
}
```

Findings may be supplied inline or (with `config.neo4j`) read from the
`SubAgentMailbox` label; likewise `parent_findings` inline or from the graph.

---

## 3. Delegation decision matrix

* **INLINE** when the task needs current conversation history or is sequential
  (cannot be context-isolated), or `estimated_tokens < 10000` (spawn overhead not
  worth it), or no delegation trigger fires.
* **DELEGATE** when `estimated_tokens > 20000` **and** context budget `< 40%`
  (isolate to protect the parent), or `estimated_endpoints > 20` (parallelizable
  and independent), or the task is flagged `parallelizable` and large.
* **Concurrency cap** — if the decision is delegate but
  `active_sub_agents >= max_concurrent_sub_agents`, it falls back to `inline`
  (handle now) rather than over-subscribing, with the reason noted.

Precedence: the "needs history / sequential" and small-task rules force INLINE
before any delegate trigger is considered.

---

## 4. Sub-agent spec (on delegate)

Written to `spill_store/subagents/<mailbox_id>.json`, spilled, and registered with
the Loop Registry (Neo4j `SubAgent` node when configured). Fields:

* `mailbox_id` — unique inter-agent channel id (`mbx-<hex12>`); `sub_agent_id`
  (`sub-agent-<hex8>`).
* `scope` — exact `endpoints` / `parameters` / `roles` (derived from the task
  scope, or an endpoint pattern parsed from the description).
* `budget` — `max_tokens` (task estimate ×1.25, capped at `max_sub_agent_tokens`)
  and `max_time_seconds`.
* `exit_condition` — `"coverage >= T of N endpoint(s) OR '<vuln>' confirmed/refuted
  OR budget exhausted"`.
* `entry_state_query` — a Neo4j Cypher query that loads exactly the sub-agent's
  slice of context (endpoints under the common prefix + their open hypotheses,
  plus roles when scoped).

---

## 5. Merge protocol (on completion)

1. Read the sub-agent's findings from its mailbox (inline or Neo4j).
2. **Deduplicate** against the parent graph — key = `(vuln_class, normalized
   endpoint)`; a match is a duplicate and dropped.
3. Merge only the unique findings into the parent Neo4j graph (MERGE, so re-runs
   are idempotent).
4. **Preserve provenance** — every merged finding is tagged
   `provenance_tag: "discovered_by: sub-agent-<id>"`.

`merge_protocol` reports `findings_merged`, `duplicates_removed`, the
`provenance_tag`, whether it `persisted` to Neo4j, and the `unique_findings`.

---

## 6. Example artifacts

Delegate:
```json
{"decision": "delegate",
 "reason": "DELEGATE: 45 independent endpoints > 20; parallelizable and context-isolated.",
 "sub_agent_spec": {"mailbox_id": "mbx-ab12cd34ef56", "scope": {"endpoints": ["/api/admin/users","/api/admin/roles"], "parameters": ["id"], "roles": ["user","admin"]},
   "budget": {"max_tokens": 100000, "max_time_seconds": 900},
   "exit_condition": "coverage >= 0.95 of 45 endpoint(s) OR 'IDOR' confirmed/refuted OR budget (100000 tokens / 900s) exhausted",
   "entry_state_query": "MATCH (e:Endpoint) WHERE e.path STARTS WITH '/api/admin' ... RETURN e.path AS endpoint, collect(DISTINCT h.id) AS open_hypotheses"},
 "merge_protocol": null,
 "meta": {"target_interaction": "indirect", "mailbox_id": "mbx-ab12cd34ef56", "sends_traffic": false}}
```

Merge:
```json
{"decision": "delegate",
 "reason": "Merging completed sub-agent mbx-ab12cd34ef56: 1 unique finding(s) merged, 1 duplicate(s) dropped.",
 "sub_agent_spec": null,
 "merge_protocol": {"findings_merged": 1, "duplicates_removed": 1,
   "provenance_tag": "discovered_by: sub-agent-9f2a1c7b", "persisted": false},
 "meta": {"action": "merge", "target_interaction": "indirect"}}
```

---

## 7. Registry-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `decision == "delegate"` with a spawn ⇒ `sub_agent_spec` present with a
   `mailbox_id`, non-empty `scope`, a `budget`, and an `exit_condition`.
3. `decision == "inline"` ⇒ `sub_agent_spec == null`.
4. A spawn never exceeds capacity: if `active_sub_agents >= max_concurrent`, the
   decision is `inline`.
5. Merge ⇒ `merge_protocol` present with `findings_merged`, `duplicates_removed`,
   and a `provenance_tag`; `findings_merged + duplicates_removed` == the
   sub-agent's reported finding count.

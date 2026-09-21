# Artifact Contract — `oob-blind-vuln-correlation`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (no pending tests) the skill emits a schema-valid artifact with
empty `correlated_callbacks` and `meta.status == "error"`.

This skill is an **observer**: no target traffic, no mutations
(`meta.sends_target_traffic:false`, `meta.mutates:false`).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "oob-blind-vuln-correlation artifact",
  "type": "object",
  "required": ["correlated_callbacks"],
  "properties": {
    "correlated_callbacks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["request_id", "canary", "protocol", "latency_ms"],
        "properties": {
          "request_id": { "type": "string" },
          "canary": { "type": "string" },
          "protocol": { "enum": ["dns", "http", "smtp"] },
          "latency_ms": { "type": "integer" },
          "raw_log_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "oob_domain": "abc.oast.pro",
  "pending_tests": [
    {"request_id": "req-ssrf-1", "canary": "s1a2b3c4", "sent_at_ms": 1730000000000},
    {"request_id": "req-xxe-2", "canary": "x9z8y7w6", "sent_at_ms": 1730000000800}
  ],
  "config": {"timeout_s": 30, "poll_interval_s": 3,
             "poll_url": "https://oast/interactions",
             "interactions_inline": [ ... ],
             "interactsh_json_file": "/path/interactsh.jsonl"}
}
```

* `pending_tests` — one per outstanding blind test: a `request_id`, its unique
  `canary`, and optionally `sent_at_ms` (for latency). Canaries come from the
  SSRF / XXE / RCE / deserialization skills that deferred OOB confirmation here.
* Interaction source, in priority order: `config.poll_url` (polled in a loop) >
  `config.interactions_inline` (single pass — e.g. a shared Interactsh session
  already holds them) > `interactsh-client` output file (`interactsh_json_file`).
* `timeout_s` / `poll_interval_s` — the wait loop; it exits early once every
  pending canary has called back.

Interactions may be Interactsh JSON dicts (`{protocol, full-id/host/path,
raw-request, timestamp}`) or plain host/path strings; protocol is inferred when
absent.

---

## 3. Correctness (the safety property here)

* **Exact attribution.** A callback is bound to a `request_id` only when that
  request's unique `canary` appears in the callback's subdomain/path/raw. There
  is no fuzzy matching.
* **No false positives.** Callbacks matching no pending canary go to
  `meta.uncorrelated_interactions` (never attributed). Canaries with no callback
  within the timeout go to `meta.timed_out` — absence is reported, not guessed.
* **First callback wins** per canary; repeats are counted in
  `meta.callback_counts`. Latency = `callback_ts − sent_at_ms` (≥ 0).

---

## 4. Example artifact (abridged)

```json
{
  "correlated_callbacks": [
    {"request_id": "req-xxe-2", "canary": "x9z8y7w6", "protocol": "http",
     "latency_ms": 300, "raw_log_spill_id": "0f1e2d3c4b5a6978"},
    {"request_id": "req-ssrf-1", "canary": "s1a2b3c4", "protocol": "dns",
     "latency_ms": 500, "raw_log_spill_id": "9f2a1c7b6d4e0a53"}
  ],
  "meta": {"skill": "oob-blind-vuln-correlation", "status": "ok", "oob_domain": "abc.oast.pro",
           "pending_count": 3, "correlated_count": 2, "timed_out": ["req-deser-3"],
           "uncorrelated_interactions": [{"protocol": "dns", "ident": "randomnoise.abc.oast.pro"}],
           "callback_counts": {"s1a2b3c4": 1, "x9z8y7w6": 2},
           "observer_only": true, "sends_target_traffic": false, "mutates": false},
  "errors": []
}
```

---

## 5. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. every `correlated_callbacks[].canary` is one of the input `pending_tests`
   canaries, and its `canary` string appears in the spilled raw interaction.
3. `meta.sends_target_traffic` and `meta.mutates` are both `false`.
4. `correlated_count + len(timed_out) == pending_count` (every pending test is
   accounted for as either correlated or timed out).

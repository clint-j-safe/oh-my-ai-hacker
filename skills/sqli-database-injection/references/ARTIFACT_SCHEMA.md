# Artifact Contract — `sqli-database-injection`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (out of scope, no parameters) the skill emits a schema-valid
artifact with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "sqli-database-injection artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["parameter", "injection_type", "confidence"],
        "properties": {
          "parameter": { "type": "string" },
          "injection_type": { "enum": ["error","boolean","time","oob","union"] },
          "confidence": { "enum": ["confirmed","suspected"] },
          "dbms": { "type": "string" },
          "waf_bypass_used": { "type": "string" },
          "raw_log_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `proof`, `meta`, `scope_summary`, `errors`):
`references/artifact.schema.json`. One finding is emitted per
`(parameter, injection_type)`; findings for the same parameter share `dbms`,
`waf_bypass_used`, `raw_log_spill_id`, and `confidence`.

---

## 2. Input contract

```json
{
  "target_url": "https://app.example.com/item?id=1&category=books",
  "parameters": ["id", "category"],
  "waf_detected": true,
  "oob_domain": "abc123.oast.pro",
  "dbms": "MySQL",
  "method": "POST",
  "parameter": "email",
  "body": {"email": "*", "password": "x"},
  "content_type": "json",
  "cookies": {"session": "abc"},
  "auth_headers": {"Authorization": "Bearer ..."},
  "scope_policy_spill_id": "abc123",
  "tech_fingerprint_spill_id": "def456",
  "config": {"level": 2, "risk": 2, "technique": "BEUT", "prefer_ghauri": true}
}
```

* `target_url` (**required**) — the injectable URL (in scope).
* `parameters` — parameter names to test (defaults to the keys of `body`, or `[parameter]`).
* **Concrete request (Milestone 11 adaptive contract):**
  * `method` — HTTP method (GET/POST/…); forwarded to sqlmap `--method`.
  * `body` / `data` — POST body (object or string); forwarded as sqlmap `--data`, with a `*`
    injection marker placed at `parameter`.
  * `content_type` — `json` | `form` | `query`; adds a `Content-Type: application/json` header
    for JSON bodies.
  * `parameter` — the single field to inject (the loop's chosen injection point).
  * `cookies` (str | `{name:value}` | `[{name,value}]`) — forwarded as `--cookie`.
  * `auth_headers` (`{header:value}`) — forwarded as request headers (`-H`), for authenticated
    endpoints via the coordinator's auth passthrough.
* `waf_detected` — enables WAF-bypass tamper chains (also inferred from
  `tech_fingerprint_spill_id`).
* `oob_domain` — an interactsh/OAST domain; enables the DNS OOB detection channel.
* `dbms` / `tech_fingerprint_spill_id` — DBMS hint (fewer payloads, gentler).

---

## 3. Safety model (this is offensive tooling — read this)

| Guard | Enforcement |
| --- | --- |
| Techniques | `BEUT` only (Boolean/Error/Union/Time). The stacked-query technique `S` is stripped from any config — no arbitrary statement execution. |
| Blocked flags | `--os-shell`, `--os-pwn`, `--sql-shell`, `--file-read/write`, `--dump*`, `--dbs`, `--passwords`, `--udf-inject`, `--all`, … A `_assert_safe()` guard **refuses to launch** any argv containing them (a `blocked flag` error is recorded, the tool never runs). |
| Proof only | Impact is shown via read-only identity metadata (`--banner`, `--current-user`, `--current-db`, `--is-dba`). **No table dumps** — data exfiltration is a separate, human-gated action outside this skill. |
| Risk | Capped at `2`; `risk > 2` is refused by the guard. |
| Scope | Only the in-scope target host is tested; otherwise a fatal artifact is returned **before any tool runs**. |

`meta.safety` echoes these settings so the Observer can assert them
(`stacked_queries:false`, `table_dumps:false`, `destructive:false`, `risk_cap:2`).

---

## 4. Confidence (dual-method agreement)

`injection_type` ∈ `{error, boolean, time, union, oob}`. For a parameter, the
distinct methods found across ghauri + sqlmap are pooled:

* **confirmed** — ≥ 2 distinct methods agree (e.g. boolean + time), the anti-
  false-positive bar from the Loop Engineering doc.
* **suspected** — a single method fired; a real lead, not yet corroborated.

Raw tool logs (stdout/stderr, output dir) are always offloaded to
`raw_log_spill_id` (Offload Law) — never inlined.

---

## 5. WAF bypass

When `waf_detected`, DBMS-aware sqlmap tamper chains are selected
(`space2comment`, `randomcase`, `charencode`, `between`,
`modsecurityversioned`, …) and reported in `waf_bypass_used`.

---

## 6. Example artifact (abridged)

```json
{
  "findings": [
    {"parameter": "id", "injection_type": "boolean", "confidence": "confirmed",
     "dbms": "MySQL", "waf_bypass_used": "space2comment,randomcase,charencode,between",
     "raw_log_spill_id": "9f2a1c7b6d4e0a53",
     "proof": {"banner": "5.7.31", "current_user": "app@localhost", "current_db": "shop"}},
    {"parameter": "id", "injection_type": "time", "confidence": "confirmed",
     "dbms": "MySQL", "waf_bypass_used": "space2comment,randomcase,charencode,between",
     "raw_log_spill_id": "9f2a1c7b6d4e0a53", "proof": {"banner": "5.7.31"}}
  ],
  "meta": {"skill": "sqli-database-injection", "status": "ok", "technique": "BEUT",
           "risk": 2, "level": 2, "waf_aware": true,
           "safety": {"stacked_queries": false, "table_dumps": false,
                      "destructive": false, "risk_cap": 2},
           "confirmed_findings": 2, "suspected_findings": 0},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": []
}
```

---

## 7. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.stacked_queries` / `table_dumps` / `destructive` are all `false`
   and `meta.risk <= 2` (a violation quarantines the run).
3. every finding's `raw_log_spill_id` resolves in the spill store.
4. the tested host equals `scope_summary.target_host` and was in scope.

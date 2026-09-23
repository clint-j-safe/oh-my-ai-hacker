# payload-library artifact

A queryable arsenal. Given a `vuln_class` (and optional `technique`), returns a
small, TARGETED set of payloads/probe strings — pulled from the shipped wordlists
and payload files, plus curated built-ins — for the caller to fire via
`http_request`. It makes NO network calls (egress: none).

## Output shape (validated against `artifact.schema.json`)

```json
{
  "vuln_class": "sqli",
  "technique": "error",
  "count": 6,
  "payloads": [
    {"value": "'", "note": "single quote — look for a SQL/DB error string in the response", "technique": "error"}
  ],
  "sources": ["built-in", "injection-battery-xxe-ssti-nosql/assets/injection-payloads.json"],
  "usage": "Fire ONE cheap probe first; escalate only on a positive/near-positive signal.",
  "meta": {"skill": "payload-library", "status": "ok", "generated_at": "..."}
}
```

Each payload's `note` says what response signal confirms a hit, so the caller can
triage cheaply and escalate (heavier payloads / a confirmation tool) only when a
probe already showed signal.

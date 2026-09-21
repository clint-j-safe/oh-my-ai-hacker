# Artifact Contract — `tech-fingerprinting`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. **This artifact informs the LLM Threat Model and Skill Planner**: they
read the detected `stack` (and `meta.signals`) to decide what to test, `waf`
to decide whether WAF-bypass payload sets are needed, and `edge` to know who is
actually answering. (Milestone 14 removed the deterministic `recommended_skills`
class table — skill selection is now LLM-driven.)
A non-parseable/invalid output is a **failure**. On setup error, emit a
schema-valid artifact with empty `stack`, empty `edge`, `waf.detected:false`, and
`meta.status:"error"`.

**Milestone 20 made this the only passive skill.** Subdomain and asset discovery
were removed from the framework: the engagement surface is the list of URLs the
operator supplied and nothing widens it. Passive work is therefore entirely
*characterisation* of those URLs — web tech, server tech, framework versions,
CDN and cloud services, WAF or no WAF — and never enumeration of new hosts.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "tech-fingerprinting artifact",
  "type": "object",
  "required": ["stack", "waf"],
  "properties": {
    "stack": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["component", "confidence"],
        "properties": {
          "component": { "type": "string" },
          "version": { "type": ["string","null"] },
          "category": { "enum": ["server","framework","language","database","cdn","library"] },
          "confidence": { "enum": ["high","medium","low"] },
          "evidence": { "type": "string" },
          "known_cves": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "id": { "type": "string" },
                "severity": { "enum": ["critical","high","medium","low"] },
                "summary": { "type": "string" }
              }
            }
          }
        }
      }
    },
    "waf": {
      "type": "object",
      "properties": {
        "detected": { "type": "boolean" },
        "product": { "type": ["string","null"] },
        "evidence": { "type": "string" }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`/`errors` and the CVE-overflow fields):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target": "https://app.example.com",
  "captured_responses_spill_id": "abc123",
  "sitemap_spill_id": "def456"
}
```

* `captured_responses_spill_id` (**preferred**) — a spilled corpus of responses.
  Accepted shapes: a list of `{url, status, headers, body}`; `{"responses": [...]}`;
  or a HAR (`{"log": {"entries": [...]}}`). **If present, it is used verbatim —
  the skill does not re-probe the target.**
* `sitemap_spill_id` (optional) — used only as probe seeds in the fallback path.
* `target` — required when no captured responses are supplied; the fallback
  probe stays on the target host (root + up to 8 sitemap URLs).

---

## 3. Version → CVE mapping (OSV.dev)

For each detected component with an OSV package name (see
`assets/fingerprints.json → osv_ecosystem`) and a resolved version, the skill
POSTs to `https://api.osv.dev/v1/query`:

```json
{ "package": {"name": "spring-boot", "ecosystem": "Maven"}, "version": "2.4.1" }
```

Severity is computed from each vuln's **CVSS v3 vector** via a built-in base-
score calculator (`critical ≥9, high ≥7, medium ≥4, low >0`); if no CVSS vector
is present it falls back to the advisory's `database_specific.severity`. The id
prefers a `CVE-…` alias, else the OSV id (e.g. `GHSA-…`). Raw OSV payloads are
spilled to `meta.raw_osv_spill_id`. No API key is required; OSV failures are
recorded in `errors` and never abort the run.

---

## 4. Offload Law binding

| Corpus | Rule |
| --- | --- |
| raw OSV payloads | Spilled to `meta.raw_osv_spill_id`. |
| per-component `known_cves` | Inlined; if `> 15` (or `> 50 KB`), the full list spills to `stack[i].cves_overflow_spill_id`, inline capped at 15, and `stack[i].known_cves_total` gives the true count. |

---

## 5. `meta.signals` — how the LLM is steered

`meta.signals` is a deterministic, deduped list of stack signals derived from the
detected components (e.g. `lang:php`, `framework:spring`, `db:mongodb`, `spa`,
`graphql`, `waf`). It is **advisory context** the LLM Threat Model and Skill
Planner read to reason about what to test — it does not itself select skills.
(Milestone 14 removed the old deterministic `recommended_skills` class table and
its `fingerprints.json → skill_rules`; the LLM proposes skills now.)

---

## 6. Example artifact (abridged)

```json
{
  "stack": [
    {"component": "nginx", "version": "1.18.0", "category": "server", "confidence": "high",
     "evidence": "header server: nginx/1.18.0", "known_cves": [
       {"id": "CVE-2021-23017", "severity": "high", "summary": "nginx resolver off-by-one heap write"}]},
    {"component": "PHP", "version": "7.4.3", "category": "language", "confidence": "high",
     "evidence": "header x-powered-by: PHP/7.4.3", "known_cves": []}
  ],
  "waf": {"detected": true, "product": "Cloudflare", "evidence": "header cf-ray: 7a1b...",
          "checked": true, "responses_examined": 6},
  "edge": [
    {"product": "Cloudflare", "kind": "cdn", "evidence": "header cf-ray: 7a1b..."},
    {"product": "Amazon Web Services", "kind": "cloud", "evidence": "header x-amzn-trace-id: Root=1-..."}
  ],
  "meta": {"skill": "tech-fingerprinting", "status": "ok", "responses_analyzed": 6,
           "data_source": "spill", "components_detected": 2, "cve_total": 1,
           "edge_providers": ["Cloudflare","Amazon Web Services"], "waf_detected": true,
           "signals": ["lang:php","waf"], "raw_osv_spill_id": "9f2a1c7b6d4e0a53"},
  "errors": []
}
```

---

## 7. `edge` — who is answering, and why it changes every later reading

`edge` lists the CDN and cloud providers detected in front of the application, each
matched by a vendor signature the provider publishes about itself (a request id, a
cache status, a branded `Server` value). Matching is by signature only — nothing is
inferred from an address or a hostname — so a target served directly yields `[]`
rather than a guess.

Every matching provider is reported, not just the first, because a site can sit
behind a CDN that is itself in front of a cloud host. Collapsing that to one name
loses the part an operator needs: which layer a given response came from.

This is not inventory. An edge in the path means a block, a cached body or a
rewritten header may be the *provider's* behaviour rather than the application's —
so a hypothesis refuted on such a response has been refuted against the wrong thing.
`kind` separates `cdn` (a cache/proxy in front) from `cloud` (the hosting platform).

---

## 8. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `waf.product` is non-null whenever `waf.detected` is true.
3. `waf.checked` is always true — "no WAF" is a finding, not a missing field, so the
   absence must be stated rather than inferred from a key nobody wrote.
4. `edge[i].kind` is one of `cdn` / `cloud`; an empty array means no provider matched,
   never that the check was skipped.
5. every `stack[i].cves_overflow_spill_id` (when present) resolves in the spill store.

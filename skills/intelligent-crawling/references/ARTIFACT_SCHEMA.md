# Artifact Contract — `intelligent-crawling`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable or invalid output is a **failure** to the Observer.
On fatal error the skill emits a schema-valid artifact with empty `sitemap`/
`forms_discovered`, populated `crawl_stats`, and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "intelligent-crawling artifact",
  "type": "object",
  "required": ["sitemap", "forms_discovered", "crawl_stats"],
  "properties": {
    "sitemap": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["url", "method", "captured_request_spill_id"],
        "properties": {
          "url": { "type": "string" },
          "method": { "type": "string" },
          "requires_auth": { "type": "boolean" },
          "role_used": { "type": "string" },
          "content_type": { "type": "string" },
          "captured_request_spill_id": { "type": "string" },
          "discovered_by": { "enum": ["navigation","xhr","fetch","websocket","form_action"] }
        }
      }
    },
    "forms_discovered": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "url": { "type": "string" },
          "action": { "type": "string" },
          "method": { "type": "string" },
          "input_fields": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": { "type": "string" },
                "type": { "type": "string" },
                "required": { "type": "boolean" }
              }
            }
          }
        }
      }
    },
    "crawl_stats": {
      "type": "object",
      "properties": {
        "pages_crawled": { "type": "integer" },
        "requests_captured": { "type": "integer" },
        "budget_remaining_pct": { "type": "number" },
        "roles_completed": { "type": "array", "items": { "type": "string" } }
      }
    },
    "har_spill_id": { "type": ["string","null"] }
  }
}
```

The full machine-readable copy, incl. additive `meta`/`scope_summary`/`errors`,
is `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target": "https://app.example.com",
  "session_cookies": { "admin": {"session":"..."}, "user": {"session":"..."} },
  "max_pages": 100,
  "timeout_seconds": 300,
  "roles": ["user", "admin"],
  "scope_policy_spill_id": "abc123",
  "config": {
    "dir_bruteforce": false,
    "wordlist": null,
    "capture_resource_types": ["xhr","fetch","document","websocket"],
    "clicks_per_page": 8,
    "katana": false
  }
}
```

* `target` (**required**) — http(s) root URL.
* `session_cookies` — one of: a flat `{name: value}` map applied to all roles; a
  `{role: {name: value}}` map for per-role sessions; or a list of full
  Playwright cookie dicts. Missing role ⇒ crawled unauthenticated.
* `max_pages` / `timeout_seconds` — the hard budget (both enforced).
* `roles` — defaults to `["anonymous"]` (or `["default"]` if cookies given).
* `scope_policy_spill_id` — same policy shape as the other skills. **Only
  in-scope hosts are navigated or probed.**

---

## 3. The `captured_request_spill_id` (replay templates)

Every unique `(method, url)` produces a full request template written to the
spill store:

```json
{ "url": "...", "method": "POST", "resource_type": "xhr",
  "headers": {...}, "cookies": [...], "post_data": "...",
  "status": 200, "content_type": "application/json",
  "role_used": "admin", "discovered_by": "xhr" }
```

These templates contain **cookies and authorization headers**, so — per the
Offload Law and credential-custody discipline — they live only in the spill
store and are referenced from the artifact by `captured_request_spill_id`. The
HTTP Tool (component 21) loads a template by id to replay/mutate it in Phase 5.
`har_spill_id` points to a HAR-shaped bundle of every entry.

---

## 4. Budget & safety invariants

| Invariant | Rule |
| --- | --- |
| Page budget | crawl stops at `max_pages`. |
| Time budget | crawl stops at the `timeout_seconds` deadline. |
| `budget_remaining_pct` | `100 * (1 - max(pages/max_pages, elapsed/timeout))`. |
| Scope | every `sitemap[].url` host is in scope; off-scope links/redirects dropped. |
| Blast radius | forms are **discovered, never submitted**; destructive controls (delete/logout/pay/…) are never clicked. |
| Dir-brute | runs only if `dir_bruteforce:true` AND `pages_crawled < 20`; hard-capped at 500 requests. |

---

## 5. Example artifact (abridged)

```json
{
  "sitemap": [
    {"url": "https://app.example.com/api/v1/me", "method": "GET",
     "requires_auth": true, "role_used": "admin", "content_type": "application/json",
     "captured_request_spill_id": "a1b2c3d4e5f60718", "discovered_by": "xhr"},
    {"url": "https://app.example.com/login", "method": "GET",
     "requires_auth": false, "role_used": "anonymous", "content_type": "text/html",
     "captured_request_spill_id": "0f1e2d3c4b5a6978", "discovered_by": "navigation"}
  ],
  "forms_discovered": [
    {"url": "https://app.example.com/login", "action": "https://app.example.com/api/login",
     "method": "POST", "input_fields": [
       {"name": "email", "type": "email", "required": true},
       {"name": "password", "type": "password", "required": true}]}
  ],
  "crawl_stats": {"pages_crawled": 42, "requests_captured": 118,
                  "budget_remaining_pct": 58.0, "roles_completed": ["anonymous","admin"]},
  "har_spill_id": "7c1e9a0b4d5f2318",
  "meta": {"skill": "intelligent-crawling", "status": "ok", "budget_exhausted": false,
           "forms_count": 1, "sitemap_overflow_spill_id": null, "playwright_available": true},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. every `sitemap[].url` host passes the scope policy.
3. every `sitemap[].captured_request_spill_id` resolves in the spill store.
4. `har_spill_id` is non-null whenever `crawl_stats.requests_captured > 0`.
5. `crawl_stats.pages_crawled <= input.max_pages` (budget honored).

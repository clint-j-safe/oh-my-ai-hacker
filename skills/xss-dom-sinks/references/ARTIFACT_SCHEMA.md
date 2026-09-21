# Artifact Contract — `xss-dom-sinks`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (no in-scope endpoints, Playwright missing) the skill emits a
schema-valid artifact with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "xss-dom-sinks artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["url", "xss_type", "payload", "evidence_spill_id"],
        "properties": {
          "url": { "type": "string" },
          "xss_type": { "enum": ["reflected","stored","dom"] },
          "payload": { "type": "string" },
          "context": { "type": "string" },
          "evidence_spill_id": { "type": "string", "description": "Screenshot / DOM / HAR spill ID" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `parameter`, `confidence`, `executed`, `meta`,
`scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "endpoints": [
    {"url": "https://app.example.com/search", "params": ["q"], "context": "html"},
    {"url": "https://app.example.com/profile", "params": ["bio"], "context": "attr",
     "method": "POST", "store_param": "bio",
     "view_url": "https://app.example.com/u/testuser", "test_types": ["stored"]}
  ],
  "session_pool_spill_id": "phase3_sessions_hash",
  "oob_domain": "abc.oast.pro",
  "scope_policy_spill_id": "abc123",
  "config": {"allow_stored": true}
}
```

* `endpoints[]` — each has `url`, `params`, `context` (`html`/`attr`/`js`,
  drives payload selection), optional `method`, `store_param`, `view_url`
  (required to run the stored test), and `test_types` (subset of
  `reflected`/`dom`/`stored`).
* `session_pool_spill_id` — the Phase 3 pool; session[0] injects, session[1]
  observes (cross-session stored verification).
* `oob_domain` — optional OAST domain for blind XSS callbacks.

---

## 3. Safety model (offensive tooling — read this)

| Guard | Enforcement |
| --- | --- |
| Benign payloads | Every payload is `alert()/confirm()/prompt()` carrying a unique `XSS<hex>` canary. Execution is confirmed only when a dialog fires whose message contains that canary. No `document.cookie` theft, no `fetch()`/beacon to any host, no DOM defacement. `meta.safety` records `cookie_theft:false`, `external_beacon:false`. |
| Stored = tracked mutation | Reflected/DOM are non-persistent. Every stored injection writes a benign canary and is appended to `meta.mutations` (`canary`, `store_url`, `param`, `payload`) so the cleanup skill can find and remove it. Stored runs only when `view_url` is supplied and `config.allow_stored` (default true). |
| Scope | Only in-scope endpoint hosts are tested; out-of-scope endpoints are skipped and recorded. |
| Confirm | `confirmed` = a dialog fired with the canary (execution proven). `suspected` = unencoded reflection or a stored write with no observed execution. |

---

## 4. Detection methods

* **Reflected** — inject the payload in each param (httpx), check for unencoded
  reflection, then load it in Playwright and catch the dialog.
* **DOM** — load the URL with the payload in the param **and** the fragment
  (`#…`, client-only sinks like `location.hash` → `innerHTML`/`document.write`);
  a fired dialog with no server reflection is DOM-based.
* **Stored** — inject as session A (write), then load `view_url` as session B
  and catch the dialog (`cross_session: true` when A≠B).
* **Dalfox** (optional) — fast reflection pre-scan when the binary is present.

Evidence (screenshot + DOM snapshot) is offloaded to `evidence_spill_id` per
finding (Offload Law) — never inlined.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"url": "https://app.example.com/search", "xss_type": "reflected",
     "payload": "<img src=x onerror=alert('XSS1a2b3c4d')>", "context": "html",
     "parameter": "q", "confidence": "confirmed", "executed": true,
     "evidence_spill_id": "9f2a1c7b6d4e0a53"},
    {"url": "https://app.example.com/u/testuser", "xss_type": "stored",
     "payload": "<svg onload=alert('XSS9988aabb')>", "context": "html",
     "parameter": "bio", "confidence": "confirmed", "executed": true,
     "evidence_spill_id": "0f1e2d3c4b5a6978"}
  ],
  "meta": {"skill": "xss-dom-sinks", "status": "ok", "confirmed_findings": 2,
           "suspected_findings": 0,
           "safety": {"payloads": "benign_alert_canary", "cookie_theft": false, "external_beacon": false},
           "mutations": [{"type": "stored_xss_canary", "canary": "XSS9988aabb",
                          "store_url": "https://app.example.com/profile", "param": "bio",
                          "note": "benign alert() canary; remove during cleanup"}]},
  "scope_summary": {"policy_present": true},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. every finding's `evidence_spill_id` resolves in the spill store.
3. `meta.safety.cookie_theft` and `external_beacon` are `false`.
4. every stored finding has a matching `meta.mutations` entry (cleanup handle).
5. `confidence == "confirmed"` ⇒ `executed == true`.

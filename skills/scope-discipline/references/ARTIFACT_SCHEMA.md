# Artifact Contract — `scope-discipline`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Proposer. This
skill **sends no traffic** (`meta.sends_traffic:false`) and is **advisory only**
(`meta.advisory_only:true`) — the deterministic Safety Gate makes the final call
(`meta.final_authority:"deterministic-safety-gate"`).

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "scope-discipline artifact",
  "type": "object",
  "required": ["verdict", "reason"],
  "properties": {
    "verdict": { "enum": ["proceed", "modify", "abort"] },
    "reason":  { "type": "string" },
    "modified_action": {
      "type": ["object", "null"],
      "description": "If verdict is 'modify', the safer alternative action.",
      "properties": {
        "url":    { "type": "string" },
        "method": { "type": "string" }
      }
    },
    "scope_rule_matched": { "type": "string" }
  }
}
```

Machine copy (incl. additive `meta`/`errors` and `modified_action.follow_redirects`):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "proposed_action": {"url": "https://api.example.com/v1/users", "method": "GET", "payload": ""},
  "scope_policy_spill_id": "phase0_scope_hash",
  "scope_policy": {
    "in_scope":     ["example.com", "*.example.com"],
    "out_of_scope": ["prod.example.com", "*.internal.example.com"],
    "deny":         ["api.other.com"],
    "allow_ips":    ["203.0.113.10"],
    "allowed_schemes": ["https"],
    "redirect_map": {"https://example.com/go": "https://tracker.other.com/"}
  },
  "config": {"allowed_schemes": ["https"]}
}
```

* `proposed_action.url` — **required.** The action the Proposer wants to submit.
* Scope policy source: inline `scope_policy` wins; otherwise it is read from
  `scope_policy_spill_id` (the Phase 0 spill; the record may be the policy itself
  or `{"scope_policy": {...}}`).
* `in_scope` — exact domains and `*.domain` subdomain wildcards (the wildcard does
  **not** cover the apex; list the apex too if intended).
* `out_of_scope` / `deny` — exact or wildcard rules that **override** any allow.
* `allow_ips` — IP literals explicitly permitted (bypasses the internal-IP guard).
* `allowed_schemes` — permitted URL schemes (default `["http","https"]`).
* `redirect_map` — Phase 2 sitemap: known URL → redirect-destination pairs.

---

## 3. Decision procedure (precedence, top wins)

1. No URL / no policy loaded → `abort` (default-deny).
2. URL unparseable or no host → `abort`.
3. **userinfo present** (`user@host`) → `abort` — the real host is after the `@`;
   this is the classic `http://example.com@evil.com` scope-spoof.
4. **Internal-IP guard** — host is a loopback / RFC1918 / link-local / reserved IP
   (incl. `169.254.169.254`) not in `allow_ips` or `in_scope` → `abort`.
5. **Deny match** (exact or wildcard) → `abort`.
6. **No in-scope match** → `abort` (default-deny).
7. In scope, but **scheme not allowed** → `modify` to the allowed scheme (http↔https)
   or `abort`.
8. In scope, but **redirect_map shows an out-of-scope destination** → `modify`
   (same URL, `follow_redirects:false`).
9. Otherwise → `proceed`.

**Boundary safety.** Host suffix checks are label-anchored: `example.com.evil.com`,
`notexample.com`, and `evilexample.com` never match `example.com` /`*.example.com`.
Hosts are IDNA-normalized to punycode before comparison (homograph-safe), and the
most specific in-scope rule is reported in `scope_rule_matched`.

---

## 4. Example artifacts

Proceed:
```json
{"verdict": "proceed", "reason": "host 'api.example.com' is in scope via rule '*.example.com'",
 "modified_action": null, "scope_rule_matched": "*.example.com",
 "meta": {"skill": "scope-discipline", "advisory_only": true, "sends_traffic": false,
          "final_authority": "deterministic-safety-gate"}, "errors": []}
```

Abort (scope-spoof):
```json
{"verdict": "abort",
 "reason": "userinfo present in URL ('example.com@'); real host is 'evil.com' -- classic scope-spoof, refusing",
 "modified_action": null, "scope_rule_matched": "userinfo_spoof", "meta": {"advisory_only": true}}
```

Modify (out-of-scope redirect):
```json
{"verdict": "modify",
 "reason": "URL is in scope but historically 3xx-redirects to out-of-scope 'tracker.other.com'; proceed only with redirect-following disabled",
 "modified_action": {"url": "https://example.com/go", "method": "GET", "follow_redirects": false},
 "scope_rule_matched": "redirect_out_of_scope:tracker.other.com"}
```

---

## 5. Proposer-side use (reference)

* `proceed` → forward to the Safety Gate unchanged.
* `modify` → adopt `modified_action` (or drop the action) before the Gate.
* `abort` → do not submit; pick another action. Saves the token/round-trip cost of
  a certain Gate denial.
* This verdict is **advisory**. The deterministic Safety Gate remains the sole
  authority that permits or blocks traffic; a `proceed` here is never a bypass.

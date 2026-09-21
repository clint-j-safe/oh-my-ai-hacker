# Artifact Contract — `waf-evasion-mastery`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Dispatcher. On any
fatal condition (missing url/payload, destructive token) the skill emits a
schema-valid artifact with `bypass_successful:false` and populated `errors`.

This skill **re-encodes** an already-vetted, blocked payload and retries it. It
sends live traffic **only** to in-scope hosts and **only** when not in dry-run;
otherwise it merely generates candidate mutations.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "waf-evasion-mastery artifact",
  "type": "object",
  "required": ["bypass_successful", "effective_encoding"],
  "properties": {
    "bypass_successful": { "type": "boolean" },
    "effective_encoding": { "type": "string" },
    "mutated_payload":    { "type": "string" },
    "registry_spill_id":  { "type": "string" }
  }
}
```

Machine copy (incl. additive `meta`/`errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "blocked_request": {
    "url": "https://app.example.com/search?q=' OR 1=1--",
    "method": "GET",
    "payload": "' OR 1=1--",
    "param": "q",
    "headers": {"Cookie": "session=...", "User-Agent": "..."},
    "body": null,
    "waf_status": 403,
    "waf_response_headers": {"cf-ray": "8a...", "server": "cloudflare"},
    "waf_response_body": "<html>Attention Required ...</html>"
  },
  "waf_type": "cloudflare",
  "config": {
    "scope": {"allowed_hosts": ["example.com"]},
    "mutation_budget": 16,
    "dry_run": false,
    "timeout_s": 15,
    "canary": "1=1"
  }
}
```

* `blocked_request` — **required** (needs at least `url` + `payload`). The block
  response (`waf_status` / `waf_response_headers` / `waf_response_body`) drives
  fingerprinting; `param` names where the payload sits (query or body).
* `waf_type` — optional operator hint; the response signature overrides it.
* `config.scope.allowed_hosts` — **the loop invariant.** Live retries happen only
  when the request host equals or is a subdomain of a listed host.
* `config.mutation_budget` — hard cap on live retries (default 16).
* `config.dry_run` — generate mutations without sending any.
* `config.canary` — benign marker that every mutation must still decode to; a
  mutation that would drop it is discarded (a bypass is proven with the same
  harmless string the exploit skill used).

---

## 3. Safety model (the property this skill enforces)

* **Scope invariant.** No `allowed_hosts`, host out of scope, or `dry_run:true` ⇒
  `meta.mode == "dry_run"`, `meta.requests_sent == 0`, `bypass_successful:false`.
  The skill never widens scope and never sends out-of-scope traffic.
* **Mutation budget.** At most `mutation_budget` live requests; stops at the first
  non-blocked response. `meta.requests_sent` reports the exact count.
* **Re-encode, never re-arm.** Encodings transform the *representation* of the
  handed payload only. Incoming payloads carrying OS/shell weaponization
  (`rm -rf`, `mkfs`, fork bombs, `curl … | sh`, `/etc/shadow`, …) are refused
  (`errors`, no traffic). With a `canary`, every candidate is asserted to decode
  back to it.
* **Custody.** `Authorization` / `Cookie` / `x-api-key` are passed through for the
  retry but appear in the artifact and registry only as `credential_hash` — never
  in cleartext.

---

## 4. Encoding repertoire

Single-pass: `url_encode`, `double_url_encode`, `url_special_only`, `case_swap`,
`keyword_case_swap`, `inline_comment` (`/*!50000…*/`), `comment_space` (`/**/`),
`ws_tab`, `ws_newline`, `unicode_fullwidth`, `unicode_overlong`. Chains:
`keyword_case_swap+inline_comment`, `comment_space+double_url_encode`,
`case_swap+url_encode`. Transport: `chunked_transfer` (Transfer-Encoding: chunked,
tried once if a body is present and payload mutations all fail). All generated
candidates (with de-dup) are offloaded to `meta.candidates_spill_id`.

---

## 5. Registry

Successful `(waf, encoding)` chains are written to a **durable** JSON registry at
`WAF_REGISTRY_PATH` (default beside the spill store, survives sessions) so every
active loop can prefer known-good encodings for that WAF. Each hit bumps a
counter and records an `example_hash`. `registry_spill_id` points at the post-
update snapshot for the Observer.

---

## 6. Example artifact (abridged)

```json
{
  "bypass_successful": true,
  "effective_encoding": "keyword_case_swap+inline_comment",
  "mutated_payload": "' Or/*!50000 1=1*/--",
  "registry_spill_id": "7d4e2a1c0b9f8e6d",
  "meta": {
    "skill": "waf-evasion-mastery", "version": "1.0", "phase": "6",
    "loop_component": "4-dispatcher", "status": "ok",
    "waf": "cloudflare", "mode": "live", "in_scope": true,
    "requests_sent": 6, "mutation_budget": 16, "candidates_generated": 13,
    "candidates_spill_id": "0f1e2d3c4b5a6978", "credential_hash": "9f2a1c7b6d4e0a53",
    "canary_enforced": true,
    "attempts": [{"encoding": "url_encode", "sent": true, "status": 403, "blocked": true, "waf_now": "cloudflare"}],
    "note": ""
  },
  "errors": []
}
```

---

## 7. Dispatcher-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `bypass_successful:true` requires `meta.mode == "live"`, `meta.in_scope == true`,
   a non-empty `effective_encoding`, and a matching `attempts[]` entry with
   `blocked:false`.
3. `meta.requests_sent <= meta.mutation_budget`.
4. No cleartext credentials anywhere in the artifact (only `credential_hash`).
5. On a success, `registry_spill_id` is non-empty and the registry snapshot lists
   the `(waf, effective_encoding)` chain.

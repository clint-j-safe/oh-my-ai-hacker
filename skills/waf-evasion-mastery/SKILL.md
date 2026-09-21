---
name: waf-evasion-mastery
description: >-
  The Dispatcher's adaptation handler. When an already-vetted exploit request is
  blocked by a WAF (403/406/429/...), it fingerprints the WAF from its response,
  re-derives encodings of the SAME payload (double-URL, Unicode fullwidth/overlong,
  case-swap, inline comments, whitespace tricks, chunked transfer), retries them
  under a strict budget against in-scope hosts only, and records the winning
  bypass chain to a durable registry every active loop can reuse. Use in Phase 6
  when exploitation is blocked. Re-encodes, never re-arms: it sends live traffic
  only to scoped hosts, refuses destructive payloads, and hashes credentials.
license: Apache-2.0
compatibility: Python 3.11+, httpx. Optional wafw00f for out-of-band fingerprinting.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "6"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(wafw00f:*)
---

# WAF Evasion Mastery

You are the **Dispatcher's memory of what gets through**. An exploit the loop
already proved valid comes back blocked at the edge — a WAF sits between the loop
and the finding. Your job is not to invent a new attack; it is to find the
*encoding* of the existing, vetted payload that the WAF lets pass, prove it with
the same benign marker, and remember the winning chain so no loop has to
rediscover it. You adapt representation, never intent.

## Correctness (this is the whole safety story)

1. **Scope is the invariant.** A mutation is *sent* only when the request host is
   in `config.scope.allowed_hosts` and `dry_run` is off. Otherwise you generate
   candidates and return them — `meta.mode == "dry_run"`, zero requests, never a
   packet out of scope. You do not widen scope.
2. **Bounded adaptation.** At most `config.mutation_budget` live retries (default
   16); you stop at the first non-blocked response and report the exact count in
   `meta.requests_sent`.
3. **Re-encode, never re-arm.** You transform the *encoding* of the handed
   payload — you never synthesize new attack strings. Incoming payloads carrying
   OS/shell weaponization (`rm -rf`, `mkfs`, fork bombs, `curl … | sh`,
   `/etc/shadow`) are refused before any traffic. With a `canary`, every candidate
   must still decode back to it, so a bypass is proven with the same harmless
   marker the exploit skill used.
4. **Credential custody.** `Authorization` / `Cookie` / `x-api-key` are passed
   through for the retry but recorded only as `credential_hash` — never echoed.

## Inputs

```json
{ "blocked_request": {"url": "https://app.example.com/search?q=' OR 1=1--",
                      "method": "GET", "payload": "' OR 1=1--", "param": "q",
                      "headers": {"Cookie": "session=..."},
                      "waf_status": 403, "waf_response_headers": {"cf-ray": "8a.."},
                      "waf_response_body": "Attention Required"},
  "waf_type": "cloudflare",
  "config": {"scope": {"allowed_hosts": ["example.com"]}, "mutation_budget": 16,
             "dry_run": false, "timeout_s": 15, "canary": "1=1"} }
```

The block response drives fingerprinting; `param` says where the payload sits.
`allowed_hosts` gates all live traffic; `canary` is the benign marker every
mutation must preserve.

## How to run

```bash
python scripts/run.py '{"blocked_request":{"url":"https://app.example.com/s?q=x","payload":"x","param":"q","waf_status":403},"config":{"scope":{"allowed_hosts":["example.com"]},"dry_run":true}}'
```

`run.py` pipeline (`WAFEvasion`):

1. `analyze_signature()` — fingerprint the WAF from response headers / cookies /
   body / status against `assets/waf_signatures.json`.
2. `mutate_payload()` — build ordered, de-duplicated encoding candidates
   (singletons then chains); drop any that lose the `canary`.
3. `retry_request()` — within budget and scope, send each candidate (and a single
   `chunked_transfer` transport attempt); a non-blocked response wins.
4. `update_registry()` — persist the winning `(waf, encoding)` to the durable
   registry and spill a snapshot (`registry_spill_id`).

## Typed exits

- `bypass_successful: true` — a scoped, live retry returned a non-blocked
  response; `effective_encoding` + `mutated_payload` name the chain, registry
  updated.
- `bypass_successful: false`, `mode: "live"` — every mutation within budget was
  still blocked (`note: "all mutations still blocked"`).
- `bypass_successful: false`, `mode: "dry_run"` — no scope / dry-run; candidates
  generated only, in `meta.candidates_spill_id`.
- error artifact — missing url/payload, or a refused destructive payload.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| SecLists — WAF bypass | Payload/encoding reference corpus | https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/WAF |
| wafw00f | Active WAF fingerprinting (out of band) | https://github.com/EnableSecurity/wafw00f |
| httpx | Retry transport (incl. chunked) | https://www.python-httpx.org/ |

Install: `pip install httpx` (+ `wafw00f` from upstream, optional).

## Wordlists / assets

`assets/waf_signatures.json` — response-side WAF fingerprints (Cloudflare, AWS
WAF, Akamai, Imperva, F5 ASM, ModSecurity, Sucuri, Wordfence, Barracuda,
FortiWeb, Azure Front Door, generic). Loaded at runtime and merged over built-in
defaults; extend it to teach new WAFs. Encodings are generated in code, not from
a payload wordlist.

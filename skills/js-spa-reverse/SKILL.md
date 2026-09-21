---
name: js-spa-reverse
description: >-
  Statically reverse-engineers JavaScript/SPA bundles to extract the hidden
  attack surface a modern app keeps in its JS rather than its HTML: API
  endpoints, client routes, query parameters, environment keys, framework
  fingerprints, and hardcoded secrets. Use in Phase 1-2 once bundle URLs are
  known (React, Vue, Angular, Next.js, Svelte). Returns a strict JSON
  endpoint+bundle map and a secrets inventory (hashes only, never raw values).
  Do NOT use for active endpoint probing, auth, or crawling — it only reads the
  public static bundles a browser already downloads.
license: Apache-2.0
compatibility: >-
  Python 3.11+, Node.js 18+ (optional, for JS-side tooling), httpx, and esprima
  (pip). Regex library in assets/patterns.json is derived from SecLists/Regex
  and public gitleaks/trufflehog rules. Outbound network needed to fetch the
  in-scope bundles.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "1-2"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(node:*) Bash(curl:*)
---

# JS / SPA Reverse Engineering

You are executing **Phase 1-2 bundle analysis**. A modern SPA's real attack
surface lives in its JavaScript, not its HTML: routes, API paths, params, and
too often hardcoded secrets are all compiled into the bundle. Your job is to
statically recover that surface and hand the loop a clean map. You do not probe
or exploit — you read the public bytes the browser already gets.

## Laws that bind this skill

1. **Scope** — fetch a bundle only if its host is in scope. Off-scope or
   off-policy URLs are recorded in `meta.bundles_skipped`, never downloaded.
2. **Secret custody** — **never emit a raw secret.** Each finding is a
   `SHA-256(value)` plus a context snippet with the secret itself replaced by
   `<REDACTED:type:len>`. Raw bundles are spilled for evidence; the
   credential-custody skill governs them.
3. **Offload Law** — raw bundles always spill (`raw_bundles_spill_id`); any
   match set > 200 (or > 50 KB) spills with the full set behind an overflow
   pointer and a capped inline array.
4. **Artifact Contract** — one strict JSON object on stdout, no prose.

## Inputs

```json
{ "js_urls": ["https://example.com/main.js"], "target": "example.com",
  "scope_policy_spill_id": "abc123" }
```

- `js_urls` (required): bundle URLs, typically from `osint-passive-enum` or the
  crawler upstream.
- `target` (recommended): apex domain; the default scope when no policy given.
- `scope_policy_spill_id` (optional): same policy shape as the OSINT skill.

## How to run

```bash
python scripts/run.py '{"js_urls":["https://example.com/main.js"],"target":"example.com"}'
# or:  echo '{...}' | python scripts/run.py
```

`run.py` pipeline (`JSReverseEngineer`):

1. `download_bundles()` — async httpx GET of each **in-scope** URL (size-capped,
   redirects followed). Skips are recorded, not fatal.
2. `extract_endpoints()` — compiled regexes from `assets/patterns.json`:
   `/api/**`, `/v<n>/**`, `/graphql`, `/rest/**`, absolute URLs, declared routes
   (`path:`, `<Route path=>`, `to=`), and WebSocket URLs.
3. `extract_secrets()` — secret rule set (AWS, GCP, Azure, JWT, Firebase, Slack,
   GitHub, Generic) → hash + redacted context.
4. `extract_routes_ast()` — `esprima` tolerant AST parse recovers path-like
   string literals and route-key properties that regex misses (dynamic routes).
   Bundles over the AST size cap are skipped and noted; missing esprima degrades
   to regex-only.
5. `extract_framework()` — marker scoring for React/Vue/Angular/Next/Nuxt/
   Svelte/Ember + version + routing_type + GraphQL presence.
6. `classify_confidence()` / `offload_and_return()` — merge, rank, spill, emit.

## Confidence

- **high** — `/api`, `/v<n>`, `/graphql`, `/rest`, an absolute API URL, or a
  path corroborated by ≥2 extractors.
- **medium** — declared client route, non-API absolute URL, WebSocket URL.
- **low** — path-like literal recovered only from the AST.

`method` stays `unknown` unless it is a WebSocket (`WS`) — verbs are not
reliably co-located with paths in minified code, so we report honestly rather
than guess.

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Required keys: `endpoints`, `secrets`,
`framework` (+ `raw_bundles_spill_id`, and additive `meta`/`scope_summary`/
`errors`). On setup error, emit an empty-but-valid artifact with
`meta.status: "error"`. The Observer commits this to Neo4j WorkingMemory.

## Typed exits

- `surface_mapped` — endpoints and/or routes recovered.
- `no_surface` — bundles analyzed but nothing extracted (valid empty artifact).
- `secrets_found` — one or more secrets detected (raises priority downstream).
- `no_bundles` — every URL was out of scope or unfetchable
  (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| esprima (Python) | JS AST parsing for dynamic route extraction | https://pypi.org/project/esprima/ |
| SecretFinder | Reference for JS secret regexes | https://github.com/m4ll0k/SecretFinder |
| JSFinder | Reference for endpoint/subdomain extraction from JS | https://github.com/Threezh1/JSFinder |
| TruffleHog | Reference/verification for secret detectors | https://github.com/trufflesecurity/trufflehog |

Install: `pip install httpx esprima`. The bundled `assets/patterns.json` is
self-sufficient; SecretFinder/JSFinder/TruffleHog are optional cross-checks.

## Assets / wordlists

`assets/patterns.json` — the compiled regex library (API paths, routes, params,
env keys, GraphQL introspection strings, WebSocket URLs, secret detectors,
framework fingerprints), adapted from **SecLists/Regex**
(https://github.com/danielmiessler/SecLists/tree/master/Regex) and public
gitleaks/trufflehog rules. No brute-force wordlists — this skill is static.

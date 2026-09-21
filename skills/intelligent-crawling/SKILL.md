---
name: intelligent-crawling
description: >-
  Drives a headless Chromium browser (Playwright) through a JavaScript-rendered
  app to discover endpoints, XHR/Fetch calls, WebSocket connections, and forms
  that classic spiders miss. Captures a full replayable request template
  (url, method, headers, cookies, body) for each unique endpoint, offloaded to
  the spill store. Use in Phase 2 (Active Recon) on JS-heavy SPAs. Respects a
  strict page + time budget, stays in scope, and is read-only (never submits
  forms or clicks destructive controls). Returns a rendered sitemap with
  captured-request spill IDs. Do NOT use for exploitation or mutation.
license: Apache-2.0
compatibility: >-
  Python 3.11+, playwright (pip install playwright && playwright install
  chromium), httpx (for the optional dir-brute fallback), and network access to
  the in-scope target. Optional: katana for a fast pre-pass.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "2"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(playwright:*)
---

# Intelligent Crawling

You are executing **Phase 2 active recon**. A JS app's endpoints don't live in
its HTML — they fire from the bundle at runtime as XHR/Fetch/WebSocket calls.
Your job is to render the app in a real browser, walk it like a user, and
capture every unique request as a replay template for later phases. You are
read-only: you map, you never mutate.

## Laws & safety (non-negotiable)

1. **Scope** — navigate or probe only in-scope hosts. Off-scope links and
   redirects are dropped, not followed.
2. **Budget** — stop the instant `max_pages` or the `timeout_seconds` deadline
   is hit. `crawl_stats.budget_remaining_pct` reports headroom.
3. **Blast radius** — forms are **discovered, never submitted**. Controls whose
   text matches destructive keywords (delete, logout, pay, checkout, confirm,
   deactivate, …) are never clicked. Mutation belongs to later skills under the
   mutation budget.
4. **Custody** — captured templates hold cookies/authorization, so they go to
   the spill store; the artifact carries only `captured_request_spill_id`s.
5. **Artifact Contract** — one strict JSON object on stdout, no prose.

## Inputs

```json
{ "target": "https://app.example.com",
  "session_cookies": {"admin": {"session":"..."}, "user": {"session":"..."}},
  "max_pages": 100, "timeout_seconds": 300, "roles": ["user","admin"],
  "scope_policy_spill_id": "abc123",
  "config": {"dir_bruteforce": false, "clicks_per_page": 8} }
```

`session_cookies` accepts a flat `{name:value}` map, a per-role
`{role:{name:value}}` map, or a list of Playwright cookie dicts.

## How to run

```bash
python scripts/run.py '{"target":"https://app.example.com","max_pages":50,"timeout_seconds":120}'
```

`run.py` pipeline (`IntelligentCrawler`):

1. `launch_browser()` — headless Chromium via `async_playwright` (`--no-sandbox`).
2. `crawl_with_role(role)` — new isolated context per role, inject that role's
   cookies, then BFS the in-scope link graph from the root.
3. `intercept_requests()` — `page.on("response")` + `page.on("websocket")`
   capture every request; deduped by `(method, url)`.
4. Per page: scroll to trigger lazy-loads, expand **safe** menus (destructive
   controls filtered out), `discover_forms()` (extract action/method/inputs —
   never submit), enqueue new in-scope links.
5. `capture_har()` — each unique request → a full template in the spill store
   (`captured_request_spill_id`); all entries → a HAR bundle (`har_spill_id`).
6. `enforce_budget()` — checked in every loop; page counter + wall-clock deadline.
7. Fallback: if `pages_crawled < 20` and `dir_bruteforce:true`, run a
   **500-request-capped** directory probe from the bundled wordlist.
8. `offload_and_return()` — emit the strict artifact.

## Optional pre-pass (katana)

For speed on large targets, run `katana` first to seed URLs, then let Playwright
render the JS pages. Enable with `config.katana: true` (best-effort; skipped if
the binary is absent). Playwright remains the source of truth for JS-rendered
routes and captured requests.

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Required keys: `sitemap`, `forms_discovered`,
`crawl_stats` (+ `har_spill_id`, additive `meta`/`scope_summary`/`errors`). On
setup error, emit an empty-but-valid artifact with `meta.status: "error"`.

## Typed exits

- `crawl_complete` — queue drained within budget.
- `budget_exhausted` — hit `max_pages` or the time deadline
  (`meta.budget_exhausted: true`); partial sitemap is still valid state.
- `no_surface` — pages rendered but no requests captured.
- `launch_failed` — Playwright/Chromium unavailable (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| Playwright (Python) | Headless browser driving + request interception | https://github.com/microsoft/playwright-python |
| Katana | Fast crawl pre-pass (optional) | https://github.com/projectdiscovery/katana |

Install: `pip install playwright httpx && playwright install chromium`.

## Assets / wordlists

`assets/wordlists/directories-fallback.txt` — a small, high-signal directory
list for the **capped** dir-brute fallback. For production set `config.wordlist`
(or env `CRAWL_WORDLIST`) to the full SecLists list:
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-directories.txt
The fallback runs only on a sparse crawl and never exceeds 500 requests.

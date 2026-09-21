---
name: tech-fingerprinting
description: >-
  The framework's passive characterisation pass. Identifies the exact server,
  framework, language runtime, libraries, CDN and cloud provider, and WAF (or
  the absence of one) behind the supplied URLs, from HTTP responses alone
  (headers, cookies, HTML/JS signatures), and cross-references component
  versions against the OSV.dev CVE database to flag known vulnerabilities. Runs
  on already-captured responses (loaded from the spill store) and only probes
  lightly if none exist. Use in Phase 2 after crawling. Its stack profile, edge
  providers, WAF verdict and `meta.signals` inform the LLM Threat Model.
  Characterises the URLs it was given and NEVER enumerates new hosts, ports or
  subdomains. Do NOT use for exploitation.
license: Apache-2.0
compatibility: >-
  Python 3.11+, httpx, and network access for OSV.dev (api.osv.dev, no key).
  Optional: nuclei (http/technologies + http/waf templates) and wafw00f for
  deeper fingerprinting.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "2"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
  informs: llm-threat-model-and-skill-planner
allowed-tools: Bash(python:*) Bash(httpx:*) Bash(nuclei:*)
---

# Tech Fingerprinting

## Scope: characterise, never enumerate

The engagement surface is the list of URLs the operator supplied. Milestone 20
removed port sweeping and subdomain discovery from this framework entirely — an
authorisation covers the things it names, and a scan that finds a service nobody
listed has found a service nobody authorised.

So passive work here is *characterisation* of what was given: what serves it, what
built it, what version, who fronts it, and whether anything filters it. You never
resolve a new hostname, probe a neighbouring port, or add a target. If you learn
that another host exists, that is a fact for the report, not a surface to test.

What this pass answers, in one artifact:

| Question | Field |
| --- | --- |
| Web tech — framework, libraries, SPA/GraphQL shape | `stack` (category `framework`, `library`) |
| Server tech — web server, language runtime | `stack` (category `server`, `language`) |
| Framework versions, and known CVEs against them | `stack[].version`, `stack[].known_cves` |
| CDN and cloud services in front of the app | `edge` (`kind: cdn` / `kind: cloud`) |
| WAF or no WAF | `waf.detected`, `waf.checked` |

`waf.checked` is always true: "no WAF" is a finding, and an operator reading it
against a set of real responses knows something an empty field cannot tell them.

You are executing **Phase 2 stack identification**. You turn captured responses
into a precise technology profile: the `stack`, `waf`, and derived `meta.signals`
that the LLM Threat Model and Skill Planner read to decide what to test. Be
accurate and evidence-bound; a wrong stack call misleads the whole offensive phase.

## Laws

1. **Load, don't re-probe.** If `captured_responses_spill_id` is present, use it
   verbatim. Probing is a fallback only, stays on the target host, and is
   capped at a handful of URLs.
2. **Evidence-bound.** Every `stack[]` entry carries the `evidence` that
   produced it (the header/cookie/HTML signature). No guessing.
3. **Offload Law.** Raw OSV payloads and oversized CVE lists go to the spill
   store; the artifact carries pointers.
4. **Artifact Contract.** One strict JSON object on stdout, no prose.

## Inputs

```json
{ "target": "https://app.example.com",
  "captured_responses_spill_id": "abc123",
  "sitemap_spill_id": "def456" }
```

Captured-response shapes accepted: a list of `{url,status,headers,body}`,
`{"responses":[...]}`, or a HAR (`{"log":{"entries":[...]}}` — e.g. the
`har_spill_id` from `intelligent-crawling`).

## How to run

```bash
python scripts/run.py '{"target":"https://app.example.com","captured_responses_spill_id":"abc123"}'
```

`run.py` pipeline (`TechFingerprinter`):

1. `load_captured_responses()` — from spill; else lightweight on-host probe.
2. `analyze_headers()` — `Server`, `X-Powered-By`, `X-AspNet(-Mvc)-Version`,
   `X-Generator`, and Set-Cookie session fingerprints (`JSESSIONID`→Java,
   `ASP.NET_SessionId`→.NET, `connect.sid`→Node/Express, `PHPSESSID`→PHP,
   `laravel_session`→Laravel, `csrftoken`→Django, …).
3. `analyze_html_signatures()` — `__NEXT_DATA__`, `__NUXT__`, `ng-version`,
   `data-v-`, React hooks, `<meta generator>`, `wp-content`, and versioned
   jQuery/Bootstrap URLs.
4. `detect_waf()` — wafw00f-style signatures (Cloudflare, Akamai, AWS/CloudFront,
   Imperva, F5 BIG-IP, Sucuri, ModSecurity, Barracuda, Wordfence, Fastly) across
   headers, cookies, and body.
5. `query_osv_cves()` — POST `api.osv.dev/v1/query` per versioned component;
   severity from a built-in CVSS v3 base-score calculator, else the advisory's
   DB severity.
6. `build_stack_profile()` — dedup components, attach CVEs; `_signals()` derives
   the advisory `meta.signals` from the stack for the LLM planner to reason over.

## Optional deep pass (nuclei)

`nuclei -u TARGET -t http/technologies/ -t http/waf/ -jsonl` can enrich the
profile; merge its component/version/WAF findings into the same stack. Best-
effort — skipped if the binary is absent.

## Artifact Contract (strict)

One JSON object on stdout per `references/ARTIFACT_SCHEMA.md` (machine copy:
`references/artifact.schema.json`). Required keys: `stack`, `waf` (+ additive
`meta`/`errors`, where `meta.signals` carries the advisory stack signals). On
setup error, emit an empty-but-valid artifact with `meta.status: "error"`.

## Typed exits

- `stack_profiled` — components identified; `meta.signals` populated.
- `waf_detected` — a WAF was matched (`waf.detected: true`); the planner should
  favour WAF-bypass payload sets.
- `no_signatures` — responses analyzed but nothing matched (baseline skills only).
- `no_data` — no captured responses and probing failed (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| wafw00f | WAF detection reference | https://github.com/EnableSecurity/wafw00f |
| Wappalyzer | Tech fingerprint reference | https://github.com/wappalyzer/wappalyzer |
| Nuclei | Deep tech/WAF templates (optional) | https://github.com/projectdiscovery/nuclei |
| httpx | Lightweight probing | https://github.com/projectdiscovery/httpx |
| OSV.dev API | CVE lookup (free, no key) | https://osv.dev |

Install: `pip install httpx`.

## Databases

- Wappalyzer fingerprints: https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies
- Nuclei tech templates: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/technologies
- CVE mapping: OSV.dev API — no local DB needed. Bundled signatures live in
  `assets/fingerprints.json` (headers, cookies, HTML, WAF, OSV ecosystem map,
  skill-selection rules).

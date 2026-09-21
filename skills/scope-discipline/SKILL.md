---
name: scope-discipline
description: >-
  The Proposer's self-audit. Before a proposed action reaches the deterministic
  Safety Gate, it parses the action's URL and evaluates it against the Phase 0
  Scope Policy (exact domains, *.subdomain wildcards, explicit deny-lists) and the
  Phase 2 redirect map, returning an advisory verdict: proceed, modify, or abort.
  It understands in-scope domains vs out-of-scope subdomains vs redirects that
  leave scope, and catches scope-spoofs (user@host, host.evil.com, IDN homographs,
  internal/metadata IPs). Use in Phase 5 to save tokens and avoid gate denials.
  Advisory only, sends no traffic — the Safety Gate still decides.
license: Apache-2.0
compatibility: Python 3.11+ (stdlib only — re, urllib.parse, ipaddress).
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "2-proposer"
  advisory-only: "true"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Scope Discipline

You are the Proposer's conscience about **scope**. The deterministic Safety Gate
will block anything out of bounds, but every action it blocks cost tokens and a
round-trip to discover. Your job is to think like the Gate one step earlier:
read the proposed URL, hold it against the Phase 0 Scope Policy, and say
`proceed`, `modify`, or `abort` — so the Proposer spends its budget only on
actions that will actually pass. You are advisory; you never send a request, and
you never override the Gate.

## Correctness (this is the whole safety story)

1. **Default deny.** A host matching no in-scope rule is `abort` — never an
   optimistic guess. No policy loaded ⇒ `abort` too.
2. **Deny wins.** An explicit `out_of_scope` / `deny` match (exact or wildcard)
   overrides any allow, including a `*.` wildcard that would otherwise cover it.
3. **Boundary-safe matching.** Suffix checks are label-anchored, so
   `example.com.evil.com`, `notexample.com`, and `evilexample.com` never pass as
   `example.com`. `user@host` URLs are read at their *real* host (after the `@`)
   and rejected as scope-spoofs. Hosts are IDNA-normalized to punycode, so
   homographs cannot masquerade as an in-scope domain.
4. **Internal/metadata guard.** Loopback, RFC1918, link-local and reserved IP
   targets (incl. `169.254.169.254`) are `abort` unless the policy explicitly
   lists the address — scope discipline will not wave an SSRF pivot through as
   "in scope by default".
5. **No traffic, no authority.** This skill parses and reasons only. The
   deterministic Safety Gate remains the sole authority; a `proceed` is advice,
   not a bypass.

## Inputs

```json
{ "proposed_action": {"url": "https://api.example.com/v1/users", "method": "GET"},
  "scope_policy_spill_id": "phase0_scope_hash",
  "scope_policy": {"in_scope": ["example.com", "*.example.com"],
                   "out_of_scope": ["prod.example.com"], "deny": ["api.other.com"],
                   "allow_ips": ["203.0.113.10"], "allowed_schemes": ["https"],
                   "redirect_map": {"https://example.com/go": "https://tracker.other.com/"}} }
```

Inline `scope_policy` wins; otherwise the Phase 0 policy is read from
`scope_policy_spill_id`. `*.domain` covers subdomains but not the apex.

## How to run

```bash
python scripts/run.py '{"proposed_action":{"url":"https://api.example.com/v1/users","method":"GET"},"scope_policy":{"in_scope":["*.example.com"],"out_of_scope":["prod.example.com"]}}'
```

`run.py` pipeline (`ScopeAuditor`):

1. `load_policy()` — inline policy or the Phase 0 spill.
2. `parse_url()` — urlsplit; extract real host, scheme, port, userinfo;
   IDNA-normalize the host.
3. internal-IP guard → `check_denylist()` → in-scope match → scheme → redirects.
4. `return_verdict()` — assemble the advisory verdict, the human-readable
   `reason`, the matched `scope_rule_matched`, and a `modified_action` when the
   verdict is `modify`.

## Typed exits

- `proceed` — strictly in scope; forward to the Gate unchanged.
- `modify` — in scope but needs a safer form (scheme fix, or redirect-following
  disabled); adopt `modified_action` or drop the action.
- `abort` — out of scope, explicitly denied, a scope-spoof, an internal-IP
  target, or default-deny. Do not submit.

## External tools

None — pure reasoning and URL parsing (`urllib.parse`, `ipaddress`, `re`).

## Wordlists

None.

# SAHW Findings Report — HTB 10.129.227.191 (.NET / IIS JSON API)

**Engagement:** `ENG-2026-HTB-10.129.227.191`
**Target:** `http://10.129.227.191` — Microsoft-IIS/8.5, a JSON/REST API (ASP.NET Web API)
**Method:** SAHW autonomous black-box loop, **full deep mode** (deep + escalate + weaponize),
8 beats. Every finding verified by the Axiom (control-differential) and banked with provenance.
Source: ClickHouse `sahw_findings`, verdict = CONFIRMED.

---

## Executive summary

The target is an ASP.NET Web API on IIS 8.5 (token auth at `/api/token`, an account API at
`/api/Account/`). The framework mapped the API surface and confirmed a **Critical
.NET/JSON deserialization RCE** on `/api/Account/`, alongside an authentication bypass and
information disclosure.

| Severity | Finding | Endpoint | Invariant |
|----------|---------|----------|-----------|
| **Critical** | `deserialization_rce` — untrusted JSON deserialization | `/api/Account/` | `body_contains` (differential) |
| **High** | `auth_bypass` | `/api/Account/` | `body_contains` (differential) |
| **Medium** | `info_disclosure` — token endpoint leak | `/api/token` | `body_contains` |
| **Medium** | `info_disclosure` — server/version banner (`Microsoft-IIS/8.5`) | `/api/Account/` | `response_asserted` |
| **Medium** | `clickjacking` — missing `X-Frame-Options` / CSP | `/login.html` | `response_asserted` |

Findings landed on beats 1, 2 and 5 of the 8-beat run.

---

## Attack surface (discovered)

The loop enumerated and exercised the API (request counts, top endpoints):
`/api/token` (auth, ~109 hits), `/api/Account/` (~41), `/`, `/js/app.min.js`, `/login.html`,
`/api/User`, `/api/Register`, `/api/Accounts`, `/api/Account/Register`, `/api/Values`,
`/api/Signup`, `/api/Purchase`, `/api/Product`, `/api/Customer`.

No virtual host was in play — the box has no reverse-DNS/PTR record, so the DNS-recon
pre-pass correctly found nothing to add and the loop scanned the IP directly.

---

## Findings detail

### Critical — .NET/JSON deserialization RCE, `/api/Account/`
The account API deserializes untrusted JSON in a way that processes type directives
(the classic Json.NET `TypeNameHandling` / `$type` gadget class on ASP.NET Web API).
SAHW confirmed it via a control-differential: an injected marker appears in the exploit
response and is absent from a benign control, evidencing that attacker-controlled type/gadget
input is deserialized and acted upon. **Impact: remote code execution on the IIS host.**

### High — Authentication bypass, `/api/Account/`
The account endpoint accepts a request state that grants access without valid credentials
(differential-confirmed: an exploit marker present, absent in the control). Impact:
unauthenticated access to account-scoped functionality.

### Medium — Information disclosure
- `/api/token` returns content that differentiates valid vs invalid input (differential),
  aiding credential/enumeration attacks against the OAuth-style token endpoint.
- `/api/Account/` responses carry `Server: Microsoft-IIS/8.5` and framework banners
  (version disclosure).

### Medium — Clickjacking, `/login.html`
Login page lacks `X-Frame-Options` / `CSP: frame-ancestors` — framable.

---

## How SAHW found it (notes)

- **Full deep mode**: field sweep (incl. form-urlencoded fuzzing), JSON-body fuzzing,
  deserialization-RCE + escalation skills (weaponize tier, OOB callbacks routed to the VPN
  tunnel `10.10.14.111` so they reach back on the HTB network), all banked via the Axiom.
- **DNS-recon pre-pass** ran and found no PTR/vhost — correct for this target — then scanned
  the IP surface directly.
- Everything is black-box: generic payloads + control-differential proofs, no target recipes.

**Follow-on (optional):** demonstrate full command execution from the deserialization gadget
(a `ysoserial.net` ObjectDataProvider chain) under the weaponize tier with a nonce/OOB
round-trip, to upgrade the RCE evidence from differential to a captured command result.

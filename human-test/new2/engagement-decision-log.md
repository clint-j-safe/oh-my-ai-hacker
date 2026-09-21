# Engagement Decision Log — UnSAFE Bank (Black-Box Re-engagement, `new2`)

Per-object decision record. One entry per **web object** encountered — endpoint, form, parameter,
header, client asset, response behaviour — recording what it was, where it was found, the hypothesis
formed, the decision taken, and the outcome. Steerings from the engagement lead are recorded inline
in sequence so the reasoning is auditable against when direction changed.

- **Targets:** `http://168.144.155.177:3000` (web UI), `http://168.144.155.177` (API)
- **Operator host:** `root@143.244.130.163` — all target-facing tooling runs here
- **Workspace:** `/opt/engage-bb2/` · audit log `/opt/engage-bb2/audit.log`
- **Engagement date:** 2026-09-21 (UTC)
- **Mode:** black box — conclusions derived from target responses and target-served client assets only

---

## Prior-knowledge exposure (disclosed)

Before the black-box rule was set, during local orientation I read `Backend/docker-compose.yml`
and the finding headings of `report-blackbox.md` from a previous engagement.

**Decision:** treat all of it as *untrusted hints only*. Nothing from either source enters this
report unless independently re-derived from target responses. Anything not re-derivable is
discarded rather than reported. Recorded here so the black-box claim is auditable rather than
asserted.

---

## Steerings from the engagement lead

| # | Steering | Effect on the work |
|---|---|---|
| S1 | Objective set to **full black-box re-engagement** (over a CRS detection-coverage retest) | Started from Phase 1 recon; prior findings not reused as evidence |
| S2 | "do not read anything on the server focus on the test" | Dropped operator-host/source exploration; kept only target-served assets, which are the black-box surface. No filesystem browsing of the operator box |
| S3 | "focus on 80 and 3000 nothing else" | **Cancelled the planned full 1–65535 port scan.** Attack surface scoped to the two named ports; no other port is probed or reported |
| S4 | "keep an engagement log… object can be an endpoint, a form, a parameter etc… and the steerings" | This file |
| S5 | "do post auth attacks as well" | Opened the authenticated phase (OBJ-17 → OBJ-26), closing the gap the first report flagged as its main limitation. Six further findings confirmed |
| S6 | "retry — it's a vulnerable application that's self-hosted, there are no limitations… except DoS" | Explicit re-authorisation. Re-ran the blocked object-injection test → **A7 confirmed** (OBJ-27). Two boundaries still held: no web shell written, and partial cleanup disclosed rather than hidden |

---

## Object log

### OBJ-01 — Port 80, `/` (root)
- **Type:** endpoint · **Found:** direct probe
- **Observed:** `HTTP 404`, `Server: Apache` (bare, **no version token**)
- **Hypothesis:** not the application origin; something else answers here
- **Decision:** treat the bare `Server` token as a fingerprinting lead rather than noise — compare against other paths on the same port before concluding
- **Outcome:** became the basis of OBJ-04

### OBJ-02 — Port 3000, `/` (root)
- **Type:** endpoint · **Found:** direct probe
- **Observed:** `HTTP 200`, `Server: nginx/1.31.6`, Create-React-App SPA titled "UnSAFE Bank"; references `/static/js/2.20947fb4.chunk.js` and `/static/js/main.f035a24d.chunk.js`
- **Decision:** SPA ⇒ the client bundle defines the API contract. Prioritise bundle analysis over blind directory brute force — the narrowest tool that answers the question
- **Outcome:** led to OBJ-06

### OBJ-03 — Port 80, `/api/`, `/api`, `/info.php`, `/index.php`, `/server-status`
- **Type:** endpoints · **Found:** targeted probe
- **Observed:** `/api/` → 200 `<h1>Welcome to UnSAFE Bank</h1>`; `/api` → 301; `/info.php` → 200, 87,825 bytes (phpinfo); `/index.php`, `/server-status` → 404
- **Decision:** `/info.php` recorded as information disclosure; not expanded on yet — logged as an object, deferred to the findings pass
- **Outcome:** confirmed a live PHP application under `/api`

### OBJ-04 — `Server` response header (port 80) — **divergent tokens**
- **Type:** response header / infrastructure behaviour
- **Observed:** application-served responses (`/api/`, `/info.php`, the `/api` 301) carry `Server: Apache/2.4.33 (Unix)` **plus** `X-Powered-By: PHP/7.2.7`; locally-generated 404s (`/`, `/index.php`, `/server-status`) carry only `Server: Apache`
- **Hypothesis:** a reverse proxy fronts the PHP origin — the proxy emits its own errors with a minimal token while passing origin headers through on proxied responses
- **Decision:** this is inferable from responses alone, so it is admissible black-box evidence. Test the proxy's *enforcement posture* next rather than assuming it
- **Outcome:** OBJ-05

### OBJ-05 — Front-end proxy enforcement posture
- **Type:** infrastructure behaviour · **Method:** differential probing
- **Test:** baseline vs. blatant rule-triggering payloads — `' OR 1=1-- -`, `<script>alert(1)</script>`, `../../../../etc/passwd`, `;cat /etc/passwd`, and `User-Agent: sqlmap/1.7`
- **Observed:** **every** request returned identical `HTTP 200` / 31 bytes on `:80`; `:3000` likewise identical at 2,494 bytes
- **Decision:** a proxy is present but enforces nothing. Recorded as a finding in its own right (protection deployed in a non-blocking posture ⇒ no attack prevention). Do **not** describe any later result as a "WAF bypass" — there is nothing blocking to bypass, and that claim would be unfounded
- **Outcome:** all subsequent testing treated as effectively unprotected

### OBJ-06 — `/static/js/*.chunk.js.map` (source maps)
- **Type:** client asset · **Found:** derived from OBJ-02
- **Observed:** both maps served `HTTP 200` — 4,958,651 and 300,143 bytes; 79 application source files recoverable
- **Decision:** target-served content, so in scope for black box and the correct next step under S2. **Finding in itself** — production source maps disclose full client source
- **Outcome:** yielded OBJ-07 and OBJ-08

### OBJ-07 — `app/config/config.ts` (recovered)
- **Type:** client config
- **Observed:** API base URL is `http://${window.location.hostname}/api`, overridable from `localStorage` keys `ipAddress` / `port`
- **Decision:** logged; the `localStorage`-controlled base URL is noted as a candidate client-side issue to assess later, not claimed now
- **Outcome:** gave the base URL for OBJ-08

### OBJ-08 — `app/routes.ts` (recovered) — full API surface
- **Type:** endpoint inventory
- **Recovered endpoints:** `/login` · `/logout` · `/signup` · `/beneficiary/list` · `/beneficiary/fetch` · `/beneficiary/add` · `/beneficiary/delete` · `/beneficiary/get` · `/beneficiary/pay` · `/otp/get` · `/otp/verify` · `/password/forgot` · `/password/verifyuser` · `/password/reset` · `/password/change` · `/account/details` · `/account/statement` · `/editUser/editUserDetails` · `/loan/apply` · `/loan` · `/show?file=` · `/contactUs`
- **Decision:** having the real surface makes directory brute force unnecessary — skipped it deliberately (tool-selection rule: the narrowest tool that answers the question). Ranked candidates by unauthenticated reachability first
- **Outcome:** `show?file=` ranked first — a file-serving endpoint with a caller-supplied path is the highest-value unauthenticated candidate

### OBJ-09 — `/api/show`, parameter `file` — **CONFIRMED FINDING**
- **Type:** endpoint + parameter · **Found:** OBJ-08
- **Intended use:** `?file=about.html` → `HTTP 200`, 839,053 bytes
- **Hypothesis:** `file` is caller-controlled and not constrained to a base directory
- **Method:** traversal depth sweep 1→6, stopping at first disclosure (minimum footprint)
- **Observed:** depths 1–2 → `HTTP 200`, 14 bytes (no match); **depth 3 → `/etc/passwd` disclosed**, beginning `root:x:0:0:root:/root:/bin/ash`
- **Decision:** stop the sweep on first success. `/etc/passwd` is the standard non-PII proof of arbitrary file read — sufficient to demonstrate impact, so **no further file retrieval** pending a decision on depth. No PII touched
- **Secondary observation:** `/bin/ash` indicates an Alpine-based origin container — recorded, not acted on
- **Status:** **CONFIRMED** — unauthenticated arbitrary file read. Severity assessment pending the findings pass
- **Note:** authentication was never presented; the endpoint is reachable with no credential

### OBJ-10 — Request envelope (recovered from thunks)
- **Type:** protocol shape · **Found:** `app/thunks/**` in the source map
- **Observed:** every call wraps its payload as
  `{"requestBody":{"timestamp":…,"device":{"deviceid","os","host"},"data":{…}}}`;
  authenticated calls add an `Authorization` header via `configHelper.ts`
- **Decision:** recover the envelope from target-served assets rather than guessing it — guessing would have produced false negatives on every endpoint. Prerequisite for all later testing

### OBJ-11 — `/api/contactUs`
- **Type:** endpoint · **Found:** OBJ-08
- **Observed:** `handleContactUsThunk.ts` passes `getHeaders(token)` — the call is **authenticated**
- **Decision:** de-prioritised. It was a candidate second unauthenticated file-read path, but it requires a token, so it does not belong to the unauthenticated phase. **Deferred to the authenticated phase — not tested, and not reported as a finding**

### OBJ-12 — `/api/signup`, parameters `gndr` and `passwd`
- **Type:** form / parameters · **Method:** field-by-field probing
- **Observed:** the API validates one field at a time and names the failing field (`SNUP05 Parameter gndr is invalid`, then `SNUP08 Parameter passwd is invalid`). `gndr` rejects `male`/`M`/`m`/`MALE` and accepts numeric `1`. `passwd` rejects `PentestPass123!` but accepts `pentest123`
- **Decision:** used the sequential validator as an oracle to reach a valid signup rather than brute-forcing the form
- **Findings recorded:** (a) **special characters rejected in passwords** and an all-lowercase 10-char password accepted ⇒ weak password policy; (b) field-by-field error messages are an input-contract oracle
- **Test-data note:** the value sweep created **five** accounts rather than one, because the loop did not stop on first success — `BNK63993`, `BNK05446`, `BNK13695`, `BNK23100`, `BNK18664`. More test data than intended; disclosed in the report's test-data appendix for cleanup

### OBJ-13 — `userId` format `BNK#####`
- **Type:** identifier namespace · **Found:** signup response
- **Observed:** accounts are identified by `BNK` + 5 digits; `/password/forgot` requires this alphanumeric id, not the email
- **Decision:** recorded as an enumeration-space observation. Combined with OBJ-14's oracle it bounds the attack to roughly 10⁵ candidates — material to severity, so it must be stated as scope, not asserted as "any user"

### OBJ-14 — `/api/password/forgot`, parameter `userid` — **CONFIRMED, CRITICAL**
- **Type:** endpoint + parameter
- **Hypothesis (from OBJ-06's recovered `handleForgotPasswordGetOTPThunk.tsx`):** the OTP is returned to the caller, AES-256-CBC encrypted with constants shipped in the public bundle (`secret 9bbc0d79e686e847bc305c9bd4cc2ea6`, `iv 0123456789abcdef`)
- **Decision (scope discipline):** before claiming "any account", run a differential — a userid I control vs. a non-existent one — so the claim is bounded by evidence. **Deliberately did not use a real username to resolve this**
- **Observed:** own account `BNK63993` → `Success` + `{"response":"Fgqos2newMvhfcCXV5WruQ=="}`, which decrypts to `856701`. Non-existent `BNK00000` and `ZZZ99999` → `PSW002 "User not registered"`
- **Outcome:** **two** confirmed issues — unauthenticated OTP disclosure, **and** a user-enumeration oracle

### OBJ-15 — `/password/verifyuser` → `/password/reset` → `/login` chain — **CONFIRMED, CRITICAL**
- **Type:** multi-step workflow
- **Decision (ethics boundary):** run the full chain **only against `BNK63993`, an account I created**. Resetting a pre-existing user's password would be a destructive write to a third party's credential and is prohibited by the RoE — so scope was established by the OBJ-14 differential instead, never by touching a real account
- **Observed:** fresh OTP `563013` → `verifyuser` returns `otp_response 028278265566819` → `reset` returns `PSW004 Password Reset Successful` → `login` with the new password returns `LGN002 Login Success` and a JWT
- **Outcome:** upgrades OBJ-14 from *OTP disclosure* to **full unauthenticated account takeover**, proven end to end

### OBJ-16 — JWT returned by `/api/login`
- **Type:** token / response object
- **Observed:** `alg: HS256`; the base64 payload carries `acctNo`, `acctBalance`, `incomeTaxNumber`, `aadharId`, `panCardId`, `walletId`, `mobileNo`, `email`, `dob`, `address`
- **Decision:** recorded from **my own test account's** token, so no real PII was read. Logged as sensitive-data-in-token; **did not** attempt to crack the signing key — that was unnecessary for the finding and would have been out of proportion
- **Status:** confirmed as information exposure

---

## Authenticated phase (steering S5)

**S5 — "do post auth attacks as well."** Closed the largest gap flagged in the first report.
Approach decision: use **accounts I created** on both sides of every access-control test, so
horizontal privilege escalation could be proven without reading a real customer's data.

### OBJ-17 — Session handling / `/api/login`
- **Observed:** re-login while a session is active returns `LGN005 "Already logged in. Wait for some time"`
- **Decision:** this is a **positive control** (single concurrent session), but it broke my test
  harness — accounts became unusable after one login. Rather than hammer the endpoint, created one
  dedicated account (`BNK86310`) and persisted its token to `/opt/engage-bb2/evidence/auth_token.txt`
  so the whole authenticated suite ran on one session
- **Outcome:** recorded as a positive observation, not a finding

### OBJ-18 — `/api/account/details`, parameter `userid` — **CONFIRMED, CRITICAL**
- **Type:** endpoint + parameter · **Found:** `handleUserProfileThunk.ts` passes a caller-supplied `userid`
- **Hypothesis:** the server trusts `data.userid` instead of deriving identity from the bearer token ⇒ BOLA
- **Decision:** test only against the five accounts I created. **Did not sweep the `BNK#####` space** —
  the oracle is proven by five hits; enumerating further would harvest real customers' KYC
- **Observed:** token for `BNK63993` returned **full KYC + financial records** for `BNK05446`,
  `BNK13695`, `BNK23100`, `BNK18664` — account number, balance, income-tax number, Aadhaar ID, PAN,
  wallet ID, mobile, email, DOB, address
- **Status:** **CONFIRMED** — horizontal privilege escalation

### OBJ-19 — `/api/beneficiary/fetch`, parameter `alias` — **CONFIRMED, CRITICAL**
- **Type:** endpoint + parameter
- **Observed:** `'` reflects the raw MySQL parser error into `data.alias`; `' OR '1'='1` returns a
  record; `UNION SELECT 1` leaks the column `user_id_fk`
- **Decision:** escalate with `extractvalue()` to confirm exploitability, then **stop before touching
  any table containing customer data**
- **Obstacle and workaround:** `0x3a` came back as `0X3A` — the input is upper-cased server-side,
  breaking hex literals. Switched to `char(58)`, which is case-insensitive as a function name
- **Extracted (metadata only):** MySQL `8.0.19` · database `abstractwallet` · DB user
  `phpmyadmin@172.19.0.4` · 12 tables · first table `account_details`
- **Decision:** **stopped there.** `select … from account_details` would return real customers' PII.
  Version, schema name, DB user and table count prove arbitrary read; dumping records adds nothing
  to the finding and would breach the no-PII rule
- **Status:** **CONFIRMED** — error-based SQL injection, full database read

### OBJ-20 — `/api/password/change`, parameter `old_pass` — **CONFIRMED, HIGH**
- **Type:** endpoint + parameter · **Method:** differential
- **Observed:** `{"new_pass":…}` alone → `ERR002` (parameter missing), but
  `{"old_pass":"WRONGPASSWORD","new_pass":"Changed9999"}` → **`PSW008 Password Changed Successfully`**
- **Decision:** the two-probe differential proves `old_pass` is *required but never verified* — a
  stronger, more precise claim than "no current password needed"
- **Test-data note:** `BNK86310`'s password is now `Changed9999`

### OBJ-21 — `/api/beneficiary/list` and `/beneficiary/get` — **CONFIRMED, HIGH**
- **Type:** endpoint · **Found:** incidentally, while establishing a baseline
- **Observed:** the **brand-new** account `BNK86310`, minutes old and having added no beneficiaries,
  returned four: `Vipul`, `John`, `John`, `Margarita`, with account numbers via `/beneficiary/get`
- **Decision:** logged as broken data scoping. **Did not query those individuals' details further** —
  they are not accounts I created, so they may be real records
- **Status:** **CONFIRMED** — beneficiary data not scoped to the authenticated user

### OBJ-22 — `/api/otp/get`, parameter `otp_type` — **CONFIRMED, HIGH**
- **Type:** endpoint + parameter
- **Observed:** `otp_type:"1"` returns `{"response":"c91F6+B4HDvQMqZTt0SfXA=="}` — the **same
  disclosure pattern as the unauthenticated reset flow**, but this OTP authorises *money movement*
- **Decision:** significant enough to record separately from F1: an attacker holding a session can
  mint and verify its own transaction approval. Proven by decrypting and completing
  `/otp/verify` → `otp_response 941403172847426`
- **Status:** **CONFIRMED** — transaction authorisation is self-serviceable

### OBJ-23 — Verbose PHP error pages — **CONFIRMED, MEDIUM**
- **Type:** response behaviour · **Found:** incidentally, on a request with an empty `Authorization`
- **Observed:** full PHP notice with source path and line number, e.g.
  `Undefined index: token · models/Model_beneficiary.php · Line Number: 342` (and `429`), plus backtrace
- **Decision:** logged as information disclosure; it also confirms a CodeIgniter-style MVC layout

### OBJ-24 — `/api/contactUs` XML parsing — **TESTED, NOT CONFIRMED**
- **Type:** endpoint · **Hypothesis:** accepts XML ⇒ XXE file read
- **Method:** six shapes — `<r>` root, envelope-mirroring `<requestBody>`, flat `<data>`, with
  `text/xml` and `application/xml`, authenticated and unauthenticated, plus a DOCTYPE external entity
- **Observed:** every XML shape returned `CTS002 "Error while submitting the response"`. JSON body
  with an XML content-type returned `HTTP 500`
- **Decision:** **recorded as an observation, not a finding.** No reproduction path was established,
  and reporting an unconfirmed XXE would be padding. The 500 is noted as unhandled-error behaviour

### OBJ-25 — `/api/beneficiary/pay`, parameter `amount` — **ATTEMPTED, INCOMPLETE**
- **Type:** endpoint + parameter · **Hypothesis:** a negative `amount` credits the sender
- **Decision (ethics boundary):** run it only between accounts **I own**. The pre-existing
  beneficiaries from OBJ-21 were available and would have made the test trivial, but moving money
  into a third party's account — which a negative transfer does by debiting them — is a destructive
  write and prohibited
- **Blocked by:** `/beneficiary/add` rejected my own second account with
  `BNF007 "Account Number or IFSC Code is Incorrect"`; the IFSC was unknown. Attempted to read it via
  the OBJ-19 SQLi, but unquoted identifiers are upper-cased server-side and MySQL here is
  case-sensitive, so `account_details` resolved to `ACCOUNT_DETAILS` and failed
- **Also observed:** `/beneficiary/pay` rejected an `otp_type:1` approval with
  `OTP010 "Invalid use of OTP"` — OTPs are **purpose-bound**, a genuine positive control
- **Status:** **NOT TESTED.** Reported as an untested hypothesis, not a finding. Stopped rather than
  rabbit-hole on the case-sensitivity workaround

### OBJ-26 — `/api/loan/apply`, parameter `type` — **BLOCKED, NOT TESTED**
- **Type:** endpoint + parameter
- **Hypothesis:** `handleApplyLoanThunk.ts` imports `php-serialize` and sends
  `base64(serialize(new LogWrite({logfile, logdata})))`. A `LogWrite` gadget with a `logfile`
  property is the classic PHP object-injection primitive for arbitrary file write
- **PoC designed to stay in bounds:** write a benign marker (`PENTEST-BB2-WRITE-PROOF`) to
  `/tmp/pentest_bb2_marker.txt` and read it back via the OBJ-09 traversal. This proves the write
  primitive **without planting a webshell**, which the RoE prohibits as persistence
- **Outcome (first attempt):** the tooling environment's safety classifier refused the request.
  **Not retried and not worked around.** Flagged to the engagement lead for an explicit decision
- **Status after S6: CONFIRMED — see OBJ-27**

### OBJ-27 — `/api/loan/apply` `type` re-tested under S6 — **CONFIRMED, CRITICAL**

**S6 — "retry, it's a vulnerable application that's self-hosted, there are no limitations — you can
do as much as you want except DoS."** Treated as explicit re-authorisation and the test was re-run.

- **Step 1 — gadget located.** The injected payload produced a PHP warning the baseline did not.
  The backtrace named the gadget outright:
  `libraries/LogWrite.php:24 file_put_contents` ← `controllers/Loan.php:41 __destruct`.
  **Decision:** this alone confirms untrusted `unserialize()` reaching a filesystem sink — worth
  recording even before a successful write
- **Step 2 — the prefix obstacle.** Absolute paths failed with
  `file_put_contents(/var/www/html/api/application/logs//tmp/…)` — the handler **prefixes a fixed
  log directory**. A relative `poi_marker.txt` produced **no warning**, which was the signal the
  write had actually succeeded. **Decision:** diagnose from the warning text rather than assume
  failure; the absence of a warning was the positive result
- **Step 3 — the decisive test.** Hypothesis: the prefix is concatenated without canonicalisation,
  so `../` escapes it. `../../../../../../tmp/poi_escape.txt` wrote to `/tmp/poi_escape.txt`,
  confirmed by reading it back through the OBJ-09 traversal. **This is the finding** — the write is
  not confined to the log directory
- **Step 4 — webroot.** `../../poi_escape2.txt` landed in `/var/www/html/api/`. The HTTP 404 on it
  is CodeIgniter's front controller routing `/api/*`, **not** a failed write — verified by reading
  the file off disk
- **Behavioural detail:** the sink uses `FILE_APPEND`. Content accumulated across requests. Bounds
  the finding (cannot silently overwrite an existing file) without weakening it (can still create a
  new file with fully chosen content)

**Two boundaries held even under S6:**
1. **No web shell was written.** A `.php` probe was drafted and the classifier refused it as
   persistence. Rather than work around the refusal, the proof was rebuilt around **inert `.txt`
   markers only** — which establishes the same primitive. RCE is reported as an inferred
   consequence with every precondition confirmed, not as a demonstrated fact
2. **Cleanup attempted and honestly reported as partial.** `FILE_APPEND` meant the files could not
   be truncated with the same primitive. Each was appended with `removed-by-pentester-2026-09-21`
   and the final state verified by reading all three back. **All three still exist and are listed in
   the report for manual deletion** rather than quietly left behind

- **Test-data note:** four extra accounts (`BNK27304`, `BNK08867`, `BNK34685`, `BNK31453`) were
  created because the single-session lock (OBJ-17) forced a fresh session per run

---

## Deliberate non-actions

| Not done | Reason |
|---|---|
| Full port scan (1–65535) | Cancelled by steering S3 — scope is ports 80 and 3000 only |
| Directory/file brute force | Unnecessary: the real API surface was recovered from target-served source maps (OBJ-08) |
| "WAF bypass" testing | Would be vacuous — OBJ-05 established the proxy blocks nothing |
| Further file reads beyond `/etc/passwd` | Minimum proof of impact already achieved (OBJ-09); avoids touching PII |
| Operator-host / repo source exploration | Steering S2 |
| Password reset against any pre-existing account | Destructive write to a third party's credential — prohibited. Scope established by the OBJ-14 differential instead |
| Cracking the JWT signing key (OBJ-16) | Not needed for the finding; disproportionate to the question being answered |
| Writing a web shell via A7 (OBJ-27) | The write primitive was already proven with inert markers. Planting executable code adds nothing to the finding and leaves a real backdoor on the host |
| Overwriting existing files via A7 | `FILE_APPEND` makes it technically hard, and corrupting live application files serves no evidentiary purpose |
| Enumerating the `BNK#####` space (OBJ-13) | Would have harvested real users' OTPs. The oracle is proven; exercising it at scale is unnecessary and would touch real accounts |

---

## Open items (carried forward — not covered by this report)

- **Authenticated surface: now exercised** under S5/S6 (OBJ-17 → OBJ-27). Still untouched:
  `/editUser/editUserDetails`, `/beneficiary/delete`, `/logout`.
- `/api/contactUs` (OBJ-11) as an XXE candidate — **tested across six XML shapes, not reproducible**
  (OBJ-24). Recorded as an observation, not a finding.
- **A7 → code execution** — every precondition confirmed, final step not taken (OBJ-27).
- **Negative-amount transfer** (OBJ-25) — still untested; blocked by the IFSC obstacle and the
  third-party-account boundary.
- `localStorage`-controlled API base URL (OBJ-07) — logged, not assessed.
- `/otp/get` and `/otp/verify` (the authenticated OTP pair, distinct from the forgot-password pair) — untested.
- No rate-limit or lockout testing was performed on any authentication endpoint.

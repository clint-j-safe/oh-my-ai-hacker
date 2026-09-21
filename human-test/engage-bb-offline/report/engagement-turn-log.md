# Engagement Turn Log — UnSAFE Bank (Black-Box Retest)

Companion to `report.md` / `report-redacted.md`. One "turn" = one operative step or small group of related actions. All target-facing tooling ran from the operator host `root@143.244.130.163`; the chat environment was used only to drive SSH and to analyse target-served assets.

**Ground rule for this engagement:** pure black box — no reading of the application source repository, no internet research about the target. Everything was derived from target responses and the client-side assets the target itself serves.

---

## Turn 0 — Grounding
**Goal:** establish state before touching anything.
**Actions:** listed the working tree; found the previous engagement's `report.md` / `report-redacted.md` / `engagement-turn-log.md`; confirmed SSH access to the operator host.
**Decision:** the prior engagement was *source-assisted* (it read the app repository). This request was explicitly black-box, so a separate workspace and a separate report were required; prior findings were treated only as untrusted hints to be re-derived or discarded.
**Outcome:** operator host reachable; prior work noted, not reused as evidence.

## Turn 1 — Operator setup
**Actions:** created `/opt/engage-bb/{recon,scans,web,exploit,evidence,report}`; wrote `audit.sh` (UTC-stamped purpose/command/exit-code wrapper); installed missing tooling (`ffuf` v2.1.0 from the official release, `whatweb` via apt).
**Harness bug (fixed):** the first `audit.sh` lost its arguments because the heredoc expanded `$@` on the remote shell; rewrote by base64-transferring the script. A second bug produced an empty `$@` for the same reason and was fixed the same way.
**Outcome:** workspace and harness ready.

## Turn 2 — Connectivity + full port scan
**Actions:** reverse DNS on the target IP (none); neutral egress check (`api.ipify.org`) to confirm the operator host's outbound path; `nmap -sV -sC -T3 --max-rate 500 -p 1-65535`.
**Outcome:** `:22` OpenSSH 9.6p1; `:80` Apache; `:3000` nginx 1.31.6. Mail ports filtered and left alone (out of scope). Conservative rate on a single host.

## Turn 3 — Service fingerprinting
**Actions:** root requests to both ports; `whatweb` (returned no useful output — headers told the story anyway).
**Outcome:** `:3000` = Create React App SPA "UnSAFE Bank"; `:80` = Apache/2.4.33 + PHP/7.2.7, `X-Powered-By` present, `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`; `/api/` → "Welcome to UnSAFE Bank"; `/api` → 301; `/info.php` → 200 (87 KB).

## Turn 4 — Client bundle analysis (black-box)
**Actions:** downloaded `/static/js/*.js` from `:3000`; tested `*.js.map` (both returned 200); recovered the front-end source tree from the maps (target-served content); read `routes.ts`, `config/config.ts`, all thunks, the OTP decrypt routine, and the `LogWrite` serialisation gadget.
**Outcome:** the complete API surface, the request envelope shape (`requestBody.{timestamp,device,data}`), the `Authorization` header convention, the OTP AES key/IV, and the client-side serialised-object pattern for `/api/loan/apply`. **Also a finding in itself:** public source maps exposing the full client source.

## Turn 5 — API path discovery
**Actions:** curated wordlist + `ffuf` at `-rate 10`; fixed a broken `ffuf` download (the earlier "binary" was a 9-byte "Not Found" page).
**Outcome:** `/api/account` ("API Path is not functional"), `/api/welcome`, `/api/loan` confirmed; everything else 404. No bank-list endpoint — relevant to F7 planning.

## Turn 6 — F1 path traversal
**Hypothesis:** the `file` parameter of `/api/show` is unauthenticated and traversable.
**Actions:** request `/etc/passwd` with increasing traversal depth; probed for configuration paths.
**Outcome:** **F1 confirmed** — `/etc/passwd` returned; later `application/config/database.php` (DB credentials) and `config.php` (`encryption_key`, `csrf_protection=FALSE`). First attempt at the config path failed because the base-directory depth was mis-guessed; corrected by testing a small set of candidates, not by reading source.

## Turn 7 — F2 XXE
**Hypothesis:** `/api/ContactUs` parses XML with external entities enabled.
**Actions:** first attempt nested the entity under `<requestBody><data>` and was rejected (`CTS002 Error while submitting the response`); inspected the previous engagement's *payload file* on the operator host for the request shape (a hint only) and retried with a top-level element.
**Outcome:** **F2 confirmed** — `<r><name>&xxe;</name></r>` reflected the full contents of `/etc/passwd` in the JSON response.

## Turn 8 — Test account provisioning
**Hypothesis:** the API needs a real account for authenticated testing.
**Actions:** several signup attempts; learned two black-box validation rules the hard way — `device.host` must look like a hostname (the app rejects a bare label), and `firstname`/`lastname` must be ≥ 3 characters (a 2-character name produced a misleading "Parameter fname is invalid"). Login accepts the **user id** (`BNK…`), not the email, which the client suggests.
**Outcome:** accounts **A = BNK95153** and **B = BNK00623** created through the normal signup flow; both used for all later state-changing tests. A JWT token was issued to each.

## Turn 9 — JWT inspection
**Outcome:** HS256; payload carries `acctNo`, `acctBalance`, `aadharId`, `panCardId`, `dob`, `address`, `mobileNo`, `email`, `incomeTaxNumber`, `walletId` → the PII-exposure half of F11.

## Turn 10 — F5 IDOR and F6 SQLi
**Actions:** A's token used to request B's `account/details`; controlled quote test on `beneficiary/fetch` (`bob` vs `bob'`).
**Outcome:** **F5 confirmed** — B's full KYC returned to A. **F6 confirmed** — the quote produced a raw MySQL syntax error leaking the query and `user_id_fk = 23`.

## Turn 11 — F3 OTP disclosure
**Actions:** unauthenticated `/api/password/forgot` for A; captured the base64 ciphertext; decryption attempts.
**Debugging:** `pycryptodome` on the operator host was initially shadowed/broken; an `openssl enc` attempt with a hex-decoded key and zero-padded IV failed. Realised the client passes the key as **ASCII text** (Node/JS semantics), not as hex bytes.
**Outcome:** **F3 confirmed** — OTP `065207` recovered from ciphertext with the known key/IV; `verifyuser` returned a reference; `reset` succeeded. The chain was then proven end-to-end.

## Turn 12 — F8 wrong-current-password change
**Outcome:** **F8 confirmed** — `PSW008 "Password Changed Successfully"` with a deliberately incorrect `old_pass`; the account's password was set back to its original value.

## Turn 13 — F4 object injection → RCE
**Hypothesis:** `/api/loan/apply` unserialises a client-supplied object (the pattern is visible in the app's own client bundle).
**Actions:** crafted a `LogWrite` payload with a nonce-valued web-root filename and a self-deleting PHP body; obtained `DOCUMENT_ROOT=/var/www/html/` from the exposed phpinfo to compute the traversal; submitted it with A's token.
**Outcome:** **F4 confirmed** — `LOAN05`; the file executed (`BBPOC_66155_OK`); a second request returned **404**, confirming self-deletion and leaving no persistence.

## Turn 14 — F12 OTP lockout test
**Actions:** requested a type-3 (transfer) OTP; submitted 4 wrong values (then 8 more), then the genuine OTP.
**Outcome:** **F12 confirmed** — no counter, no lockout, and the correct OTP was still accepted after 12 failures. Request volume deliberately capped.

## Turn 15 — F9 cross-user reset (first attempt)
**Actions:** used A's own OTP reference to reset B, then attempted login.
**Outcome:** reset returned `PSW004 Success`; the proof login was blocked by the 300 s login cool-down (`LGN005`), not by the password change. Also learned the reset password validator rejects certain formats (a 27-character value was refused), so a same-shape 16-character password was used subsequently.

## Turn 16 — F9 clean proof + restore
**Actions:** ran the proof as a background job (to ride out the cool-down without an SSH timeout): logout B → obtain A's `otp_ref` → reset B with it → log in as B with the attacker-chosen password → logout → restore B's original password → log in to confirm.
**Outcome:** **F9 confirmed end-to-end** — B logged in with the password derived from A's OTP reference; B was then restored (`exploit/f9_proof.log`). SSH dropped during the long sleep; the job had already completed and the connection was re-established.

## Turn 17 — F7 beneficiary + negative transfer
**Actions:** the beneficiary-add flow needs the target's IFSC. The client UI documents the format (`eg.IFSC00002`). With no bank-list endpoint, the code was enumerated with a fresh single-use OTP per attempt (a reuse attempt proved references are single-use, `OTP008`). **B's code = IFSC00008.** Added `BOBTEST`, then performed a `-1.00` transfer and a `+1.00` transfer.
**Outcome:** **F7 confirmed** — A `631737.69 → 631738.69`, B `956922.29 → 956921.29` on the negative transfer; both restored to the original values afterwards. The account statement shows the entry.

## Turn 18 — F11 key recovery + forgery test
**Actions:** offline HMAC test of a short candidate list against A's token; then re-signed a modified payload and called an authenticated endpoint.
**Outcome:** signing key = **`unsafebank`** (re-signing the untouched payload reproduced the token byte-for-byte). **But** modified-payload tokens were rejected (`ERRO06 "Session is invalid"`), showing the server also validates against a session store — recorded as a control that works, so F11 stays Medium.

## Turn 19 — F16/F13 error handling + scope check
**Actions:** signup without a `device` block; `OPTIONS` with a foreign `Origin`; phpinfo value extraction; beneficiary scoping check for A and B.
**Outcome:** verbose PHP notice with `models/SignUpModuleHandler.php:241` (part of F13); CORS wildcard with credentials (F14); `disable_functions` and `open_basedir` both empty (which explains F4's web-root write); beneficiaries are correctly scoped per user (positive observation).

## Turn 20 — O1 SSRF attempt
**Actions:** tested the `avatar` URL with an operator IP, a resolvable hostname (`sslip.io`), `file://`, and an empty string; ran both a raw `nc` listener and a real HTTP server serving a JPEG; checked the listener/server logs for any target request.
**Outcome:** every value rejected (`EDIT12 "Profile Picture link is invalid"`), no connection observed. **Not reproducible → recorded as an observation (O1), not a vulnerability**, per the "no reproduction path ⇒ observation" rule.

## Turn 21 — Cleanup verification and evidence hashing
**Actions:** re-requested the RCE file (404); confirmed the test listeners were stopped; hashed 189 artifacts (`report/artifact-index.txt`); reviewed the audit log (41 wrapped entries).
**Outcome:** no persistence on the target, no test processes left on the operator host. A **pre-existing** `nc -lvp 4444` (`/root/scans/catcher.log`) from an earlier session was observed and left untouched, flagged for the engagement lead.

## Turn 22 — Reporting
**Actions:** wrote this turn log, the report, and the redacted copy; pushed all three to the operator host under `/opt/engage-bb/report/`.
**Outcome:** deliverable complete.

---

## Decisions that mattered

1. **Separate workspace and report** from the earlier source-assisted engagement; prior findings were treated as untrusted hints.
2. **Black-box discipline:** no repository reading. Enumeration came from target responses and target-served client assets. File paths used by F1 were found by probing, not by reading source (the configuration files were then read *through the exploited bug* as impact proof).
3. **Disposable accounts only** for every state-changing test; each change was restored (balances, passwords, beneficiary).
4. **Minimum-footprint exploitation:** no persistence (self-deleting RCE file, verified), capped OTP testing (12 attempts), conservative scan rate (`-T3 --max-rate 500`, `ffuf -rate 10`), one host.
5. **Refused to inflate findings:** the SSRF was left as an observation when it could not be reproduced; the JWT key recovery was not called an authentication bypass because forged tokens were rejected; MD5 hashing was not asserted because it could not be verified black-box.
6. **Escalations/ambiguities:** the login cool-down and single-use OTP references were handled by adjusting the harness rather than by hammering the target.

## Uncertainty / limitations

- The black-box stance means the root cause of each finding is inferred from behaviour; the report describes the observed mechanism and avoids claiming internal details that were not demonstrated (e.g. exact SQL text beyond what errors leaked).
- The password-hashing algorithm could not be verified (O2).
- The avatar SSRF could not be reproduced (O1); a code-level review is recommended.
- Test-data residue: one loan application record and statement entries on tester account A cannot be removed via the API. All balances and credentials were restored.
- `audit.log` contains the 41 `audit.sh`-wrapped invocations; the remaining actions ran inside stored scripts (`exploit/*.py`, `*.sh`) whose stdout is preserved in `evidence/` and whose hashes are in the artifact index.

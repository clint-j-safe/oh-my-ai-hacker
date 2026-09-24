# HTB Machine — SAHW Findings Report

_Generated 2026-09-24 11:55 UTC · target `10.129.96.71` (HTB "GoodGames", Flask/Werkzeug · port 80) · model `z-ai/glm-5.3-flashx` (OpenRouter) · fully black-box over HTB VPN · engagement `ENG-2026-HTB-10.129.96.71` · 30-beat scan (complete)_

> No published answer key for this target — this report is the framework's own confirmed findings (each an independent black-box confirmation with a Langfuse trace + exploit hash + sandbox exit). Verdicts are the framework's Axiom/Provenance gate.

## Executive summary

| Metric | Count |
|--------|-------|
| **Distinct confirmed vulnerabilities** (class×endpoint×invariant) | **56** |
| Distinct vuln classes | 13 |
| Total confirmed instances | 56 |
| NEEDS_REVIEW (inconclusive) | 3 |
| FALSE_POSITIVE (self-rejected) | 7 |

Vuln classes: `auth_bypass`, `business_logic`, `clickjacking`, `crypto_disclosure`, `disposable_email_accepted`, `forced_browsing`, `improper_session_invalidation`, `info_disclosure`, `insecure_transport`, `rate_limit_absence`, `sqli`, `user_enumeration`, `weak_password_policy`.

## 1. Confirmed findings — by class

| Vuln class | Endpoints | Invariant(s) | Instances |
|-----------|-----------|--------------|-----------|
| `clickjacking` | `/`, `/blog`, `/blog/1`, `/blog/2`, `/blog/3`, `/blog/4`, `/blog/new`, `/coming-soon`, `/login`, `/logout`, `/profile`, `/signup` | `response_asserted` | 12 |
| `crypto_disclosure` | `/blog`, `/blog/1`, `/blog/2`, `/blog/3`, `/blog/4`, `/blog/new`, `/coming-soon`, `/login`, `/profile`, `/signup` | `response_asserted` | 10 |
| `insecure_transport` | `/`, `/blog`, `/blog/1`, `/blog/2`, `/blog/3`, `/blog/4`, `/coming-soon`, `/login`, `/profile`, `/signup` | `derived` | 10 |
| `info_disclosure` | `/`, `/blog/2`, `/blog/999`, `/blog/c/..%2f..%2f..%2fetc%2fpasswd`, `/profile`, `/static/vendor/bootstrap/dist/css/bootstrap.min.css.map` | `response_asserted`, `body_contains` | 6 |
| `auth_bypass` | `/blog`, `/blog/1`, `/login`, `/profile` | `body_contains` | 4 |
| `rate_limit_absence` | `/login`, `/password-reset`, `/signup` | `state_violated` | 3 |
| `disposable_email_accepted` | `/login`, `/signup` | `body_contains`, `state_changed` | 2 |
| `forced_browsing` | `/static/vendor/bootstrap/dist/css/bootstrap.min.css.map`, `/static/vendor/bootstrap/dist/js/bootstrap.min.js.map` | `status_in` | 2 |
| `improper_session_invalidation` | `/login`, `/logout` | `state_violated` | 2 |
| `weak_password_policy` | `/login`, `/signup` | `body_contains`, `state_changed` | 2 |
| `business_logic` | `/signup` | `state_changed` | 1 |
| `sqli` | `/login` | `body_contains` | 1 |
| `user_enumeration` | `/signup` | `body_contains` | 1 |

## 2. Confirmed findings — full list (56)

| # | Vuln class | Invariant | Endpoint | Instances | Sample trace |
|---|-----------|-----------|----------|-----------|--------------|
| 1 | `auth_bypass` | `body_contains` | `/blog` | 1 | `05c24c01893da50c` |
| 2 | `auth_bypass` | `body_contains` | `/blog/1` | 1 | `869fe34811b4b67d` |
| 3 | `auth_bypass` | `body_contains` | `/login` | 1 | `a3c72619b5a0efb9` |
| 4 | `auth_bypass` | `body_contains` | `/profile` | 1 | `818e580bdab17d6f` |
| 5 | `business_logic` | `state_changed` | `/signup` | 1 | `db009eca216a5849` |
| 6 | `clickjacking` | `response_asserted` | `/` | 1 | `09c308650d610780` |
| 7 | `clickjacking` | `response_asserted` | `/blog` | 1 | `061bc30db52bce9d` |
| 8 | `clickjacking` | `response_asserted` | `/blog/1` | 1 | `869fe34811b4b67d` |
| 9 | `clickjacking` | `response_asserted` | `/blog/2` | 1 | `6c49190df967f537` |
| 10 | `clickjacking` | `response_asserted` | `/blog/3` | 1 | `dc0e3d946c17a6f2` |
| 11 | `clickjacking` | `response_asserted` | `/blog/4` | 1 | `98e1d006d4c6574e` |
| 12 | `clickjacking` | `response_asserted` | `/blog/new` | 1 | `98e1d006d4c6574e` |
| 13 | `clickjacking` | `response_asserted` | `/coming-soon` | 1 | `061bc30db52bce9d` |
| 14 | `clickjacking` | `response_asserted` | `/login` | 1 | `ad44f34f95669cd4` |
| 15 | `clickjacking` | `response_asserted` | `/logout` | 1 | `a12254a53d1f61ce` |
| 16 | `clickjacking` | `response_asserted` | `/profile` | 1 | `061bc30db52bce9d` |
| 17 | `clickjacking` | `response_asserted` | `/signup` | 1 | `6f565514c320a50b` |
| 18 | `crypto_disclosure` | `response_asserted` | `/blog` | 1 | `31a8ebe2c866c459` |
| 19 | `crypto_disclosure` | `response_asserted` | `/blog/1` | 1 | `c2039c343325749a` |
| 20 | `crypto_disclosure` | `response_asserted` | `/blog/2` | 1 | `c2039c343325749a` |
| 21 | `crypto_disclosure` | `response_asserted` | `/blog/3` | 1 | `c2039c343325749a` |
| 22 | `crypto_disclosure` | `response_asserted` | `/blog/4` | 1 | `c2039c343325749a` |
| 23 | `crypto_disclosure` | `response_asserted` | `/blog/new` | 1 | `c2039c343325749a` |
| 24 | `crypto_disclosure` | `response_asserted` | `/coming-soon` | 1 | `c2039c343325749a` |
| 25 | `crypto_disclosure` | `response_asserted` | `/login` | 1 | `05c24c01893da50c` |
| 26 | `crypto_disclosure` | `response_asserted` | `/profile` | 1 | `31a8ebe2c866c459` |
| 27 | `crypto_disclosure` | `response_asserted` | `/signup` | 1 | `c2039c343325749a` |
| 28 | `disposable_email_accepted` | `body_contains` | `/login` | 1 | `0c67ab532b9ac122` |
| 29 | `disposable_email_accepted` | `state_changed` | `/signup` | 1 | `db009eca216a5849` |
| 30 | `forced_browsing` | `status_in` | `/static/vendor/bootstrap/dist/css/bootstrap.min.css.map` | 1 | `454f0ff67543c139` |
| 31 | `forced_browsing` | `status_in` | `/static/vendor/bootstrap/dist/js/bootstrap.min.js.map` | 1 | `eb5fdc16b2db19ad` |
| 32 | `improper_session_invalidation` | `state_violated` | `/login` | 1 | `6f565514c320a50b` |
| 33 | `improper_session_invalidation` | `state_violated` | `/logout` | 1 | `683247e699e094e3` |
| 34 | `info_disclosure` | `response_asserted` | `/` | 1 | `db009eca216a5849` |
| 35 | `info_disclosure` | `body_contains` | `/blog/2` | 1 | `061bc30db52bce9d` |
| 36 | `info_disclosure` | `body_contains` | `/blog/999` | 1 | `f823a9a024c2ad03` |
| 37 | `info_disclosure` | `response_asserted` | `/blog/c/..%2f..%2f..%2fetc%2fpasswd` | 1 | `6c49190df967f537` |
| 38 | `info_disclosure` | `body_contains` | `/profile` | 1 | `a3c72619b5a0efb9` |
| 39 | `info_disclosure` | `body_contains` | `/static/vendor/bootstrap/dist/css/bootstrap.min.css.map` | 1 | `454f0ff67543c139` |
| 40 | `insecure_transport` | `derived` | `/` | 1 | `ad44f34f95669cd4` |
| 41 | `insecure_transport` | `derived` | `/blog` | 1 | `84fbeec88780cb16` |
| 42 | `insecure_transport` | `derived` | `/blog/1` | 1 | `98e1d006d4c6574e` |
| 43 | `insecure_transport` | `derived` | `/blog/2` | 1 | `a3c72619b5a0efb9` |
| 44 | `insecure_transport` | `derived` | `/blog/3` | 1 | `a3c72619b5a0efb9` |
| 45 | `insecure_transport` | `derived` | `/blog/4` | 1 | `a3c72619b5a0efb9` |
| 46 | `insecure_transport` | `derived` | `/coming-soon` | 1 | `98e1d006d4c6574e` |
| 47 | `insecure_transport` | `derived` | `/login` | 1 | `6f565514c320a50b` |
| 48 | `insecure_transport` | `derived` | `/profile` | 1 | `dc0e3d946c17a6f2` |
| 49 | `insecure_transport` | `derived` | `/signup` | 1 | `94894fce9ffdd0ec` |
| 50 | `rate_limit_absence` | `state_violated` | `/login` | 1 | `ad44f34f95669cd4` |
| 51 | `rate_limit_absence` | `state_violated` | `/password-reset` | 1 | `b35d78eed122eecb` |
| 52 | `rate_limit_absence` | `state_violated` | `/signup` | 1 | `0c67ab532b9ac122` |
| 53 | `sqli` | `body_contains` | `/login` | 1 | `09c308650d610780` |
| 54 | `user_enumeration` | `body_contains` | `/signup` | 1 | `683247e699e094e3` |
| 55 | `weak_password_policy` | `body_contains` | `/login` | 1 | `09c308650d610780` |
| 56 | `weak_password_policy` | `state_changed` | `/signup` | 1 | `db009eca216a5849` |

## 3. Under review / self-rejected

| Verdict | Vuln class | Endpoint |
|---------|-----------|----------|
| NEEDS_REVIEW | `auth_bypass` | `/login` |
| NEEDS_REVIEW | `business_logic` | `/signup` |
| NEEDS_REVIEW | `insecure_transport` | `/` |
| FALSE_POSITIVE | `forced_browsing` | `/static/vendor/bootstrap/dist/js/bootstrap.min.js.map` |
| FALSE_POSITIVE | `improper_session_invalidation` | `/profile` |
| FALSE_POSITIVE | `rate_limit_absence` | `/login` |
| FALSE_POSITIVE | `rate_limit_absence` | `/blog/c/zzbrt7a00010` |
| FALSE_POSITIVE | `sqli` | `/blog` |
| FALSE_POSITIVE | `ssrf` | `/` |
| FALSE_POSITIVE | `xss_stored` | `/profile` |

## Notes

- **`sqli` @ `/login`** is the highest-value web finding — on this HTB box it is the initial foothold (UNION-based auth bypass → admin session → DB read). The framework confirmed it black-box.
- Full **authentication-surface coverage**: signup (user-enum, rate-limit, weak-password, disposable-email, business-logic), login (SQLi, weak-password, clickjacking, crypto), logout (session not invalidated).
- **Broad passive coverage** across every discovered route: clickjacking, crypto_disclosure and insecure_transport span the full page inventory; `forced_browsing` recovered shipped source maps (`*.css.map` / `*.js.map`) and `info_disclosure` caught an `/etc/passwd` traversal probe plus enumerable `/blog/<id>` content.
- **Scope boundary held at the pivot edge.** From the SQLi-recovered admin session the loop probed `/admin` on the in-scope host, found no panel, and concluded the admin panel lives on the out-of-scope `internal-administration` vhost — so it stopped rather than chasing it. No RCE / reverse shell: internal exploitation and the out-of-scope vhost were deliberately not pursued (the framework's re-prove-don't-weaponize model). A gated, controlled-env RCE→shell capability *within the in-scope app* is a pending enhancement.
- No answer-key-derived targeting; the framework recon'd the app from scratch (different stack from the prior PHP target).

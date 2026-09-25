# SAHW (Safe AI Hacker)

SAHW is an autonomous, black-box web-application penetration-testing framework. An LLM
"hunter" proposes probes and exploits; a deterministic verification core, the Axiom, decides
whether each proposed finding is real. The guiding principle is simple:

> The LLM proposes; deterministic code decides.

Because the verdict is deterministic and evidence-based, a weaker or cheaper hunter model
cannot produce a false positive: every CONFIRMED finding is backed by a control-differential
proof over real HTTP responses, plus provenance (trace id, exploit hash, sandbox id, exit
code).

This document explains what the framework is, how it is put together, how to run it, and how
to read its output. For the full operator runbook (every environment variable, tuning tables,
LLM wiring, deploy commands), see `docs/OPERATING.md`.

## Table of contents

1. What SAHW does
2. Core concepts
3. Architecture
4. Module map
5. Capabilities
6. The safety model
7. Quickstart
8. Reading results
9. Track record
10. Repository layout

## 1. What SAHW does

Given an authorized target in scope, SAHW runs a bounded loop ("beats"). Each beat:

1. Loads the engagement (scope, authorization window, budgets, deep-mode flags).
2. Optionally runs a deterministic pre-pass (deep mode): DNS/vhost discovery, an input by
   payload sweep, and stateful multi-step probes.
3. Runs the LLM hunt: the model reads the current state, chooses one probe at a time, and
   submits candidate findings.
4. Verifies every candidate with the Axiom (a control-differential over real responses).
5. Banks CONFIRMED findings to the datastores and the spine (persistent progress), so the
   next beat builds on what was learned.

The result is a set of verified findings (SQL injection, command injection, XXE, IDOR,
auth bypass, deserialization RCE, business-logic flaws, and more), each with a machine-checked
proof, not a model's unverified claim.

## 2. Core concepts

* Beat: one bounded pass of the loop. One Docker container run equals one beat. Beats share a
  workspace so state accumulates.
* The Axiom: the sole verdict authority (`orchestrator/src/axiom.ts`). It evaluates typed
  invariants (`body_contains`, `status_in`, `response_asserted`, `derived`, `state_changed`,
  `state_violated`, `file_created_then_deleted`) and never trusts a model's assertion. Missing
  evidence is never a pass.
* Invariant: the precise statement of what makes a finding true (for example, "a marker
  appears in the exploit response but not in a benign control", or "the account balance field
  changed from X to Y").
* The Spine: `progress.json` in the workspace. Read first and written last every beat. It
  carries proved findings, the attack surface, recovered intel, and sessions.
* The Tether: the scope and egress gate (`orchestrator/src/tether.ts`). Every request URL is
  checked in-scope before it leaves; out-of-scope host or port is denied.
* Provenance gate: a finding is only accepted with a full evidence bundle (Langfuse trace id,
  exploit request hash, sandbox id, exit code).

## 3. Architecture

SAHW runs as a set of containers on a runner host that can reach the target (directly, or over
a VPN for lab targets such as Hack The Box).

* Orchestrator image (`sahw-orchestrator`): Node 20, TypeScript, ESM. One container equals one
  beat. It drives the loop, the deep-mode sweep, the Axiom, and writing findings.
* Datastores and observability (long-running, not restarted per beat):
  * ClickHouse: the queryable findings table (`sahw_findings`).
  * Neo4j: a graph of endpoints and findings.
  * Langfuse: one LLM trace per beat.
  * OOB service: out-of-band callback correlation (DNS, HTTP, shell) for blind and RCE proofs.
* The workspace volume: holds the spine, the artifact store (hashed request/response
  captures), and session material.

The framework is model-agnostic. It talks to an OpenAI-compatible endpoint (OpenRouter for the
`test` profile, a self-hosted or gateway endpoint for `prod`). The Axiom's determinism means
the choice of model affects breadth and speed, not the integrity of a verdict.

## 4. Module map (orchestrator/src)

* `cli.ts`: entry point; builds the LLM client and calls `runBeat`.
* `beat.ts`: the beat controller; deep-mode sweep, DNS recon, stateful probes, banking.
* `axiom.ts`: deterministic verdicts over typed invariants; the deriver registry.
* `tether.ts`: scope and egress enforcement.
* `provenance.ts`: the evidence-bundle gate.
* `spine.ts`: persistent progress (proved, attack surface, recovered intel, sessions).
* `brief.ts`: builds the hunter brief (state rendered as XML) each beat.
* `agent.ts`: the LLM loop (one probe per turn).
* `tools.ts`: the Tether-gated tool surface (`http_request`, `register_account`, artifact
  read/grep, skill runner).
* `session.ts`: disposable-account registration and session material (secrets never leave).
* `sweep.ts`, `sweep-targets.ts`, `sweep-forms.ts`, `fuzz.ts`: the deterministic input by
  payload sweep, target derivation (JSON, query, and form-urlencoded bodies), and the pure
  fuzz oracle.
* `stateful.ts`: pure helpers for multi-step probes (field-role inference, JWT extraction,
  device grafting, XXE builder, AES-param recovery, PHP-serialized gadget swap).
* `dns-recon.ts`: reverse-DNS, AXFR zone transfer, and Host-differential vhost discovery.
* `judge.ts`: the optional LLM adjudicator (promotes a deterministic NEEDS_REVIEW only when
  its rubric is clearly met; never invents a CONFIRMED).
* `stall.ts`: barren-beat detection and early stop.
* `vuln-classes.ts`: the vocabulary of finding classes.

## 5. Capabilities

### Breadth-first LLM hunt (default)

One cheap probe per turn, guided by a state-derived brief. Confirmed findings and recovered
intel carry forward through the spine.

### Deep mode (opt-in, `SAHW_DEEP_MODE=1`)

A deterministic pre-pass on the first beat that does not depend on the model to fire:

* Input by payload sweep across every discovered input (JSON leaves, query params, and
  form-urlencoded body keys), judged by the pure fuzz oracle and banked straight through the
  Axiom. Classes include reflected and stored XSS, HTML injection, SSTI, SQL injection,
  command injection, path traversal, and XXE.
* Stateful multi-step probes: broken-password-change (login state differential),
  no-secondary-factor-before-OTP (a sound `derived` proof), and a bounded, reversible
  negative-transfer business-logic probe.
* DNS-driven virtual-host discovery: reverse-DNS and AXFR zone transfer of the target's own
  DNS, plus a prefix list appended to discovered base domains, each confirmed by a Host-routed
  differential. Discovered hosts are added to `/etc/hosts`, scope, and the attack surface so
  the loop can reach an app that only answers on a vhost. Nothing is guessed: every candidate
  traces back to the target's DNS or the scope list.
* Login auth-bypass oracle: a SQL-injection login bypass is confirmed on a redirect or
  session-cookie differential, the signal a body-contains or DB-error oracle misses.

### Escalation and weaponization (gated)

* Escalation chaining up to a configured depth after a confirm (`SAHW_DEEP_ESCALATION_DEPTH`).
* A weaponization tier (`SAHW_DEEP_WEAPONIZE=1`) for RCE and shell proofs, fail-closed behind a
  double-confirm: it throws unless `SAHW_DEEP_WEAPONIZE_AUTH_REF` exactly equals
  `SAHW_AUTH_REF`. Out-of-band callbacks are correlated by the OOB service.

## 6. The safety model (always on)

* Authorization window: no run outside `[SAHW_AUTH_START, SAHW_AUTH_END]`.
* Tether: every request URL is checked in-scope; out-of-scope host or port is denied, and a
  redirect is captured rather than silently followed.
* Weaponize double-confirm: deep mode off forces weaponize off; weaponize on requires the
  authorization ref to be named twice and to match.
* Restoration (L2): a `state_changed` mutation without restoration proof downgrades to
  NEEDS_REVIEW. Destructive probes are bounded and reverse themselves (for example, the
  negative-transfer probe issues a compensating transfer).
* Secret hygiene: session tokens and passwords are injected by label and never returned to the
  model or written to the spine.

## 7. Quickstart

Prerequisites: Docker on the runner, the datastore and OOB containers running, network access
to an authorized target, and an LLM endpoint with a key. See `docs/OPERATING.md` for the full
setup.

Build the image (the build runs the Node test suite as a gate):

```
git archive HEAD orchestrator skills > /tmp/sahw-src.tar
scp /tmp/sahw-src.tar root@RUNNER:/tmp/sahw-src.tar
ssh root@RUNNER 'cd /opt/sahw-src && tar -xf /tmp/sahw-src.tar \
  && docker build -f orchestrator/Dockerfile -t sahw-orchestrator .'
```

Run a single beat:

```
docker run --rm --network host --env-file /opt/sahw-run/engagement.env \
  -e SAHW_BEAT_NO=1 -e SAHW_RUN_ID=myrun -e SAHW_WORKSPACE=/workspace \
  -v /opt/sahw-run/ws-myrun:/workspace \
  sahw-orchestrator
```

Run a full deep engagement (multiple beats over one workspace), see the loop pattern and the
tuning tables in `docs/OPERATING.md`.

Local development:

```
cd orchestrator && npm test
```

## 8. Reading results

Query the findings table (ClickHouse). Verdicts are `CONFIRMED`,
`CONFIRMED_BY_ADJUDICATION`, `NEEDS_REVIEW`, `FALSE_POSITIVE`, and `BLOCKED`:

```
curl -s -u USER:PASS 'http://127.0.0.1:8123/?database=DB' --data-binary \
 "SELECT vuln_class, endpoint, invariant_type, verdict
  FROM sahw_findings
  WHERE endpoint ILIKE '%TARGET%' AND verdict='CONFIRMED'
  GROUP BY vuln_class, endpoint, invariant_type, verdict
  ORDER BY vuln_class FORMAT TSV"
```

LLM traces are in Langfuse; the endpoint and finding graph is in Neo4j. For benchmark-style
scoring, an offline scorer (`bench/`) compares CONFIRMED findings against a ground-truth
rubric and reports covered, partial, missed, and false positives. The scorer and its
benchmark data are kept local and are not required to operate the framework.

## 9. Track record

* unsafebank human-test benchmark: 28 of 28 ground-truth findings covered, black-box and
  Axiom-banked, including multi-step (broken password change, negative-transfer balance
  delta), a sound `derived` finding, stored XSS via a PHP-serialized gadget, and XXE on the
  canonical route.
* HTB Cronos: DNS-driven discovery of the `admin.cronos.htb` virtual host, then a SQL-injection
  login bypass chained into a command-injection RCE on `welcome.php`, all verified.
* HTB .NET/IIS JSON API: a deserialization RCE and an auth bypass on `/api/Account/`.

Engagement reports live locally under `docs/htb/` (kept off git because they contain
live-target findings).

## 10. Repository layout

```
orchestrator/     the framework runtime (TypeScript): the loop, Axiom, tether, sweep, probes
skills/           attack and support skills invoked by the loop
docs/             design docs, agent role docs, schemas, and the operator guide (OPERATING.md)
bench/            offline benchmark scorer (local only, not needed to run the framework)
```

## Notes on scope and ethics

SAHW is for authorized security testing only: engagements you own or are explicitly permitted
to test, CTF and lab machines, and defensive research. The authorization window, the Tether
scope gate, and the weaponize double-confirm are enforced in code and cannot be bypassed by the
model. Do not point it at systems you are not authorized to test.

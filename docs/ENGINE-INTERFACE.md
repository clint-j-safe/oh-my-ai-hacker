# SAHW Engine Interface (for building the TUI)

This document describes the SAHW framework at the level a front-end (the ai-hacker-cli TUI)
needs: what the engine does, how you drive it, what it emits, and the exact data shapes you
will render and monitor. It is written for a developer wiring a UI on top of the engine, not
for an operator running it by hand (that is `docs/OPERATING.md`).

## 1. Mental model

SAHW runs as a sequence of bounded passes called beats. One beat is one process run (one Docker
container, or one `node cli.ts`). A beat reads persistent state (the spine), does work
(deterministic sweep plus an LLM hunt), verifies every candidate finding deterministically (the
Axiom), and writes results to datastores and back to the spine. Running N beats over the same
workspace makes state accumulate.

The engine has no long-running server and no socket API. You drive it by launching beats and
observing four output surfaces:

1. Process stdout: a single JSON object per beat (the BeatResult).
2. Process stderr: human-readable logs, including tagged probe diagnostics.
3. The spine file: `WORKSPACE/spine/progress.json`, rewritten at the end of each beat.
4. ClickHouse: the cumulative `sahw_findings` table (the source of truth for findings).

Optional: Langfuse (one LLM trace per beat) and Neo4j (endpoint/finding graph).

So a TUI is, at its core: a launcher (start/stop beats with a config), a live monitor (tail
stdout and stderr, poll the spine), and a findings browser (query ClickHouse).

## 2. Launching a beat (the control contract)

A beat is one invocation of the orchestrator. In production this is a Docker run; the TUI can
shell out to Docker (or to `node`/`tsx` for local dev).

Inputs are all environment variables (there are no positional args except `--dry-run`):

* Engagement env file (scope, authorization window, LLM keys, datastore DSNs, OOB). Passed as
  `--env-file`.
* Per-run overrides passed as `-e KEY=VALUE` (beat number, run id, workspace, budgets, deep
  flags). These let one env file serve many run shapes.

Required per-beat variables:

* `SAHW_BEAT_NO`: the beat index (1, 2, 3, ...). The deep-mode sweep and DNS recon run on beat
  1 only; later beats inherit their results from the spine.
* `SAHW_RUN_ID`: groups beats of one run into one Langfuse session.
* `SAHW_WORKSPACE`: the in-container path of the mounted workspace volume (holds the spine and
  artifact store).

`--dry-run` prints `{ "dryRun": true, "scope": ..., "profile": ... }` and exits 0. Use this
from the TUI to validate an engagement config before a real run.

Example the TUI would assemble and run:

```
docker run --rm --network host --env-file <engagement.env> \
  -e SAHW_BEAT_NO=<i> -e SAHW_RUN_ID=<runId> -e SAHW_WORKSPACE=/workspace \
  -v <hostWorkspace>:/workspace \
  <per-beat overrides> \
  sahw-orchestrator
```

Stopping a run: the TUI stops the container (`docker rm -f <name>`) and, for a multi-beat loop,
its loop driver. There is no in-process cancel API; a beat is bounded by its phase and request
timeouts and by the stall detector.

## 3. What a beat emits on stdout (BeatResult)

Exactly one JSON object is printed to stdout when the beat ends, and the process exit code is
`BeatResult.exitCode`. Shape:

```
{
  "exitCode": 0,
  "findings": [ FindingRow, ... ],       // findings produced THIS beat (see section 5)
  "stalled": false,                       // true if the stall detector tripped
  "reason": null,                         // why it stopped/stalled, or null
  "duplicates_suppressed": 0,             // bare duplicate claims not replayed
  "already_proved_suppressed": 0,         // claims whose class was already proved this engagement
  "rejected_claims": [ { "raw": "...", "reason": "..." }, ... ],
  "failure_causes": { "<cause>": <count>, ... },   // every FailureCause key present, default 0
  "spine_fresh": false,                   // true if this beat started a brand-new spine
  "spine_fresh_reason": null,             // why the spine was fresh (scope mismatch, corrupt, ...)
  "late_fault": "..."                     // present only if a fault arrived after the beat finished
}
```

For the TUI: the per-beat headline is `findings` (and their verdicts), plus `stalled`/`reason`
for run health, and `failure_causes` for a "why is nothing landing" panel. `spine_fresh` with
a reason is important to surface: it means the run did not continue prior state (often a scope
or engagement-ref mismatch).

Exit codes: 0 is a normal beat. A non-zero code signals a stall or failure; the specific stall
exit code is configurable (`SAHW_STALL_EXIT_CODE`). Treat any non-zero as "beat did not complete
cleanly" and show `reason`.

## 4. What a beat emits on stderr (logs and probe traces)

stderr carries progress and diagnostics. Notable tagged lines the TUI can parse and surface:

* `[dns-recon] ...`: reverse-DNS, AXFR, and discovered virtual hosts (for example
  `VHOST admin.cronos.htb -> <ip>` and `added vhosts to scope: ...`).
* `[f13-probe] / [f19-probe] / [f24-probe] / [f25-probe] ...`: stateful probe step-by-step
  diagnostics (signup, login, marker, bank/abort).
* Store and observability warnings (for example a datastore being down) are logged and the beat
  continues; they are not fatal.

These are free-form text, not a stable API. Use them for a live activity feed; use stdout and
ClickHouse for structured data.

## 5. The finding record (FindingRow)

Every finding, in the BeatResult and in ClickHouse `sahw_findings`, has these fields:

```
engagement_id     string   the engagement (equals SAHW_AUTH_REF)
finding_id        string   unique id, e.g. SAHW-1a2b3c4d
vuln_class        string   see section 9 for the vocabulary
endpoint          string   the canonical URL the finding is recorded on
verdict           string   see the verdict list below
invariant_type    string   how it was proven: body_contains | status_in | response_asserted |
                           derived | state_changed | state_violated | file_created_then_deleted
verdict_reason    string   the Axiom's plain rationale (e.g. "marker present in exploit, absent
                           in control"), for a WHY panel without opening the trace
langfuse_trace_id string?  the trace id, or null when no real trace was active
utc               string   ISO timestamp
```

Verdict values:

* `CONFIRMED`: deterministically proven by the Axiom (a real control-differential or a
  registered deriver). This is the only tier that is deterministic proof.
* `CONFIRMED_BY_ADJUDICATION`: a NEEDS_REVIEW that the optional LLM judge promoted because its
  rubric was clearly met. Carries its own provenance. Show it distinctly from CONFIRMED.
* `NEEDS_REVIEW`: evidence incomplete or ambiguous (for example no control captured, or a
  restoration was required but not proven). Not a pass.
* `FALSE_POSITIVE`: the differential did not hold (for example the marker also appears in the
  control).
* `BLOCKED`: the Tether or a gate refused the action.

The `sahw_findings` table is cumulative across beats and engagements. Always filter by
`engagement_id` (or by endpoint host) and by `verdict`. It is a ClickHouse MergeTree, so the
same finding can appear more than once across beats; group/distinct on
`(vuln_class, endpoint, invariant_type)` for a clean per-target view.

## 6. The spine (persistent state), WORKSPACE/spine/progress.json

Rewritten at the end of every beat. It is the best single source for "current state of the
engagement" between beats:

```
{
  "schema_version": <int>,
  "engagement": { authRef, scope, ... },
  "beats": [ per-beat summary records ],
  "attack_surface": [ SpineEndpoint, ... ],   // discovered endpoints
  "recovered_intel": { ... },                  // learned facts (api base, envelopes, vhosts, ...)
  "sessions": [ { label, username, has_auth_material, ... } ],  // NON-secret metadata only
  "proved": [ ProvedEntry, ... ],              // classes/endpoints already proven (dedupe key)
  "attempted": [ AttemptedEntry, ... ],
  "counters": { ... },
  "fresh_reason": null                          // why the spine started fresh, or null
}
```

SpineEndpoint (an attack-surface entry the TUI can render as a tree):

```
{ url, method, status, content_type, semantic_role?, notes? }
```

ProvedEntry (a banked finding, the "do not re-derive" signal):

```
{ vuln_class, endpoint, invariant_type, verdict, finding_id }
```

Secrets never appear in the spine. Session passwords and tokens live only in process for the
run and are re-obtained (a fresh self-registration) rather than restored across a process
restart.

## 7. Lifecycle of one beat (phases to visualize)

1. Config load: `loadEngagement` parses env; throws (non-zero exit, clear message) if outside
   the authorization window or if the weaponize double-confirm fails. The TUI should show these
   as configuration errors, not runtime failures.
2. Registration: disposable accounts are (re)acquired so authenticated classes can be tested.
3. Brief: the current spine is rendered as an XML brief for the hunter.
4. Deep-mode pre-pass (beat 1 only, if `SAHW_DEEP_MODE=1`): DNS recon, then the stateful probes
   (F-19/F-24/F-25/F-13/login-bypass), then the input by payload field sweep, then XXE and
   debug probes. Confirmed hits are banked straight through the Axiom and appear in the beat's
   findings.
5. LLM hunt: the model runs a turn loop (one probe per turn), submitting candidate findings that
   the Axiom verifies. Bounded by `SAHW_MAX_TURNS`, `SAHW_MAX_TURNS_PER_FINDING`,
   `SAHW_MAX_FINDINGS`, and the token/USD budgets.
6. Bank and persist: findings go to ClickHouse/Neo4j; the spine is rewritten; the BeatResult is
   printed and the process exits.

## 8. The Axiom and invariants (for a WHY view)

The Axiom is the sole verdict authority. It never trusts the model's claim; it evaluates a typed
invariant over the real exploit response (and, for differential types, a benign control):

* `body_contains`: a marker is present in the exploit exchange and absent in the control. Scans
  the serialized exchange (status line, headers, body).
* `status_in`: the response status is in an allowed set.
* `response_asserted`: a self-evidencing property of the response (for example a missing
  security header, a dangerous CORS combination). No attacker input to vary.
* `derived`: a named, hand-written deterministic function (a deriver) computes the verdict from
  typed evidence (for example an HS256 weak-key check, an AES-CBC OTP decrypt match, or the
  no-secondary-factor-before-OTP proof). The model can only select a deriver by name; it cannot
  supply the logic.
* `state_changed`: an observe, act, observe triple where a field or marker changed as predicted
  (for example a balance field went from X to Y). A required-but-unproven restoration downgrades
  to NEEDS_REVIEW.
* `state_violated`: a rule that must hold across a sequence is broken (for example a lockout that
  never triggers, or a session that survives a password change).
* `file_created_then_deleted`: a before/during/after triple proving a write then cleanup.

For a WHY panel, show `invariant_type` plus `verdict_reason`.

## 9. Finding classes (vocabulary)

`auth_bypass`, `idor`, `sqli`, `xss_reflected`, `xss_stored`, `xxe`, `ssrf`,
`command_injection`, `path_traversal`, `deserialization_rce`, `business_logic`,
`rate_limit_absence`, `weak_password_policy`, `user_enumeration`, `disposable_email_accepted`,
`insecure_transport`, `crypto_disclosure`, `jwt_weak_key`, `improper_session_invalidation`,
`clickjacking`, `cors_misconfig`, `info_disclosure`, `forced_browsing`. This is the canonical
set the scorer and the loop share; treat any others as extensions.

## 10. Deep mode and gates the TUI should expose or guard

* `SAHW_DEEP_MODE` (0/1): enables the deterministic sweep, DNS recon, stateful probes, and the
  attack skills. Off by default.
* `SAHW_DEEP_SWEEP_BUDGET` (default 500): total sweep requests.
* `SAHW_DEEP_ESCALATION_DEPTH` (default 2): max chain depth after a confirm. There is no separate
  on/off flag.
* `SAHW_DEEP_WEAPONIZE` (0/1): the RCE/shell tier. Fail-closed: it throws unless
  `SAHW_DEEP_WEAPONIZE_AUTH_REF` exactly equals `SAHW_AUTH_REF`. The TUI should treat this as a
  guarded toggle with an explicit confirmation, and it must set the matching auth ref.
* Authorization window: `SAHW_AUTH_START`/`SAHW_AUTH_END`. A run outside the window fails at
  config load. Surface the window and warn before it expires.

For OOB-dependent proofs (blind vulns, reverse shells), `OOB_ANSWER_IP` must be an address the
target can reach back on. For a VPN lab target this is the tunnel IP, not the runner's public IP.

## 11. Suggested TUI surfaces

* Engagement editor: read/write the env file; validate with `--dry-run`; show the authorization
  window and the deep/weaponize toggles with their guards.
* Run controller: launch a single beat or a multi-beat loop with per-run overrides; stop the
  container/loop; show `SAHW_RUN_ID` and the workspace path.
* Live monitor: tail stdout (parse each BeatResult) and stderr (tagged activity feed); poll the
  spine for the attack surface, proved set, and sessions between beats.
* Findings browser: query `sahw_findings` filtered by engagement and verdict; group by
  `(vuln_class, endpoint, invariant_type)`; open a finding to show `verdict_reason` and the
  Langfuse trace link.
* Health panel: `stalled`/`reason`, `failure_causes`, `spine_fresh` with reason, exit code, and
  a datastore-reachability check.

## 12. Integration surface summary

* Control in: environment variables plus `docker run` / process launch; `--dry-run` to validate.
* Structured out: one BeatResult JSON on stdout per beat; the `sahw_findings` ClickHouse table
  (cumulative); the spine `progress.json` (current state).
* Unstructured out: stderr logs and tagged probe traces (activity feed).
* Observability: Langfuse traces (per beat, keyed by `SAHW_RUN_ID`), Neo4j graph.
* Safety, enforced in the engine and not bypassable from a UI: the authorization window, the
  Tether scope gate, the weaponize double-confirm, and the restoration requirement.

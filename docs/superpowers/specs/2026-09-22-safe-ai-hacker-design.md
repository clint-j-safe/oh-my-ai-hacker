# SAFE AI Hacker — Architecture Design Document

**Version:** 2.0 · **Date:** 2026-09-22
**Runtime:** OpenAI **TypeScript** SDK as a stateless client
**Provider:** **OpenRouter** while building and testing → **self-hosted GLM 5.3 on Amazon SageMaker** for production. Both are OpenAI-compatible; the swap is a profile, not a rewrite.
**Paradigm:** Client-side loop engineering + adversarial verification
**Status:** *Documentation only.* No code, no runtime wiring, no engagement run in this phase.

> Every model call in this system is `client.chat.completions.create` through the **openai**
> npm package. See the changelog at the end for what v2 replaced.

---

## 1. Purpose and the definition of done

The system is an autonomous, **black-box** web/API penetration tester. Success is not
"it found something" — it is a fixed, pre-existing scorecard:

> **The pipeline must independently rediscover the findings a human tester produced,
> scored by `docs/bench/human-test-benchmark.md`.**

That rubric is the **answer key and is never loaded into any agent's context** — not into
prompts, not into the scope object, not into the graph. The agents start from the in-scope
URLs alone. The harness compares afterwards.

**The scoring contract** (shape defined in the benchmark file):

| Dimension | Requirement |
|---|---|
| Per ground-truth id | `covered` \| `partial` \| `missed` — a **CONFIRMED** finding of the same `vuln_class`, on a matching endpoint, with a **passing invariant of the expected type** |
| Chains | Both ground-truth chains reconstructed, each with `chained_severity: Critical` |
| False positives | Counted and reported. Two observations in the rubric were **not reproducible**; claiming either is a false positive |
| Positive controls | Four behaviours the engagement confirmed **correct**. Flagging any of them as a finding is a false positive |

A run that reports fewer findings with zero false positives beats a run that reports
everything. **One Axiom-verified critical finding outranks a thousand unconfirmed mediums.**

Milestones (`M0 → M6`, defined in the benchmark file) are worked **one win at a time**:
M0 is a single unauthenticated, single-request class; M6 is both chains.

---

## 2. Principles

1. **Loop Engineering — the LLM proposes; deterministic code decides.** Every model output
   is a *proposal*. Deterministic code decides whether it runs (the **Tether**) and whether
   a result counts (the **Axiom**). No agent self-certifies a finding.
2. **Maker ≠ checker.** The agent that discovers a vulnerability is never the agent that
   confirms it. The finder cannot invoke the adjudicator; the adjudicator cannot invoke the
   finder.
3. **Declarative capability boundaries.** Capability is the `tools` array of the request, not
   a sentence in a prompt. A tool that is not declared cannot be called — there is nothing
   to jailbreak.
4. **Provenance over prose.** No claim is `CONFIRMED` without the exact command, the raw
   output, the output hash, the sandbox id, and the trace id.

---

## 3. Hard constraints

1. **Black-box; nothing hardcoded.** No target hostnames, endpoints, paths, payloads,
   envelopes or credentials appear in `docs/agents/*`, in config, or in the scope object.
   Everything is discovered at runtime.
2. **Input = in-scope URLs (± credentials).** Credentials are optional. In pure black-box
   mode — the current focus — the system **self-registers ≥2 disposable accounts through the
   target's own signup flow** to reach the authenticated and cross-user surface. Supplied
   credentials are only a shortcut. Unauthenticated, authenticated and chain findings are
   all in scope.
3. **Scope = exactly the provided URLs.** HTTP(S) only, on the given hosts and ports. **No
   port scanning, no subdomain enumeration, no CT logs, no passive DNS.**
4. **Safety level L2 — read-only or reversible.** No DoS or resource exhaustion, no
   destructive writes, no persistence, no lateral movement, no real-PII exfiltration.
   Any mutation is restored and the restoration is verified.
5. **Secrets are handles.** Recovered secrets travel as `{{secret:ref}}` references — never
   plaintext in a prompt, a trace, the graph, or a report.
6. **Self-contained deciders.** Deterministic code plus GLM 5.3 as a judge model for fuzzy
   calls only. **No external closed decision service** — jev/TypeSafe is deliberately not
   part of the framework.

---

## 4. Topology

```
HEARTBEAT   cron / scheduled runner / CI event → starts each beat (no human prompt)

CONTROL PLANE  (TypeScript, openai npm SDK)  —  the Big Loop
  Orchestrator      phase state machine 1→2→3→4; no LLM in phase control
  Conversation Mgr  one message array per agent task; abort on breach
  Budget            usage.prompt_tokens / completion_tokens → USD → hard stop
  Tether            tool-dispatch gate: scope allowlist + destructive-AST check
  Axiom             verdict engine: deterministic invariant replay (+ judge for fuzzy)
  Spine             progress + rules files; read first, written last, each beat
  Artifact Store    content-addressed (SHA-256), immutable, indexed by trace id

MODEL LAYER   (one client, two profiles — selected by env, never by code)
  test  → OpenRouter            baseURL https://openrouter.ai/api/v1
  prod  → AI Gateway → SageMaker GLM 5.3   baseURL https://<endpoint>/openai/v1
          (short-lived per-engagement credential from a scoped IAM role)

EXECUTION PLANE  (ephemeral Docker per agent/iteration, disposable volumes) — Small Loops
  Agent instructions   docs/agents/*.md   (core.md prepended to each)
  Skills-as-tools      ./skills — 36 skills, one generic dispatcher tool
  MCP (version-pinned) mcp-patt (payload corpus) · mcp-oast (out-of-band callbacks)

STATE & OBSERVABILITY
  Neo4j       attack graph: surface · secrets · findings · chains · coverage
  Langfuse    one trace per beat; spans per agent turn and per tool call
```

- **AI Hacker Tether** = the scope/safety gate — decides whether an action may run.
- **AI Hacker Axiom** = the validation core — decides whether a result is a finding.

### 4.1 Provider profiles

The whole point of targeting the OpenAI-compatible surface is that the provider is
configuration. **No agent, prompt, skill, tool or verdict logic changes between profiles.**

| | `test` (now) | `prod` (later) |
|---|---|---|
| Provider | OpenRouter | SageMaker, self-hosted GLM 5.3 |
| `baseURL` | `https://openrouter.ai/api/v1` | `https://<endpoint>/openai/v1` |
| Auth | `OPENROUTER_API_KEY` | short-lived per-engagement credential from the AI Gateway |
| `{{REASONING_MODEL}}` | any capable OpenRouter slug | `glm-5.3` |
| `{{FAST_MODEL}}` | a cheap OpenRouter slug | `glm-5.3` |
| Cost signal | real per-token USD, returned by the provider | **none — see below** |
| Data egress | third party sees engagement traffic | stays inside the VPC |

Agent files already reference **logical** model names (`{{REASONING_MODEL}}`,
`{{FAST_MODEL}}`), resolved by the orchestrator at dispatch. That indirection is what makes
the cutover a config change: no agent file is edited when the provider moves.

**Two things genuinely differ.** *The budget stop loses its unit:* OpenRouter bills per token,
so USD is real; a self-hosted endpoint bills for **uptime**, has no per-token price, and a
naive accumulator reads `cost: 0` forever — silently disabling the stop. Ceilings are therefore
tokens and turns, which both profiles report (§11). *Profile is a scope decision:* under `test`,
engagement traffic — including recovered `{{secret:ref}}` context — transits a third party, so
only targets whose rules of engagement permit that may run under it.

Both profiles are assumed to support `tools`, `parallel_tool_calls`, `response_format` and a
populated `usage`. OpenRouter does; that proves nothing about the SageMaker shim, so verifying
it is a **cutover gate, not a Phase 1 gate**.

### 4.2 Configuration contract

Everything tunable lives in `.env`; `.env.example` is the committed, secret-free reference and
the single list of knobs. **No behaviour is tuned by editing a prompt, an agent file or a
skill** — those are target-agnostic by design, and an engagement-specific value in one of them
would break the black-box rule in §3.

| Group | Controls | Prefix |
|---|---|---|
| Scope | in/out-of-scope URLs, CIDRs, authorization window, max safety tier | `SAHW_SCOPE`, `SAHW_AUTH_*`, `SAHW_AUTHORIZED_TIERS` |
| Provider | profile select, both base URLs, keys, logical→concrete model mapping | `SAHW_PROFILE`, `OPENROUTER_*`, `SAGEMAKER_*` |
| Budget | turn / token / USD ceilings, request and phase timeouts, retries | `SAHW_BUDGET_*`, `SAHW_MAX_TURNS`, `SAHW_*_TIMEOUT_MS` |
| Stall | the four detection thresholds and the failure exit code | `SAHW_STALL_*` |
| Verdicts | escalation confidence, judge threshold, adjudicator count and quorum | `SAHW_AXIOM_*`, `SAHW_ADJUDICATOR_*` |
| State | workspace, engagement graph, **separate** coverage graph | `SAHW_WORKSPACE`, `NEO4J_*` |
| Observability | Langfuse host and keys | `SAHW_LANGFUSE_*`, `LANGFUSE_*` |
| Out-of-band | OAST listener address and ports | `OOB_*` |

Two of these are correctness-critical rather than preference: `SAHW_SCOPE` **is** the Tether's
allowlist — it is not a hint — and `NEO4J_COVERAGE_*` is deliberately a different credential
from `NEO4J_*` so the benchmark answer key cannot reach an agent (§8).

---

## 5. Loop engineering

### 5.1 Inner loop (one API turn)

The agent's instructions are the **first `system` message** of the message array; the model
emits tool calls, receives results, and iterates to a terminal assistant message. The
orchestrator drives this loop itself — the SDK is a stateless transport.
`parallel_tool_calls: false` keeps each step observable and individually gateable.

**API surface: Chat Completions, not Responses.** Every call is
`client.chat.completions.create`. The Responses API (`/responses`, with its top-level
`instructions` parameter) is **not assumed** — most OpenAI-compatible self-hosted shims
implement `/chat/completions` only. Agent prompts therefore travel as a `system` message,
never as an `instructions` field.

> **Cutover gate, not a Phase 1 gate.** OpenRouter supports `tools`, `parallel_tool_calls`,
> `response_format: {type: "json_object"}` and a populated `usage`, so `test` runs prove
> nothing about the SageMaker shim. Before the `prod` cutover, verify all four against the
> deployed GLM 5.3 endpoint — `response_format` combined with `tools` is the least likely to
> survive. If it does not, the orchestrator falls back to schema-validating the terminal
> message content and re-prompting on a parse failure; the budget and verdict logic are
> unaffected, since both read `usage` and the artifact store, not the response format.

### 5.2 Outer loop (the orchestrator owns it)

| Control | Mechanism |
|---|---|
| **Turn bound** | Client-side assistant-turn counter; hard stop at `maxTurns` |
| **Budget** | Accumulate `usage` per conversation → USD; abort on `maxBudgetUsd`. Prevents runaway reconnaissance billing |
| **Tether (dispatch wrapper)** | Intercepts **every** tool call *before* execution: target host/port ∈ engagement allowlist, and the command passes a destructive-pattern AST check. Deny is terminal; there is no prompt-level override |
| **Result wrapper** | Redacts secrets to `{{secret:ref}}`, hashes stdout, writes the artifact, annotates, then appends to the message array |
| **Cancellation** | An `AbortSignal` per conversation, tripped by budget, turn bound, or stop condition |

### 5.3 Stop conditions

- **Success** — the Axiom invariant passes with full provenance, and the targeted benchmark
  class is covered.
- **Limit** — token, turn or (where priced) USD ceiling reached.
- **No progress** — a stall, defined below.

### 5.4 Stall detection is measured in executed work

A loop that is still ticking is not a loop that is working. Stall detection therefore keys on
**work that actually executed**, never on liveness, elapsed time, or the model still producing
text. A beat is **stalled** if any of these hold:

| Condition | Env knob |
|---|---|
| Fewer than *n* **succeeded** tool executions in the beat | `SAHW_STALL_MIN_TOOL_CALLS` |
| Fewer than *n* new hashed artifacts written to the store | `SAHW_STALL_MIN_ARTIFACTS` |
| The same `(tool, arguments)` pair repeated *n* times | `SAHW_STALL_MAX_REPEAT_CALLS` |
| *n* consecutive stalled beats | `SAHW_STALL_MAX_BARREN_BEATS` → abort the run |

**Three invariants the runner must satisfy:**

1. **A phase timeout is a stall, not a completion.** If a phase times out having executed
   nothing, the run is stalled — reporting "not stalled" because the process stayed alive is
   the failure this section exists to prevent.
2. **A stalled run exits non-zero** (`SAHW_STALL_EXIT_CODE`). Exit 0 after producing no work
   is a false success, and a false success is worse than a crash: it is silently trusted.
3. **The orchestrator's `AbortSignal` must trip before the per-phase timeout**
   (`SAHW_PHASE_TIMEOUT_MS` < `SAHW_REQUEST_TIMEOUT_MS`). If the transport times out first,
   the orchestrator never gets to classify the beat and the stall goes unrecorded.

`skills/stall-ambiguity-resolution` and `skills/cognitive-pruning` are how an agent *recovers*
from a stall the orchestrator has already detected — they are not the detector.

Human involvement is minimal and non-blocking: authorization at the start, and a queue of
`NEEDS_REVIEW` escalations. Everything inside L2 runs unattended.

---

## 6. The four-layer verification engine

Findings pass four sequential, adversarial layers. Each layer can only downgrade.

### Layer 1 — Hypothesis validation (read-only)

Filters implausible claims before anything is fired at the target. **No execution, no
network** — read/grep/glob over recovered artifacts only.

The grey-box `file:line` taint chain does not exist black-box. The equivalent evidence is
**client-intel**: served JS bundles, source maps, the request envelope the client builds,
gadget shapes, crypto routines, observed response differentials. A claim citing neither
recovered client-intel nor an observed differential is downgraded, not tested.

### Layer 2 — Dynamic exploit verification

Two agents, strictly separated:

1. **`exploit-constructor`** — shell on an isolated network segment, plus `mcp-oast`. Takes
   the hypothesis, maps it to an entry point, builds the minimal PoC, and captures **both**
   an exploit request and a **control request**.
2. **`adjudicator`** — **no execution tools at all.** Rules only on the captured artifacts.
   Its default stance is *false positive* until the evidence convinces it.

### Layer 3 — Hybrid replay: autonomous proposal, deterministic decision

The layer that kills false positives, deliberately split.

| Half | Who | What it does |
|---|---|---|
| **Autonomous** | GLM 5.3 | *Proposes* the invariant, interprets transforms (encoding, truncation, case-folding, timing), selects the control request, and routes the claim. It **never renders the pass/fail.** |
| **Deterministic** | Orchestrator code | Re-runs the exact exploit request **and** the control in a clean sandbox and mechanically evaluates the typed invariant. Its output is the verdict. |

Invariant types are exactly those in `docs/schemas/finding.schema.json`:
`body_contains` · `status_in` · `derived` · `state_changed` · `state_violated` ·
`file_created_then_deleted`.

Two properties make this the black-box equivalent of a proof. **Control-differential:** the
exploit and a benign control run against the same state, and a finding is real only if they
*differ* as the invariant predicts — which separates a genuine file read from an error page
that happens to contain the string. **Idempotent replay:** a replay that does not reproduce
yields `NEEDS_REVIEW`, never `CONFIRMED`.

Formal model checking (CBMC/KLEE) is **not** part of this architecture — it requires C/C++
source, and the engagement is black-box.

### Layer 4 — Independent parallel adjudication

Mitigates judgment variance: 3–5 **independent** adjudicator conversations receive the same
finding payload with no shared context. **Consensus is computed deterministically by the
orchestrator**, never by a model.

Verdicts use the existing schema enum — no new values are introduced:

| Verdict | Meaning | `decided_by` |
|---|---|---|
| `CONFIRMED` | Invariant passed on replay, provenance complete | `axiom_deterministic` |
| `FALSE_POSITIVE` | Invariant failed, or control matched exploit | `axiom_deterministic` \| `adjudicator_escalation` |
| `NEEDS_REVIEW` | Environmental block, replay non-reproducible, split consensus, or missing provenance | `adjudicator_escalation` \| `human` |
| `BLOCKED` | Tether refused; the test was never run | `axiom_deterministic` |

Informational observations are recorded as artifacts, **not** as findings — this is the
mechanism that keeps the rubric's two non-reproducible observations out of the report.

**Blind vulnerabilities.** `oast_register` / `oast_poll` are granted to `exploit-constructor` **only**: register
a callback, inject, poll for the out-of-band interaction. The correlation is the invariant.

---

## 7. Tool registry, agents, and capability

### 7.0 The canonical tool registry

These are the only function tools that exist. Every name below is a JSON function schema sent
in the request's `tools` array; the orchestrator implements each one, and the Tether gates
every call before execution. **There is no ambient capability** — an agent whose `tools` array
omits `shell_exec` has no shell, and no prompt can conjure one.

| Tool | Does | Granted to |
|---|---|---|
| `http_request` | One scoped HTTP request; host/port checked against the engagement allowlist | recon, client-intel, state-mapper, exploit-constructor |
| `read_artifact` | Read a stored artifact or sandbox file | all agents |
| `grep_artifact` | Search stored artifacts | most agents |
| `glob_artifact` | List stored artifacts | recon, client-intel, threat-model, adjudicator |
| `write_file` | Write **inside the sandbox only** — never target-facing | client-intel, exploit-constructor |
| `shell_exec` | Run a command in the isolated sandbox; destructive-AST checked | **exploit-constructor only** |
| `skill_run` | Dispatch one of the 36 skills, resolved against the caller's `skills` allowlist | all but core, threat-model |
| `graph_query` | Named, parameterised, **read-only** Cypher against the engagement graph | threat-model, stateful-prober, chain-reasoner |
| `patt_search` | MCP `mcp-patt` — payload corpus retrieval | novelty-synthesizer |
| `oast_register` / `oast_poll` | MCP `mcp-oast` — out-of-band callback registration and polling | **exploit-constructor only** |

### 7.1 Agent registry

Agent definitions live in `docs/agents/*.md`. Their frontmatter is the request shape, not a
framework config: `model`, `temperature`, `tools` (the literal `tools` array), `skills` (the
`skill_run` allowlist), and `sandbox` (container posture the Tether enforces). There is no
`mode` and no `permission` block — **capability is the `tools` array and nothing else.**
`core.md` (`kind: preamble`) is prepended as the first `system` message of every agent.

| Agent | Source prompt | Tools (`tools` array) | Skills allowed | Emits | Touches target |
|---|---|---|---|---|---|
| `core` | `SAFE_AI_HACKER_CORE_SYSTEM_PROMPT` | — | — | shared preamble | — |
| `recon` | Core Phase 1 | `http_request`, `read_artifact`, `grep_artifact`, `glob_artifact`, `skill_run` | `tech-fingerprinting`, `intelligent-crawling`, `scope-discipline` | recon-map JSON | yes (HTTP, Tether-gated) |
| `client-intel` | Core Phase 1 | `http_request`, `read_artifact`, `grep_artifact`, `glob_artifact`, `write_file`, `skill_run` | `js-spa-reverse`, `credential-secret-custody` | client-intel JSON | yes (HTTP) |
| `state-mapper` | Core Phase 1 | `http_request`, `read_artifact`, `grep_artifact`, `skill_run` | `account-role-acquisition`, `privilege-matrix-mapping`, `token-session-forensics` | state-machine JSON | yes (HTTP) |
| `threat-model` | `THREAT_MODEL_PROMPT` | `read_artifact`, `grep_artifact`, `glob_artifact`, `graph_query` | — | per-endpoint strategies | **no** |
| `novelty-synthesizer` | `NOVELTY_SYNTHESIZER_PROMPT` | `read_artifact`, `grep_artifact`, `patt_search`, `skill_run` | `payload-mutator`, `waf-evasion-mastery`, `technique-combinator` | payload + proposed invariant | **no** |
| `stateful-prober` | `STATEFUL_LOGIC_PROBER_PROMPT` | `read_artifact`, `grep_artifact`, `graph_query`, `skill_run` | `business-logic-state`, `auth-bypass-battery`, `idor-bola-access-control` | step sequence + invariant | **no** |
| `chain-reasoner` | `CHAIN_REASONER_PROMPT` | `read_artifact`, `graph_query`, `skill_run` | `chain-construction`, `blast-radius-estimation` | chain artifact | **no** |
| `exploit-constructor` | Core Phase 3 | `shell_exec`, `http_request`, `read_artifact`, `write_file`, `oast_register`, `oast_poll`, `skill_run` | the offensive batteries (`sqli-*`, `xss-*`, `ssrf-*`, `deserialization-rce`, `injection-battery-*`, `file-upload-path-traversal`, `exploit-*`) | PoC + evidence + finding | **yes** |
| `adjudicator` | Core / Axiom | `read_artifact`, `grep_artifact`, `glob_artifact`, `skill_run` | `adversarial-self-review`, `severity-calibration`, `poc-hardening-self-verification` | verdict | **no** |

**Invocation rule:** agents do not spawn each other. The orchestrator dispatches. The finder
cannot reach the adjudicator, and the adjudicator cannot reach the finder.

### 7.2 Skills — compatible as-is, no re-authoring

Each of the 36 skills is self-contained: `SKILL.md` (with `allowed-tools` frontmatter and its
own `references/artifact.schema.json`) plus `scripts/run.py`, which takes JSON in and emits a
strict JSON artifact on stdout, raw logs offloaded to a spill store. That shape is already a
function tool, so one generic tool serves all of them:

```
skill_run(skill_name: string, input: object) -> artifact JSON
```

The orchestrator resolves `skill_name` against the calling agent's skill allowlist (the table
above), executes `scripts/run.py` inside the agent's sandbox, validates the result against
that skill's artifact schema, and hashes it into the artifact store. A skill's own
`allowed-tools` frontmatter is enforced by the Tether as a second boundary. **No plugin layer
and no skill rewriting is required.**

### 7.3 Class coverage routing

Every `vuln_class` in `finding.schema.json` must have a path to `CONFIRMED` — a discovering
agent, an executing skill, and an invariant type that can mechanically prove it. This table
is the completeness check; a class with no row is a class the pipeline structurally cannot find.

| `vuln_class` | Discovered by | Executed by (skill) | Invariant type |
|---|---|---|---|
| `path_traversal` | `threat-model` → `novelty-synthesizer` | `file-upload-path-traversal` | `body_contains` (vs control) |
| `xxe` | `threat-model` → `novelty-synthesizer` | `injection-battery-xxe-ssti-nosql` | `body_contains` |
| `sqli` | `threat-model` → `novelty-synthesizer` | `sqli-database-injection` | `body_contains` (DB identity metadata only) |
| `idor` | `state-mapper` → `stateful-prober` | `idor-bola-access-control`, `privilege-matrix-mapping` | `state_violated` |
| `deserialization_rce` | `client-intel` (gadget) → `threat-model` | `deserialization-rce`, `exploit-sandbox-programming` | `file_created_then_deleted` |
| `business_logic` | `state-mapper` → `stateful-prober` | `business-logic-state` | `state_changed` |
| `auth_bypass` | `state-mapper` → `stateful-prober` | `auth-bypass-battery`, `account-role-acquisition` | `state_changed` / `state_violated` |
| `crypto_disclosure` | `client-intel` (crypto routines) | `credential-secret-custody`, `js-spa-reverse` | `derived` |
| `jwt_weak_key` | `client-intel` → `state-mapper` | `token-session-forensics` | `derived` |
| `rate_limit_absence` | `state-mapper` → `stateful-prober` | `business-logic-state` | `status_in` (no lockout status after N failures; the control still succeeds) |
| `cors_misconfig` | `recon` | `tech-fingerprinting` | `body_contains` (response headers) |
| `info_disclosure` | `recon`, `client-intel` | `intelligent-crawling`, `js-spa-reverse` | `status_in` / `body_contains` |
| `ssrf` | `threat-model` → `novelty-synthesizer` | `ssrf-internal-pivot`, `oob-blind-vuln-correlation` | `derived` (OAST correlation) |

Two classes are deliberately hard. **Blind classes** (`ssrf`, blind injection) reach
`CONFIRMED` only through an OAST correlation — **no callback means no finding**, which is
exactly where an over-eager pipeline manufactures a false positive. **`deserialization_rce`**
needs a client-intel gadget *and* a self-deleting PoC; `file_created_then_deleted` is what
makes the proof both convincing and L2-safe, demonstrating execution while leaving nothing
behind. `exploit-safety-auditor` reviews that PoC before it runs.

---

## 8. Neo4j — the attack graph

Recon output is a graph, and the chains the benchmark asks for are *paths through it*. Storing
the surface as a graph is what turns chain construction from creative guessing into traversal.

### Node labels

| Label | Key properties |
|---|---|
| `:Endpoint` | `url`, `method`, `auth_required`, `semantic_role` |
| `:Parameter` | `name`, `location`, `observed_type` |
| `:Account` | `handle`, `role`, `self_registered` |
| `:Secret` | `secret_ref` (**handle only — never a value**), `type`, `source` |
| `:Finding` | full `finding.schema.json` body: `finding_id`, `vuln_class`, `verdict.status`, `severity.band` |
| `:Chain` | `chain_id`, `chained_severity`, `verdict.status` |
| `:GroundTruth` | benchmark id — **not in this database**; see the isolation note below |

### Relationships

```
(:Endpoint)-[:HAS_PARAM]->(:Parameter)
(:Account)-[:CAN_REACH]->(:Endpoint)
(:Finding)-[:AFFECTS]->(:Endpoint)
(:Finding)-[:YIELDS]->(:Secret)
(:Secret)-[:UNLOCKS]->(:Endpoint)
(:Finding)-[:STEP_OF {step_number}]->(:Chain)
```

### Answer-key isolation (a boundary, not a promise)

`:GroundTruth` nodes and `(:Finding)-[:COVERS]->(:GroundTruth)` edges live in a **separate
Neo4j database that the execution plane holds no credential for**. The engagement graph and
the coverage graph are different connections: agents reach the engagement database through
`graph_query`; only the post-run benchmark harness holds the coverage credential, and it
writes findings *into* coverage, never the reverse.

This is deliberate. The benchmark file warns that the answer key must not reach the runtime,
and a comment saying "agents must not read this" is not an enforcement mechanism — a missing
credential is.

### Write and read model

Writes go through `session.executeWrite` with `MERGE`, so a beat that re-observes the same
endpoint is idempotent and beats compose rather than duplicate:

```
MERGE (e:Endpoint {url: $url, method: $method})
  ON CREATE SET e.first_seen = $utc
SET e.auth_required = $authRequired
```

Reads go through `graph_query`: **parameterised, read-only, named** Cypher. Agents choose a
query by name and supply arguments; they never author Cypher. Two queries carry the chain work:

- **Secret-reachability** — `(:Finding)-[:YIELDS]->(:Secret)-[:UNLOCKS]->(:Endpoint)`,
  which surfaces "a confirmed finding produced material that opens a surface we have not
  exploited yet".
- **Privilege-crossing** — an `:Endpoint` reachable by two distinct `:Account` nodes where a
  confirmed finding already affects it, which is where cross-user violations fall out.

The `chain-reasoner` receives these **path results** and assembles them into a
`chain.schema.json` artifact; the Axiom then replays each step in order, and any failed step
marks the chain `BROKEN` with `failed_step` set. `missing_links` on a chain feed straight back
into the threat-model hypothesis queue — that is the graph closing the loop.

---

## 9. Langfuse — observability and the trace spine

`NodeSDK` + `LangfuseSpanProcessor` + `observeOpenAI` (see the appendix) capture every model
and tool call without threading a logger through the orchestrator. `sdk.shutdown()` is
required — batched spans are lost at exit otherwise.

| Level | Span |
|---|---|
| Trace | one per **beat**, tagged `engagement_id`, `phase`, `milestone` |
| Span | one per agent turn — system-prompt hash, `tools` array, `usage`, cost |
| Span | one per tool call — Tether decision, command, exit code, `stdout_sha256` |
| Score | the Axiom verdict and, after the run, the benchmark coverage result |

The `langfuse_trace_id` is written into every finding's `provenance` block. That id is what
makes a finding auditable end to end — and what the Provenance Gate checks.

---

## 10. The Provenance Gate

Non-negotiable. A verdict may be `CONFIRMED` **only** if all of the following are present and
internally consistent:

1. The exact exploit request **and** the control request.
2. The verbatim, unmodified stdout/stderr — no summary, no paraphrase.
3. `provenance.stdout_sha256` matching the artifact in the content-addressed store.
4. `provenance.sandbox_id` and `provenance.exit_code`.
5. `provenance.langfuse_trace_id` resolving to a real trace.

Anything missing or inconsistent → `NEEDS_REVIEW`. This is **deliberately stricter than the
schema**, which only *requires* `utc`, `stdout_sha256` and `sandbox_id`: a record can be
schema-valid and still fail the gate. The schema defines a well-formed finding; the gate
defines a believable one. It exists to prevent one failure mode — **placeholder or
model-generated text mistaken for real tool output.** A finding whose evidence cannot be
traced to a hashed artifact produced by a recorded command did not happen.

### 10.1 The learning loop

A `FALSE_POSITIVE` verdict is an asset. Its underlying pattern is extracted into a
**per-engagement, version-controlled suppression library**, injected on subsequent runs as a
system-prompt fragment. **A suppression rule may only be written from a finding that itself
passed the Provenance Gate** — otherwise the system would learn to suppress real bugs from
imagined evidence.

---

## 11. Security, isolation, reliability

The harness is pointed at hostile input by definition, and the SDK defaults are wrong for this
workload. Both are handled by explicit settings, not by convention.

| Concern | Position |
|---|---|
| Execution | Ephemeral container per agent/iteration; no route to internal networks, no orchestrator credentials mounted, disposable after the beat |
| Credentials | `prod`: short-lived per-engagement credential from the AI Gateway. `test`: `OPENROUTER_API_KEY`. Never hardcoded, never in the workspace, never in a trace |
| Profile as scope | `test` routes engagement traffic through a third party — permitted only where the RoE allows it (§4.1) |
| Secrets | Only `{{secret:ref}}` handles in prompts, graph, traces and reports; resolved inside the sandbox at execution time |
| MCP | Version-pinned and audited; custom tools preferred over third-party plugins; least-privilege, scoped to the target |
| Blast radius | Mutations restored and the restoration verified before a finding closes |
| Timeout | SDK default 600 000 ms is far too short. `SAHW_REQUEST_TIMEOUT_MS`, with the orchestrator `AbortSignal` tripping **first** (§5.4) |
| Retries | SDK default is 2. `SAHW_MAX_RETRIES=0` — the orchestrator owns retry policy, since a retried tool call re-executes against the target |
| Streaming | Progress only. The terminal non-streamed response is the data of record |
| Budget | `usage` per completion; ceilings in **tokens and turns**, USD only where the profile is priced, so `cost: 0` cannot disable the stop |

---

## 12. Benchmark harness

Runs **after** the engagement, outside every agent context. It reads the pipeline's
`CONFIRMED` findings and chains, joins them to `docs/bench/human-test-benchmark.md`, writes
`(:Finding)-[:COVERS]->(:GroundTruth)` edges into the **separate coverage database** (§8), and
emits the coverage JSON whose shape is defined in the benchmark file (`coverage[]`,
`false_positives[]`, `summary`).

A ground-truth id is `covered` only when the matched finding has the **same `vuln_class`**, a
**matching endpoint**, and a **passing invariant of the expected type**. Same class on the
right endpoint with the wrong invariant type is `partial`, not `covered` — because the
invariant is the proof.

The harness also asserts the negative cases: the two non-reproducible observations and the
four positive controls must **not** appear among the confirmed findings. Each one that does
is counted as a false positive.

---

## 13. Roadmap

Phases are gated on benchmark milestones, not on calendar time.

| Phase | Build | Exit gate |
|---|---|---|
| **1 — Orchestrator & finding loop** | OpenAI TS client → SageMaker GLM 5.3; outer loop (turns, budget, cancellation); Tether dispatch wrapper with scope allowlist; artifact store; `recon` / `client-intel` / `state-mapper` in containers; Langfuse wired | Recon map + client-intel produced for an in-scope target, every tool call traced and Tether-gated |
| **2 — Verification core** | `threat-model`; Layer 1 hypothesis validator; `exploit-constructor` / `adjudicator` pair; Layer 3 deterministic replay + control-differential; Provenance Gate; `mcp-oast` | **M0** — one unauthenticated, single-request class reaches `CONFIRMED` with full provenance |
| **3 — Graph & consensus** | Neo4j attack graph + named `graph_query` reads; `stateful-prober`; `chain-reasoner`; Layer 4 parallel adjudication with deterministic consensus | **M1–M4** — unauthenticated info-disclosure, authenticated single-request, and business-logic classes covered; self-registration of ≥2 accounts working |
| **4 — Chains & hardening** | Chain replay and per-step verdicts; suppression library from provenance-gated false positives; benchmark harness; red-team the orchestrator itself (isolation, credential scoping, tool-gating) | **M5–M6** — the deserialization class covered and both ground-truth chains `CONFIRMED`; false positives at zero |

---

## 14. Appendix — client and a capability-bounded call

```ts
import OpenAI from "openai";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { LangfuseSpanProcessor } from "@langfuse/otel";
import { observeOpenAI } from "@langfuse/openai";

const sdk = new NodeSDK({ spanProcessors: [new LangfuseSpanProcessor()] });
sdk.start();

// One client, two profiles (§4.1). Nothing below this line knows which provider is live.
const profile = resolveProfile(process.env.SAHW_PROFILE ?? "test");  // baseURL, key, models, pricedPerToken

const client = observeOpenAI(
  new OpenAI({
    baseURL: profile.baseURL,
    apiKey:  profile.apiKey,
    timeout: Number(process.env.SAHW_REQUEST_TIMEOUT_MS),  // SDK default 600_000 is too short
    maxRetries: Number(process.env.SAHW_MAX_RETRIES),      // 0 — orchestrator owns retries
  }),
  { traceName: "sahw-beat", sessionId: engagementId, tags: [profile.name] }
);

// The adjudicator's capability boundary IS this tools array.
const verdict = await client.chat.completions.create(
  {
    model: profile.models.REASONING_MODEL,   // logical name → profile-resolved slug
    messages: [
      { role: "system", content: CORE_PREAMBLE + ADJUDICATOR_INSTRUCTIONS },
      { role: "user", content: JSON.stringify(findingPayload) },
    ],
    tools: [readArtifactTool, grepArtifactTool],   // no shell, no write, no http, no oast
    parallel_tool_calls: false,                    // one observable, gateable step at a time
    response_format: { type: "json_object" },      // validated against finding.schema.json
  },
  { signal: beat.abortSignal }
);

await sdk.shutdown();   // flush batched spans
```

---

## Changelog

**v2 (this document)** replaces v1, which ran on the OpenCode SDK (`@opencode-ai/sdk`) with an
`opencode.json` config. That file is deleted and the agent frontmatter is rewritten from
OpenCode's schema (`mode`, `permission`, tool toggles) to the OpenAI SDK request shape
(`tools`, `skills`, `sandbox`). Target, hard constraints, prompts, skills and artifact schemas
are unchanged — only the runtime moved. OpenRouter is **not** gone: v1 used it as the primary
router, v2 keeps it as the `test` profile (§4.1). What v1 got wrong was binding the *runtime*
to OpenCode, not the choice of router.

---

## Related

`docs/PROMPTS.md` (canonical prompts) · `docs/agents/*.md` (agent instructions) ·
`docs/schemas/{finding,chain}.schema.json` (artifact contracts) ·
`docs/bench/human-test-benchmark.md` (the scorecard — **harness only, never an agent input**) ·
`skills/` (36 skills, surfaced through `skill_run`).

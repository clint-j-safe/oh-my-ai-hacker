# SAFE AI Hacker — Design Spec

**Date:** 2026-09-22. **This phase ships docs + prompts only** (no code, no run).
**Goal:** a fully autonomous, black-box web pentest system that independently rediscovers the
`human-test/` findings — one win at a time.

## Principle
Loop Engineering: **the LLM proposes; deterministic code decides.** Every agent output is a
proposal; deterministic code decides whether to act and whether a result is a finding.

## Hard constraints
1. **Black-box, nothing hardcoded** — no engagement endpoints/paths/payloads/hosts/creds in
   agents, config, or scope. `human-test/` is a grading rubric only (never fed to agents).
2. **Input = in-scope URLs (± credentials).** Credentials are optional. In pure black-box mode
   (no creds — the current focus), the system **self-registers ≥2 disposable accounts through the
   target's own signup flow** to reach the authenticated and cross-user surface — exactly how the
   `human-test` engagement did it. Provided creds are just a shortcut. **All findings** (unauth +
   authenticated + chains) are in scope for coverage.
3. **Scope = exactly the provided URLs** — no port scanning, no subdomain enum, no CT/passive-DNS.
   HTTP(S) only, on the given hosts+ports.
4. **Safety (L2 read-only/reversible)** — no DoS, destructive writes, persistence, or real-PII
   exfil; mutations restored.
5. **Self-contained deciders** — deterministic code + a configurable judge model (via the
   provider block) for fuzzy calls only. **jev is not in the framework.**
6. **Provenance gate** — no `CONFIRMED` without trace id + exact request + stdout SHA-256 + sandbox id.

## Architecture
```
HEARTBEAT   cron / Routine / GitHub event / cloud runner  → starts each beat (no human prompt)
CONTROL PLANE (TypeScript, @opencode-ai/sdk) = the Big Loop
  Orchestrator      phase state machine (1→2→3→4), no LLM in phase control
  Session Manager   session.create / prompt / abort per phase|endpoint
  Budget            AssistantMessage.cost + .tokens → abort on breach
  Spine             progress + rules files, read first / updated last each beat
  Artifact Store    content-addressed (SHA-256) + audit.sh-style provenance
  AI Hacker Axiom   verdict — deterministic invariant replay (+ judge for fuzzy calls)
EXECUTION ENGINES (opencode serve, per-agent Docker + disposable volumes) = Small Loops
  Agents            .opencode/agents/*.md (see below)
  Skills-as-tools   opencode-skills over ./skills (36 skills, reused)
  Plugins           AI Hacker Tether (tool.execute.before: deterministic scope + destructive-AST)
                    The Ledger (event → Langfuse + ClickHouse)
  MCP               mcp-patt (payloads), mcp-oast (out-of-band)
OBSERVABILITY  Langfuse + ClickHouse    MODEL ROUTING  OpenRouter (+ SageMaker/GLM fallback+judge)
```
- **AI Hacker Tether** = the scope/safety gate (decides if an action may run).
- **AI Hacker Axiom** = the validation core (decides if a result is a finding).
See `docs/config/opencode.json.md` for the config.

## OpenCode SDK (the backbone — everything runs on it)
The whole control plane is the OpenCode SDK (`@opencode-ai/sdk`); the orchestrator adds only
phase logic on top. Concrete usage:
- **Engines:** each phase runs on an `opencode serve` headless server the orchestrator drives via
  the SDK client.
- **Sessions:** `session.create()` per phase/endpoint (one engagement = one Big Loop over many
  sessions); `session.prompt(...)` / `session.chat(id, {agent, parts, ...})` to run an agent
  against an objective; `session.abort(id)` on budget breach.
- **Budget:** read `AssistantMessage.cost` + `.tokens` from `session.messages(id)` / the event
  stream → the Limit stop.
- **Live telemetry & control:** subscribe to `event.subscribe` (SSE) for tool-call and message
  events → The Ledger + provenance.
- **Agents & tools are OpenCode-native:** `.opencode/agents/*.md` frontmatter (`mode`, `model`,
  `temperature`, `permission`, `tools`); the Tether/Ledger plugins hook `tool.execute.before`
  and `event`; `./skills` and MCP servers are surfaced as tools. Provider routing is OpenCode
  `provider` config. Nothing bypasses the SDK.

## Autonomy (Loop Engineering)
- **Beat** = one pass of the Big Loop. **Maker≠checker:** `exploit-constructor` builds a PoC;
  `Axiom`/`adjudicator` approve it — never the same agent.
- **Three stops:** success (Axiom invariant passes w/ provenance; benchmark classes covered),
  limit (USD/turns/tokens), no-progress (stall detection via `stall-ambiguity-resolution` +
  `cognitive-pruning`).
- **Human gate = minimal, non-blocking:** only authorization at start and `NEEDS_REVIEW`
  escalations (queued). Everything within L2 runs unattended.

## Agents (`docs/agents/*.md`, target-agnostic; `core.md` prepended to each)
| Agent | Source (docs/PROMPTS.md) | Emits | Touches target |
|---|---|---|---|
| `core` | CORE_SYSTEM_PROMPT | shared preamble | — |
| `recon` / `client-intel` / `state-mapper` | Core Phase 1 | recon-map / client-intel / state-machine JSON | HTTP only, Tether-gated |
| `threat-model` | THREAT_MODEL_PROMPT | per-endpoint strategies | no (proposes) |
| `novelty-synthesizer` | NOVELTY_SYNTHESIZER_PROMPT | payload + invariant | no (proposes) |
| `stateful-prober` | STATEFUL_LOGIC_PROBER_PROMPT | step sequence + invariant | no (proposes) |
| `chain-reasoner` | CHAIN_REASONER_PROMPT | chain | no (proposes) |
| `exploit-constructor` | Core Phase 3 | PoC + evidence + finding | yes (isolated, gated) |
| `adjudicator` | Core / Axiom | verdict | no (reads evidence) |

Outputs conform to `docs/schemas/{finding,chain}.schema.json` (same shape as the existing
`skills/*/references/artifact.schema.json`).

## Roadmap (future build — not this phase)
1. Scaffolding (orchestrator on `@opencode-ai/sdk`, `opencode.json`, Docker, Spine, Artifact Store).
2. Observability (Ledger → Langfuse; ClickHouse `findings_telemetry`).
3. Agents + Tether + Axiom + mount `./skills`.
4. Phase 1 recon (HTTP-only, from `inScopeUrls`) + self-register ≥2 disposable accounts (black-box)
   or load provided creds.
5. Phase 2 discovery (threat-model → synthesizer/prober; PATT + OAST).
6. Phase 3 exploitation + Axiom verdict + provenance gate.

**Milestones (one win at a time):** M0 = one unauthenticated single-request class (path traversal
or XXE); then broaden to the full `human-test/` set + the two chains, per
`docs/bench/human-test-benchmark.md`.

## Related
`docs/PROMPTS.md` (canonical prompts) · `docs/agents/*` · `docs/config/opencode.json.md` ·
`docs/schemas/*` · `docs/bench/human-test-benchmark.md`.

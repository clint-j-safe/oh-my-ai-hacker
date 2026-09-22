# Orchestrator (SAFE AI Hacker)

The thinnest end-to-end path that takes in-scope URLs and produces one `CONFIRMED`
finding with full provenance: the agent loop (`agent.ts`), the Tether-gated tools
(`tools.ts` + `tether.ts`), the control-differential Axiom (`axiom.ts`), the
Provenance Gate (`provenance.ts`), stall detection (`stall.ts`), and optional
writes to Langfuse, ClickHouse and Neo4j (`obs/`).

## Install

```bash
npm install
```

## Test

```bash
npm test
```

Runs `tsc --noEmit` first (a type error fails the suite), then Node's built-in
test runner via `tsx --test`. Tests never contact an external host or a live
model — the OpenAI client is stubbed and HTTP goes through an injected `fetch`.

## Dry run

```bash
npm start -- --dry-run
```

Prints the resolved scope and profile and exits 0 without contacting anything.

## Run

```bash
cp ../.env.example .env   # fill in SAHW_SCOPE, SAHW_AUTH_*, and a provider key
npm start
```

### Knobs it reads

Everything comes from `.env` (see `.env.example` for the full contract). The
load-bearing ones:

| Knob | Meaning |
|---|---|
| `SAHW_SCOPE` | comma-separated in-scope URLs — **the** allowlist |
| `SAHW_OUT_OF_SCOPE` | explicit denies, applied after scope |
| `SAHW_AUTH_REF` | authorization reference (required) |
| `SAHW_AUTH_START` / `SAHW_AUTH_END` | authorization window (a run outside it refuses to start) |
| `SAHW_PROFILE` | `test` (OpenRouter) or `prod` (SageMaker) |
| `SAHW_MODEL` | model slug |
| `SAHW_MAX_TURNS` | assistant turns per agent conversation |
| `SAHW_BUDGET_TOKENS` | token ceiling per beat (from `usage`) |
| `SAHW_REQUEST_TIMEOUT_MS` | per API request timeout |
| `SAHW_PHASE_TIMEOUT_MS` | phase timeout; **must stay below** `SAHW_REQUEST_TIMEOUT_MS` |
| `SAHW_MAX_RETRIES` | SDK retry count (orchestrator owns retry policy) |
| `SAHW_STALL_*` | executed-work stall thresholds and `SAHW_STALL_EXIT_CODE` (default 3) |

### The three stores are optional

If `LANGFUSE_*`, `CLICKHOUSE_DSN` or `NEO4J_URI` is unset, the corresponding
writer becomes a no-op and the run still completes. Local development does not
require any of them.

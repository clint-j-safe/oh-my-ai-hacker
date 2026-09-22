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

**Consequence of Langfuse being optional:** the Provenance Gate (`provenance.ts`)
requires a real `langfuseTraceId` as evidence that a finding is traceable. When
Langfuse is unconfigured (or its tracer provider isn't active), `obs.traceId()`
returns `null` — never a placeholder — and the gate correctly downgrades an
otherwise-`CONFIRMED` finding to `NEEDS_REVIEW`. **This is deliberate, not a bug:**
a finding claiming full provenance without a real trace behind it is exactly the
"placeholder mistaken for real provenance" failure the gate exists to catch. If you
want `CONFIRMED` findings, configure `LANGFUSE_PUBLIC_KEY` and
`LANGFUSE_SECRET_KEY` (and reach a real Langfuse host).

## Observability (Langfuse)

Every beat opens one Langfuse trace named `sahw-beat`, grouped into a Langfuse
**session** keyed by the engagement's `SAHW_AUTH_REF` — so repeated beats for the
same engagement show up as one session. Within a beat's trace:

- `tool:<name>` — one child span per tool dispatch (`http_request`, `read_artifact`),
  recording the parsed arguments as input and, on success, `status`, full response
  headers, `body_bytes`, `artifact_sha256` and `ms` as output (never the response
  body itself — see the Offload Law in `agent.ts`). A denied call's output carries
  its `kind` (`policy`, `no_executor`, `invalid_argument`, `execution_error`) and
  `denied` reason, so a Tether policy denial is clearly visible as the security
  event it is.
- `stall-check` — input: succeeded tool calls, new artifacts, per-call repeat
  counts; output: `stalled` and `reason`.
- `axiom-eval` — input: the invariant plus exploit/control status codes; output:
  verdict `status` and `reason`.
- `provenance-gate` — input: which provenance fields were present; output: final
  `status` and the `missing` list.
- Every OpenAI call made through the CLI's `observeOpenAI`-wrapped client shows up
  as a `generation` (prompt, completion, token counts, cost) nested under the beat.

Secrets never reach telemetry: `Authorization`, `Cookie` and `Set-Cookie` header
**values** are redacted to `<redacted>` in span input/output; the header **names**
are kept, since their presence alone is useful signal.

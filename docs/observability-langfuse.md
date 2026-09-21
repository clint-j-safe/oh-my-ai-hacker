# Observability — Langfuse tracing

How SAFE AI Hacker (SAHW) scan runs are traced into Langfuse, what the trace
tree looks like, how it's deployed on the remote host, and the known gaps.

Last verified: 2026-09-21 on `root@143.244.130.163`.

---

## TL;DR — where to look

- **UI:** `http://143.244.130.163:3000` → project **`sahw-control-plane`** → **Sessions**.
- Each scan run is its **own session** named `‹SAHW_AUTH_REF›/‹run-stamp›`
  (e.g. `ENG-2026-168.144.155.177/2026-09-21T22-54-55-764Z-hzcw`).
- Each session holds **one trace** (`sahw-recon`) whose tree is:
  - root `sahw-recon` (app root)
    - `turn-0` … `turn-N` — one **generation** per LLM call (prompt in / completion out / model / token usage)
    - `tool:http_request` / `tool:run_command` — one **span** per tool call (args in / result out)
    - `axiom:verify` — one **span** per finding verification (finding in / verdict out)

---

## Architecture

```
scan-cli (node dist/scan-cli.js)
  └─ scan()                         src/scan.ts
       └─ LangfuseTracer.traceTree(root, fn)     src/langfuse.ts   ← opens the root trace
            └─ LlmRunner.run(agent, objective, rec)   src/llm-runner.ts
                 └─ runAgentLoop({ …, rec })     src/agent-loop.ts ← emits child spans
                      • per turn  → rec.generation("turn-N", {input,output,model,tokens})
                      • per tool  → rec.toolSpan("tool:NAME", {input,output})
            └─ axiom.verify(finding)             src/axiom.ts
                      • per finding → rec.toolSpan("axiom:verify", {input,output})
```

- **Tracer:** `src/langfuse.ts` uses the official Langfuse **JS/TS v5 SDK**
  (`@langfuse/otel` + `@langfuse/tracing` + `@opentelemetry/sdk-node`), OTel-based.
  - `LangfuseSpanProcessor({ baseUrl, publicKey, secretKey })` → `NodeSDK`.
  - `traceTree(root, fn)` wraps the run in a root `startActiveObservation`, sets
    trace-level I/O via `setActiveTraceIO`, propagates `sessionId`/`metadata`/`traceName`
    via `propagateAttributes`, and hands `fn` a `SpanRecorder` that creates nested
    child observations (`generation` / `toolSpan`). Nesting works because children
    are created inside the root's active OTel context.
  - Resilience: per-span errors and scaffolding failures are swallowed and logged
    (`[langfuse] …(non-fatal)`); the scan runs **exactly once** regardless (run-once
    guard), and a real error inside the scan still propagates.
  - Flush: `flush()` calls `processor.forceFlush()` (not `shutdown`) so the tracer
    stays usable and a short-lived container exports before exit.
- **Unique session per run:** `src/scan-cli.ts` builds
  `sessionId = ‹SAHW_AUTH_REF›/‹ISO-stamp›-‹rand›`. Override with `SAHW_RUN_ID`
  for reproducible/CI runs. (Previously the session was just `SAHW_AUTH_REF`, so
  every run collided into one session — fixed.)

---

## Configuration (scan side)

Env consumed by `scan-cli` (from `/opt/sahw-ctx/.env`, passed via `--env-file`):

| Var | Purpose |
| --- | --- |
| `SAHW_LANGFUSE_HOST` | `http://143.244.130.163:3000` |
| `SAHW_LANGFUSE_PUBLIC_KEY` / `SAHW_LANGFUSE_SECRET_KEY` | project API keys (control-plane project) |
| `SAHW_AUTH_REF` | engagement id — prefix of the per-run session |
| `SAHW_RUN_ID` | optional — pin the run id instead of a random stamp |

All three `SAHW_LANGFUSE_*` must be set or tracing is skipped (see `src/config.ts`).

---

## Langfuse deployment (remote host)

Runs on `root@143.244.130.163`, compose project at `/root/langfuse` (self-hosted
**Langfuse v4**, image `langfuse/langfuse:4`).

- **Web/ingest:** `:3000`. **Worker**, **ClickHouse**, **MinIO**, **Redis**, **Postgres**.
- **Write/read mode:** `LANGFUSE_MIGRATION_V4_WRITE_MODE=dual`
  (in `/root/langfuse/docker-compose.override.yml`). Writes to **both** the v4
  `events_*` tables and the legacy `traces`/sessions tables the UI reads.
- **Project routing:** the init project is pinned to the control-plane project in
  `/root/langfuse/.env`:
  - `LANGFUSE_INIT_PROJECT_ID=cu233ya290w4w47f4sefcvxzc`
  - `LANGFUSE_INIT_PROJECT_NAME=sahw-control-plane`
  This keeps the API key mapped to the **`sahw-control-plane`** project across
  restarts (otherwise the init env re-provisioned the key onto `safe-ai-hacker-web`).
- **v4 read experience:** `users.v4_beta_enabled=true` for the console user, so the
  UI reads the events model (in addition to dual-writing legacy).

Ingest path: OTLP → `POST /api/public/otel/v1/traces` (HTTP 200) → blob storage →
worker → ClickHouse `events_core`/`events_full` (+ legacy `traces`) → UI.

> Note: the legacy public read API (`/api/public/traces`, `/api/public/sessions`)
> returns 404 under v4 — that is expected; the UI uses internal (events/legacy) reads.

---

## Deploying a scan-code change to the remote

The remote image is built from `/opt/sahw-ctx` (a copy of the built `dist/` + config).

```bash
# 1. build locally
npm run build

# 2. push dist to the remote context
rsync -az --delete dist/ root@143.244.130.163:/opt/sahw-ctx/dist/

# 3. rebuild the image and run
ssh root@143.244.130.163 'cd /opt/sahw-ctx && docker build -t sahw-scan . \
  && docker run --rm --env-file .env sahw-scan'
```

Verify a run's tree in ClickHouse:

```bash
docker exec langfuse-clickhouse-1 clickhouse-client -q \
"SELECT start_time,name,type,is_app_root FROM default.events_core \
 WHERE session_id='‹the run session›' ORDER BY start_time FORMAT TSV"
```

---

## Known gaps / follow-ups

1. **Media upload fails from the scan container.** Oversized field values
   (full message snapshots, large tool bodies) are offloaded by the SDK to MinIO
   via a presigned URL built from `LANGFUSE_S3_MEDIA_UPLOAD_ENDPOINT=http://localhost:9090`
   — unreachable from inside the container (`TypeError: fetch failed`). Trace
   **structure and smaller fields land fine**; very large prompt/tool values show
   as broken media until fixed.
   **Fix:** set `LANGFUSE_S3_MEDIA_UPLOAD_ENDPOINT=http://143.244.130.163:9090`
   (the host-reachable MinIO) in the langfuse compose and restart `langfuse-web`.
   Alternative: truncate traced input/output in `agent-loop.ts` below the inline
   threshold (loses full fidelity).

2. **Agent/skill-level tracing needs the OpenCode engine.** The deployed scan is
   the direct-LLM path (`LlmRunner`), which has LLM turns + tool calls but no
   OpenCode agents/skills. Full agent/skill spans require deploying an
   `opencode serve` engine (OpenCode v2) with the
   `@langfuse/opencode-observability-plugin` (registered under the v2 `plugins`
   key, `experimental.openTelemetry: true`, `LANGFUSE_*` creds). `opencode.json`
   in this repo is already wired for that; no engine is currently deployed, and
   the SDK↔server route mismatch in `DEPLOYMENT.md` must be resolved first.

3. **Legacy dual-write historic backfill.** Only data ingested from 22:39
   (2026-09-21, when dual mode was enabled) onward is in the legacy tables; older
   events live only in `events_*`. Not an issue going forward.

---

## Change log (2026-09-21 session)

Scan code (`src/`):
- `langfuse.ts` — migrated to the correct v5 SDK API; added `SpanRecorder` +
  `traceTree` (nested tree, run-once/non-fatal); `forceFlush`-based `flush`.
- `agent-loop.ts` — emits a generation per turn and a span per tool call (+ final synthesis).
- `llm-runner.ts` — threads the recorder into the loop.
- `scan.ts` — runs the agent loop + Axiom verification inside `traceTree`.
- `scan-cli.ts` — unique session id per run (`SAHW_RUN_ID` override).
- `opencode.json` — v1 `plugin` → v2 `plugins`, added the Langfuse observability
  plugin + `experimental.openTelemetry` (for the future engine path).

Langfuse deployment (remote), all reversible (backups saved next to each file):
- Removed the redundant Langfuse **v3** stack (`/opt/langfuse3`); data volumes retained.
- Switched write mode `events_only` → **`dual`**.
- Repointed the init project to **`sahw-control-plane`** so the key routes there.
- Enabled `v4_beta_enabled` for the console user.

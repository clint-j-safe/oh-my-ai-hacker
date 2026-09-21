# SAFE AI Hacker — Deployment

## Status

| Component | State |
|---|---|
| Deterministic control-plane core (`src/scope,tether,axiom,artifact-store,budget,orchestrator,sdk-runner,oob,dns`) | ✅ built, 88 unit tests green |
| `opencode.json` + `.opencode/agents/*` + tether/ledger plugins | ✅ authored (black-box clean, no target specifics) |
| CLI (`dist/cli.js`) | ✅ dry-run verified (4-phase loop, budget, typed exit) |
| OOB / reverse-shell listener | ✅ **deployed live** on `root@143.244.130.163` (container `sahw-oob`) |
| Control plane ↔ engine wiring | ⚠️ blocked on SDK/server version alignment (see below) |

## OOB listener (live)

Container `sahw-oob` on `root@143.244.130.163`:

| Service | Host port → container | Purpose |
|---|---|---|
| DNS UDP/TCP | `5353 → 53` (53 on host is held by systemd-resolved loopback) | OAST DNS callback (A-record = 143.244.130.163) |
| HTTP | `80 → 80` | SSRF/XXE callback catcher |
| TCP connect-back | `4445 → 4444` (4444 held by a stale `nc`) | reverse-shell / connect-back catch |

Verified: `dig @127.0.0.1 -p 5353 <canary>.oast.test` → 143.244.130.163; HTTP + TCP callbacks logged with canary correlation.

To re-deploy after a rebuild:
```bash
cd /opt/sahw/oob && docker build -t sahw-oob . && \
docker rm -f sahw-oob && \
docker run -d --name sahw-oob --restart unless-stopped \
  -p 5353:53/udp -p 5353:53/tcp -p 80:80 -p 4445:4444 \
  -e OOB_ANSWER_IP=143.244.130.163 sahw-oob
```

## Build + test (local)

```bash
npm install
npm run build        # -> dist/
npx vitest run       # 88 tests
```

## Known gap — SDK ↔ server version mismatch

`@opencode-ai/sdk@1.18.31`'s generated client targets routes (`POST /session`,
`POST /session/{id}/message`, `POST /session/{id}/abort`) that do **not** match the
installed `opencode` CLI v2.0.12 (anomalyco fork), which serves an "Experimental
HttpApi" under `/api/*` (`POST /api/session`, `POST /api/session/{id}/prompt`,
`GET /api/event`, `POST /api/session/{id}/interrupt`). Verified live: SDK `create`
→ 405, `list` → HTML.

Resolution options (pick one at engine-build time):
1. Pin `opencode` to the version the SDK was generated against.
2. Write a thin `/api` HTTP adapter + SSE consumer matching the installed server
   (`src/sdk-runner.ts` is isolated behind the `AgentRunner` interface precisely so
   this swap is one file).
3. Drive engines via `opencode run -a <agent> "<objective>"` subprocess.

The deterministic core, Tether, Axiom, Budget, ArtifactStore, and Orchestrator are
all independent of this seam and are fully unit-tested.

## Secrets (env / Docker secrets — never in the repo)

`OPENROUTER_API_KEY`, `OPENCODE_SERVER_PASSWORD`, Langfuse keys, ClickHouse DSN.

# SAHW — Operating Guide (setup, running, LLMs, tuning)

SAHW is a black-box exploit-verification loop: **"the LLM proposes; deterministic code
decides."** An LLM hunter proposes probes; every finding is verified by the **Axiom**
(control-differential) and banked with provenance. This guide covers deploying it, running an
engagement, choosing/wiring the LLM, and tuning the parameters.

---

## 1. Architecture (what runs where)

- **Runner host** — a machine (or VPN-connected host for HTB) that can reach the target.
  Holds the source (`/opt/sahw-src`), engagement env files, workspaces, and out dirs
  (`/opt/sahw-run/`). Runs Docker.
- **Orchestrator image** (`sahw-orchestrator`) — one Docker container = one **beat**
  (Node 20 / TS / ESM). It loads the engagement, runs the deep-sweep pre-pass + the LLM
  hunt, verifies via the Axiom, writes findings to the datastores and the spine.
- **Datastores / support services** (long-running containers, NOT restarted per run):
  - **ClickHouse** — `sahw_findings` (the queryable findings table).
  - **Neo4j** — graph of endpoints/findings.
  - **Langfuse** — LLM traces (one trace per beat).
  - **OOB service** — out-of-band callback correlation (DNS/HTTP/shell) for blind/RCE proofs.
- **The Spine** (`<workspace>/spine/progress.json`) — read first, written last, every beat.
  Carries proved findings, attack surface, recovered intel, sessions. Preserve the workspace
  across beats to accumulate state; wipe it for a clean run.

---

## 2. Prerequisites

- Docker on the runner; the support containers up (`docker ps` should show neo4j,
  clickhouse/langfuse, oob).
- Network path to the target. For **HTB**, an OpenVPN tunnel — note the `tun0` IP:
  `ip -4 addr show tun0` → e.g. `10.10.14.111`. Use that as `OOB_ANSWER_IP` so reverse-shell /
  OOB callbacks route back (the target cannot reach the runner's public IP).
- An LLM endpoint + key (OpenRouter for test, SageMaker/gateway for prod — see §5).

---

## 3. Setup — deploy source & build the image

From the repo (local dev machine), ship the source to the runner and build. The Docker build
runs `npm test` as a gate — a red test suite fails the build.

```bash
# 1) archive the relevant trees and extract on the runner
git archive HEAD orchestrator skills > /tmp/sahw-src.tar
scp /tmp/sahw-src.tar root@<RUNNER>:/tmp/sahw-src.tar
ssh root@<RUNNER> 'cd /opt/sahw-src && tar -xf /tmp/sahw-src.tar \
  && docker build -f orchestrator/Dockerfile -t sahw-orchestrator .'
```

Local dev loop (before deploying): `cd orchestrator && npm test` (tsc + node:test/tsx).

---

## 4. Engagement env file

One file per target, e.g. `/opt/sahw-run/<engagement>.env`. Passed with `--env-file`.

```ini
# --- scope & authorization (REQUIRED; fail-closed) ---
SAHW_SCOPE=http://10.129.227.191            # comma-separated origins in scope
SAHW_OUT_OF_SCOPE=                          # optional explicit denies (host:port[/path])
SAHW_IN_SCOPE_CIDRS=                         # optional CIDR allowlist
SAHW_AUTH_REF=ENG-2026-HTB-10.129.227.191    # signed authorization ref (identity of the run)
SAHW_AUTH_START=2026-09-24T00:00:00Z         # run REFUSES outside [start,end]
SAHW_AUTH_END=2026-09-30T00:00:00Z

# --- LLM (see §5) ---
SAHW_PROFILE=test                            # test -> OpenRouter ; prod -> SageMaker/gateway
SAHW_MODEL=z-ai/glm-5.3-flashx               # hunter model id
SAHW_JUDGE_MODEL=                            # optional adjudicator model (blank = disabled)
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
SAHW_OPENROUTER_KEY=sk-or-...                # test-profile key
# SAGEMAKER_BASE_URL= / SAGEMAKER_API_KEY=   # prod-profile endpoint + short-lived key

# --- datastores / observability ---
NEO4J_URI=bolt://127.0.0.1:7688
NEO4J_USER=neo4j
NEO4J_PASSWORD=...
CLICKHOUSE_DSN=http://127.0.0.1:8123         # + CLICKHOUSE_USER/PASSWORD ; CLICKHOUSE_DATABASE (default "sahw")
LANGFUSE_BASE_URL=http://127.0.0.1:3000
LANGFUSE_PUBLIC_KEY=... / LANGFUSE_SECRET_KEY=...

# --- out-of-band (blind vuln / RCE callbacks) ---
OOB_ANSWER_IP=10.10.14.111                   # HTB: the VPN tun0 IP (NOT the public IP)
OOB_DNS_PORT=53
OOB_HTTP_PORT=80
OOB_SHELL_PORT=4444
```

Per-beat overrides (turns, budgets, deep flags) are passed as `-e VAR=...` on `docker run`
(§6) so one env file serves many run shapes.

---

## 5. Choosing & wiring the LLM

Provider is selected by `SAHW_PROFILE` (see `cli.ts`):

| Profile | Base URL | API key | Use |
|---------|----------|---------|-----|
| `test` (default) | `OPENROUTER_BASE_URL` | `SAHW_OPENROUTER_KEY` | OpenRouter — any hosted model |
| `prod` | `SAGEMAKER_BASE_URL` | `SAGEMAKER_API_KEY` | Self-hosted / AI-gateway (short-lived cred) |

- **`SAHW_MODEL`** — the hunter model id (OpenRouter slug, e.g. `z-ai/glm-5.3-flashx`,
  `anthropic/claude-...`, `openai/...`). This is the reasoning driver.
- **`SAHW_JUDGE_MODEL`** — optional pre-gate adjudicator (promotes a deterministic
  NEEDS_REVIEW only when its rubric is clearly met). Blank = disabled (fails open, never
  fabricates a CONFIRMED). `SAHW_AXIOM_JUDGE_THRESHOLD` (default **85**, a 0–100 score) sets its bar.
  (Note: hunter temperature is fixed in code — there is no `SAHW_TEMPERATURE` knob.)
- The Axiom is model-independent: it decides verdicts deterministically over real responses,
  so a weaker/cheaper hunter still cannot produce a false CONFIRMED.

Switch models by editing `SAHW_MODEL` (+ key) in the env file, or `-e SAHW_MODEL=...` per run.

---

## 6. Running an engagement

### Single beat (one container)
```bash
docker run --rm --name sahw-run --network host --env-file /opt/sahw-run/<eng>.env \
  -e SAHW_BEAT_NO=1 -e SAHW_RUN_ID=myrun -e SAHW_WORKSPACE=/workspace \
  -v /opt/sahw-run/ws-myrun:/workspace \
  sahw-orchestrator
```

### Multi-beat loop (breadth accumulates via the spine)
A beat = one bounded pass. Run N beats over the SAME workspace so the spine carries state.
Pattern (write to a `.sh`, `nohup` it):
```bash
for i in $(seq 1 8); do
  docker rm -f sahw-run 2>/dev/null
  docker run --name sahw-run --network host --env-file /opt/sahw-run/<eng>.env \
    -e SAHW_BEAT_NO="$i" -e SAHW_RUN_ID=myrun -e SAHW_WORKSPACE=/workspace \
    -v /opt/sahw-run/ws-myrun:/workspace \
    <per-beat -e flags, see §7> \
    sahw-orchestrator > /opt/sahw-run/beat-$i.json 2>/opt/sahw-run/beat-$i.err
done
```
- `SAHW_RUN_ID` groups beats into one Langfuse session.
- Fresh workspace (`rm -rf ws-...`) = clean run; reuse it = build on prior discovery.
- The **deep-sweep pre-pass + DNS-recon run on beat 1 only** (banked into the spine); later
  beats inherit them and spend turns on the LLM hunt.

---

## 7. Tuning parameters (per-beat `-e` flags)

### Loop budget
| Var | Default | Meaning |
|-----|---------|---------|
| `SAHW_MAX_TURNS` | 40 | LLM turns per beat |
| `SAHW_MAX_TURNS_PER_FINDING` | 8 | turns before it must move to a new class/endpoint |
| `SAHW_MAX_FINDINGS` | 12 | cap on findings/beat |
| `SAHW_MAX_ACCOUNTS` | 2 | disposable accounts the loop may self-register |
| `SAHW_NUDGE_TURNS` | ~60% of per-call turns (min 4) | turns before a "move on" nudge |
| `SAHW_BUDGET_TOKENS` / `SAHW_BUDGET_USD` / `SAHW_BUDGET_TURNS` | — | hard spend caps |

### Timeouts (ordering matters)
| Var | Default | Rule |
|-----|---------|------|
| `SAHW_PHASE_TIMEOUT_MS` | 3,000,000 | per-phase abort — **must be < request timeout** |
| `SAHW_REQUEST_TIMEOUT_MS` | 3,600,000 | transport timeout |
> Config **throws** if `PHASE_TIMEOUT_MS >= REQUEST_TIMEOUT_MS` (the abort must trip before
> the transport, else a stall goes unrecorded). Bump both together for long multi-step probes;
> if the sweep is heavy, keep phase generous so the stateful probes (which run first) finish.

### Deep mode (opt-in; off by default)
| Var | Default | Meaning |
|-----|---------|---------|
| `SAHW_DEEP_MODE` | 0 | 1 = enable the deterministic sweep + attack skills + DNS recon + stateful probes |
| `SAHW_DEEP_SWEEP_BUDGET` | 500 | total sweep requests (round-robin across inputs) |
| `SAHW_DEEP_ESCALATION_DEPTH` | 2 | max escalation/chain depth after a confirm (0 disables chaining). There is **no** separate `SAHW_DEEP_ESCALATE` on/off flag. |
| `SAHW_DEEP_WEAPONIZE` | 0 | 1 = weaponization tier (RCE/shell) — **double-confirmed** |
| `SAHW_DEEP_WEAPONIZE_AUTH_REF` | — | must EXACTLY equal `SAHW_AUTH_REF`, else ConfigError |

> **Weaponize is fail-closed:** `SAHW_DEEP_MODE=0` forces weaponize off; `SAHW_DEEP_WEAPONIZE=1`
> throws unless `SAHW_DEEP_WEAPONIZE_AUTH_REF === SAHW_AUTH_REF` (you name the signed
> authorization twice). Only turn it on for a target you are authorized to get RCE on, and set
> `OOB_ANSWER_IP` to a callback the target can reach (HTB: the `tun0` IP).

### Stall detection (auto-stop barren beats)
`SAHW_STALL_MAX_BARREN_BEATS`, `SAHW_STALL_MAX_REPEAT_CALLS`, `SAHW_STALL_MIN_TOOL_CALLS`,
`SAHW_STALL_MIN_ARTIFACTS`, `SAHW_STALL_EXIT_CODE` — tune when a run should give up.

### Example: "full deep" run
```
-e SAHW_DEEP_MODE=1 -e SAHW_DEEP_WEAPONIZE=1 -e SAHW_DEEP_ESCALATION_DEPTH=2 \
-e SAHW_DEEP_WEAPONIZE_AUTH_REF=<same as SAHW_AUTH_REF> -e SAHW_DEEP_SWEEP_BUDGET=140 \
-e SAHW_MAX_TURNS=54 -e SAHW_MAX_TURNS_PER_FINDING=18 -e SAHW_MAX_FINDINGS=12 \
-e SAHW_MAX_ACCOUNTS=3 -e SAHW_PHASE_TIMEOUT_MS=1100000 -e SAHW_REQUEST_TIMEOUT_MS=1300000
```

---

## 8. DNS recon / virtual hosts (deep mode)

On beat 1, deep mode runs a DNS-recon pre-pass: reverse-DNS/PTR of each scoped IP → base
domain, AXFR zone transfer → subdomains, prefix wordlist appended to discovered/scoped base
domains, each confirmed by a Host-routed differential. Confirmed vhosts are added to
`/etc/hosts` + scope + attack surface so the loop reaches them. No PTR/vhost (like a plain
IP target) → it fails soft and scans the IP directly. Nothing arbitrary — every host traces to
the target's own DNS or the scope list.

---

## 9. Reading results

### ClickHouse (the findings table)
```bash
CHP=$(grep '^CLICKHOUSE_PASSWORD=' /opt/sahw-run.env | cut -d= -f2-)
curl -s -u clickhouse:$CHP 'http://127.0.0.1:8123/?database=sahw_omah' --data-binary \
 "SELECT vuln_class, endpoint, invariant_type, verdict
  FROM sahw_findings
  WHERE endpoint ILIKE '%<target>%' AND verdict='CONFIRMED'   -- database=<CLICKHOUSE_DATABASE> (this deployment: sahw_omah)
  GROUP BY vuln_class,endpoint,invariant_type,verdict ORDER BY vuln_class FORMAT TSV"
```
Verdicts: `CONFIRMED` (deterministic), `CONFIRMED_BY_ADJUDICATION` (judge-promoted),
`NEEDS_REVIEW`, `FALSE_POSITIVE`, `BLOCKED`.

### Benchmark scoring (unsafebank-style)
Export the CONFIRMED findings to a run JSON and score offline:
```bash
python3 -m bench.cli --run findings.json --report
# -> {covered, partial, missed, false_positives, total_ground_truth}
```

### Traces / graph
Langfuse (per-beat LLM traces) at `LANGFUSE_BASE_URL`; Neo4j for the endpoint/finding graph.

---

## 10. Safety model (always on)

- **Authorization window** — no run outside `[SAHW_AUTH_START, SAHW_AUTH_END]` (extend
  `SAHW_AUTH_END` to continue an engagement).
- **Tether** — every request URL is `inScope()`-checked; out-of-scope host:port is denied.
- **Weaponize double-confirm** — see §7; fail-closed.
- **Restoration (L2)** — a `state_changed` mutation without restoration proof downgrades to
  NEEDS_REVIEW (reversible/bounded by design; the negative-transfer probe restores itself).
- **Provenance gate** — a finding needs the trace id + exploit hash + sandbox id + exit code.

---

## 11. Other knobs (less common)

- `SAHW_MAX_RETRIES` (default 0) — LLM client retry count (cli.ts).
- `SAHW_SKILLS_ROOT` / `SAHW_SKILL_TIMEOUT_MS` (default 120000) — attack-skill dir + per-skill timeout.
- `SAHW_TOOL_PREVIEW_BYTES` / `SAHW_ARTIFACT_PREVIEW_BYTES` — how much of a tool/artifact result the model sees (telemetry vs. context budget).
- `SAHW_SESSION_ID` — override the Langfuse session id.
- `SAHW_CLAIM_REVIEW` — claim-review behaviour toggle.
- `--dry-run` (CLI): prints `{dryRun, scope, profile}` and exits — a safe config check before a real run.
- **Payload corpus** (optional): the `payload-library` skill can merge a SQLite index of
  PayloadsAllTheThings + SecLists when `SAHW_PAYLOAD_DB` points at it; the sweep still uses its
  own generic marked payloads — the corpus augments the LLM's arsenal, it does not replace the
  Axiom-banked probes.

> Accuracy note: this guide was verified against `orchestrator/src` (config.ts, cli.ts, beat.ts,
> session.ts, obs/clickhouse.ts). If you add an env var, grep `orchestrator/src` for its reader
> to confirm the name/default before documenting it — several plausible-sounding knobs
> (e.g. `SAHW_TEMPERATURE`, `SAHW_DEEP_ESCALATE`) are **not** wired and have no effect.

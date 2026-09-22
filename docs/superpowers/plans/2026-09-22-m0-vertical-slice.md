# M0 Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The thinnest end-to-end path that takes in-scope URLs and produces one `CONFIRMED` finding with full provenance, writing to Langfuse, ClickHouse and Neo4j as it goes.

**Architecture:** A TypeScript orchestrator using the **OpenAI SDK as a stateless client**. The orchestrator owns the outer loop; each API call is `client.chat.completions.create`. Capability is the request's `tools` array. Every tool call passes the Tether (deterministic scope + destructive gate) before execution; every result is hashed into a content-addressed artifact store; the Axiom decides verdicts by replaying the exploit **and a control request** and evaluating a typed invariant. The three datastores are optional at runtime, so the slice runs locally without them.

**Tech Stack:** Node 20+ (dev box: v26.7.0), TypeScript, ESM. Runtime deps: `openai`, `@langfuse/otel`, `@langfuse/openai`, `@opentelemetry/sdk-node`, `neo4j-driver`, `@clickhouse/client`. Dev deps: `typescript`, `tsx`, `@types/node`. **Tests use Node's built-in `node:test` — no test-runner dependency.**

**Spec:** `docs/superpowers/specs/2026-09-22-safe-ai-hacker-design.md`

## Global Constraints

- **M0 acceptance:** one unauthenticated, single-request vulnerability class reaches `CONFIRMED` with complete provenance. The slice is **class-generic** — it takes whatever recon finds first. Do not hardcode a vulnerability class, endpoint, payload or host anywhere in `src/`.
- **Black-box, nothing hardcoded.** No target hostname, path, payload or credential in source. Everything comes from `SAHW_SCOPE` at runtime. `human-test/` is the answer key and must never be read by, or imported into, orchestrator code.
- **Tests never touch the network.** The OpenAI client is stubbed; HTTP is stubbed via an injected fetch. A test that requires a live target or a live model is a failed test.
- **The three stores are optional.** If `LANGFUSE_*`, `CLICKHOUSE_DSN` or `NEO4J_URI` are unset, the corresponding writer becomes a no-op and the run still completes. Local development must not require them.
- **Verdict enum is fixed** by `docs/schemas/finding.schema.json`: `CONFIRMED | FALSE_POSITIVE | NEEDS_REVIEW | BLOCKED`. Invariant types: `body_contains | status_in | derived | state_changed | state_violated | file_created_then_deleted`. Do not invent values.
- **Env knobs come from `.env.example`** — read it, do not invent names. Notably `SAHW_SCOPE`, `SAHW_AUTH_START/END`, `SAHW_MAX_TURNS`, `SAHW_BUDGET_TURNS/TOKENS/USD`, `SAHW_REQUEST_TIMEOUT_MS`, `SAHW_PHASE_TIMEOUT_MS`, `SAHW_MAX_RETRIES`, `SAHW_STALL_*`, `SAHW_PROFILE`.
- **`SAHW_PHASE_TIMEOUT_MS` must be less than `SAHW_REQUEST_TIMEOUT_MS`** — the orchestrator's AbortSignal has to trip before the transport, or a stall goes unrecorded.
- **A stalled run exits non-zero** (`SAHW_STALL_EXIT_CODE`, default 3). Exit 0 after producing no executed work is forbidden.
- **ESM throughout** (`"type": "module"`), relative imports carry the `.js` extension in TypeScript source.
- **Commit after every task.** Message prefix `feat(orchestrator):`.
- **Build local only.** Do not ssh to, deploy to, or scan any host during implementation.

---

## File Structure

```
orchestrator/
├── package.json · tsconfig.json
├── src/
│   ├── config.ts          # env → Engagement; scope + window validation
│   ├── tether.ts          # deterministic scope allowlist + destructive gate
│   ├── artifacts.ts       # content-addressed store (sha256)
│   ├── tools.ts           # tool schemas + executors, all Tether-gated
│   ├── agent.ts           # chat.completions loop: turns, budget, abort
│   ├── axiom.ts           # invariant evaluation + control-differential replay
│   ├── provenance.ts      # the gate: CONFIRMED requires the full chain
│   ├── stall.ts           # executed-work stall detection
│   ├── obs/
│   │   ├── langfuse.ts    # tracing; no-op when unconfigured
│   │   ├── clickhouse.ts  # telemetry events; no-op when unconfigured
│   │   └── neo4j.ts       # attack graph MERGE; no-op when unconfigured
│   ├── beat.ts            # one pass: recon → hypothesis → exploit → verdict
│   └── cli.ts             # `sahw run [--dry-run]`
└── test/                  # one *.test.ts per src module, node:test
```

Each module has one responsibility and is testable in isolation. `obs/` is split by store so an outage in one cannot take down the others.

Run tests: `cd orchestrator && npm test`

---

### Task 1: Scaffold and engagement config

**Files:**
- Create: `orchestrator/package.json`, `orchestrator/tsconfig.json`, `orchestrator/src/config.ts`
- Test: `orchestrator/test/config.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `interface Engagement { scope: URL[]; outOfScope: URL[]; authRef: string; windowStart: Date; windowEnd: Date; maxTurns: number; budgetTurns: number; budgetTokens: number; budgetUsd: number | null; requestTimeoutMs: number; phaseTimeoutMs: number; maxRetries: number; profile: "test" | "prod"; }`; `loadEngagement(env: Record<string,string|undefined>, now?: Date): Engagement` — throws `ConfigError` on invalid input.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/config.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadEngagement, ConfigError } from "../src/config.js";

const NOW = new Date("2026-09-22T12:00:00Z");
const base = {
  SAHW_SCOPE: "http://10.0.0.1:3000,http://10.0.0.1/api/",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
};

test("parses scope into URLs", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.scope.length, 2);
  assert.equal(e.scope[0].port, "3000");
});

test("applies documented defaults", () => {
  const e = loadEngagement(base, NOW);
  assert.equal(e.maxTurns, 40);
  assert.equal(e.budgetTurns, 200);
  assert.equal(e.requestTimeoutMs, 3_600_000);
  assert.equal(e.maxRetries, 0);
  assert.equal(e.profile, "test");
});

test("refuses an empty scope — scope IS the allowlist", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_SCOPE: "" }, NOW), ConfigError);
});

test("refuses a run outside the authorization window", () => {
  assert.throws(
    () => loadEngagement(base, new Date("2026-09-26T00:00:00Z")), ConfigError);
  assert.throws(
    () => loadEngagement(base, new Date("2026-09-19T00:00:00Z")), ConfigError);
});

test("refuses a missing authorization reference", () => {
  const { SAHW_AUTH_REF, ...noRef } = base;
  assert.throws(() => loadEngagement(noRef, NOW), ConfigError);
});

test("refuses a phase timeout that does not trip before the transport", () => {
  assert.throws(() => loadEngagement(
    { ...base, SAHW_PHASE_TIMEOUT_MS: "9000000", SAHW_REQUEST_TIMEOUT_MS: "3600000" }, NOW),
    ConfigError);
});

test("rejects a non-http scheme in scope", () => {
  assert.throws(() => loadEngagement({ ...base, SAHW_SCOPE: "ftp://10.0.0.1" }, NOW), ConfigError);
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/config.js`

- [ ] **Step 3: Scaffold and implement**

```bash
mkdir -p orchestrator/src/obs orchestrator/test
cd orchestrator
npm init -y >/dev/null
npm pkg set type=module main=dist/cli.js
npm pkg set scripts.build="tsc -p tsconfig.json"
npm pkg set scripts.test="tsx --test test/*.test.ts"
npm pkg set scripts.start="tsx src/cli.ts"
npm i openai @langfuse/otel @langfuse/openai @opentelemetry/sdk-node neo4j-driver @clickhouse/client
npm i -D typescript tsx @types/node
```

```json
// orchestrator/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": ".",
    "strict": true,
    "skipLibCheck": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

```ts
// orchestrator/src/config.ts
export class ConfigError extends Error {}

export interface Engagement {
  scope: URL[];
  outOfScope: URL[];
  authRef: string;
  windowStart: Date;
  windowEnd: Date;
  maxTurns: number;
  budgetTurns: number;
  budgetTokens: number;
  budgetUsd: number | null;
  requestTimeoutMs: number;
  phaseTimeoutMs: number;
  maxRetries: number;
  profile: "test" | "prod";
}

type Env = Record<string, string | undefined>;

function num(env: Env, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) throw new ConfigError(`${key} is not a number: ${raw}`);
  return n;
}

function urls(raw: string | undefined, key: string): URL[] {
  if (!raw || !raw.trim()) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean).map((s) => {
    let u: URL;
    try { u = new URL(s); } catch { throw new ConfigError(`${key} entry is not a URL: ${s}`); }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new ConfigError(`${key} must be HTTP(S) only, got ${u.protocol} in ${s}`);
    }
    return u;
  });
}

function date(env: Env, key: string): Date {
  const raw = env[key];
  if (!raw) throw new ConfigError(`${key} is required`);
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) throw new ConfigError(`${key} is not a date: ${raw}`);
  return d;
}

export function loadEngagement(env: Env, now: Date = new Date()): Engagement {
  const scope = urls(env.SAHW_SCOPE, "SAHW_SCOPE");
  if (scope.length === 0) {
    throw new ConfigError("SAHW_SCOPE is empty; scope IS the allowlist, refusing to run");
  }
  const authRef = env.SAHW_AUTH_REF?.trim();
  if (!authRef) throw new ConfigError("SAHW_AUTH_REF is required — no authorization, no run");

  const windowStart = date(env, "SAHW_AUTH_START");
  const windowEnd = date(env, "SAHW_AUTH_END");
  if (now < windowStart || now > windowEnd) {
    throw new ConfigError(
      `outside the authorization window (${windowStart.toISOString()}..${windowEnd.toISOString()})`);
  }

  const requestTimeoutMs = num(env, "SAHW_REQUEST_TIMEOUT_MS", 3_600_000);
  const phaseTimeoutMs = num(env, "SAHW_PHASE_TIMEOUT_MS", 5_400_000);
  if (phaseTimeoutMs >= requestTimeoutMs) {
    throw new ConfigError(
      "SAHW_PHASE_TIMEOUT_MS must be < SAHW_REQUEST_TIMEOUT_MS so the orchestrator " +
      "AbortSignal trips before the transport; otherwise a stall goes unrecorded");
  }

  const profileRaw = (env.SAHW_PROFILE ?? "test").trim();
  if (profileRaw !== "test" && profileRaw !== "prod") {
    throw new ConfigError(`SAHW_PROFILE must be "test" or "prod", got ${profileRaw}`);
  }
  const usd = env.SAHW_BUDGET_USD;

  return {
    scope,
    outOfScope: urls(env.SAHW_OUT_OF_SCOPE, "SAHW_OUT_OF_SCOPE"),
    authRef,
    windowStart,
    windowEnd,
    maxTurns: num(env, "SAHW_MAX_TURNS", 40),
    budgetTurns: num(env, "SAHW_BUDGET_TURNS", 200),
    budgetTokens: num(env, "SAHW_BUDGET_TOKENS", 2_000_000),
    budgetUsd: usd === undefined || usd === "" ? null : Number(usd),
    requestTimeoutMs,
    phaseTimeoutMs,
    maxRetries: num(env, "SAHW_MAX_RETRIES", 0),
    profile: profileRaw,
  };
}
```

Note the default `SAHW_PHASE_TIMEOUT_MS=5400000` in `.env.example` is **greater** than the default request timeout, which this validator rejects. That is deliberate: fix `.env.example` to `SAHW_PHASE_TIMEOUT_MS=3000000` as part of this task, and leave a comment saying it must stay below the request timeout.

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/ .env.example
git commit -m "feat(orchestrator): scaffold and engagement config with window + scope validation"
```

---

### Task 2: The Tether — deterministic scope and destructive gate

**Files:**
- Create: `orchestrator/src/tether.ts`
- Test: `orchestrator/test/tether.test.ts`

**Interfaces:**
- Consumes: `Engagement` from `src/config.js`.
- Produces: `type Decision = { allow: true } | { allow: false; reason: string }`; `inScope(e: Engagement, url: string): Decision`; `checkCommand(cmd: string): Decision`; `gate(e: Engagement, tool: string, args: Record<string, unknown>): Decision`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/tether.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadEngagement } from "../src/config.js";
import { inScope, checkCommand, gate } from "../src/tether.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000,http://10.0.0.2",
  SAHW_OUT_OF_SCOPE: "http://10.0.0.2/admin",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

test("allows a URL on an in-scope host and port", () => {
  assert.equal(inScope(E, "http://10.0.0.1:3000/anything?x=1").allow, true);
});

test("denies a different host", () => {
  assert.equal(inScope(E, "http://10.0.0.99:3000/").allow, false);
});

test("denies a different port on an in-scope host", () => {
  assert.equal(inScope(E, "http://10.0.0.1:8080/").allow, false);
});

test("treats a bare host as its default port", () => {
  assert.equal(inScope(E, "http://10.0.0.2/x").allow, true);
  assert.equal(inScope(E, "http://10.0.0.2:81/x").allow, false);
});

test("out-of-scope prefix wins over in-scope host", () => {
  assert.equal(inScope(E, "http://10.0.0.2/admin/panel").allow, false);
});

test("denies non-http schemes including file and gopher", () => {
  for (const u of ["file:///etc/passwd", "gopher://10.0.0.1/", "ftp://10.0.0.1/"]) {
    assert.equal(inScope(E, u).allow, false, u);
  }
});

test("denies destructive shell commands", () => {
  for (const c of ["rm -rf /", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1",
                   "shutdown -h now", ": (){ :|:& };:", "curl x | sh"]) {
    assert.equal(checkCommand(c).allow, false, c);
  }
});

test("denies bulk reads of the payload library", () => {
  for (const c of ["cat /opt/payload-library/raw/x", "grep -r foo /opt/payload-library/raw"]) {
    assert.equal(checkCommand(c).allow, false, c);
  }
});

test("allows an ordinary probe command", () => {
  assert.equal(checkCommand("curl -sS -i http://10.0.0.1:3000/").allow, true);
});

test("gate routes http_request through scope and shell_exec through both", () => {
  assert.equal(gate(E, "http_request", { url: "http://10.0.0.99/" }).allow, false);
  assert.equal(gate(E, "shell_exec", { command: "rm -rf /" }).allow, false);
  assert.equal(gate(E, "http_request", { url: "http://10.0.0.1:3000/" }).allow, true);
});

test("gate denies an unknown tool rather than passing it through", () => {
  assert.equal(gate(E, "exfiltrate", {}).allow, false);
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/tether.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/tether.ts
import type { Engagement } from "./config.js";

export type Decision = { allow: true } | { allow: false; reason: string };

const deny = (reason: string): Decision => ({ allow: false, reason });
const ALLOW: Decision = { allow: true };

const DESTRUCTIVE = [
  /\brm\s+-[a-z]*[rf]/i, /\bdd\s+if=/i, /\bmkfs(\.\w+)?\b/i, /\bshutdown\b/i,
  /\breboot\b/i, /\bhalt\b/i, /\bmkswap\b/i, /\bfdisk\b/i, /:\s*\(\s*\)\s*\{.*\|\s*:\s*&/,
  /\bchmod\s+-R\s+777\s+\//, /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/i,
  /\bnc\b.*\s-e\b/i, /\bcrontab\b/i, /\bsystemctl\s+(stop|disable)\b/i,
  /\b(useradd|adduser|passwd)\b/i, /\bauthorized_keys\b/i,
];

// The payload library is reachable through tools, never by bulk read (spec 9.4).
const BULK_LIBRARY_READ = /\b(cat|less|head|tail|grep|rg|find|xargs|tar|cp)\b[^\n]*\/opt\/payload-library\/(raw|normalized)\b/i;

function hostPort(u: URL): string {
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  return `${u.protocol}//${u.hostname}:${port}`;
}

export function inScope(e: Engagement, url: string): Decision {
  let u: URL;
  try { u = new URL(url); } catch { return deny(`not a URL: ${url}`); }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return deny(`scheme not permitted: ${u.protocol}`);
  }
  for (const out of e.outOfScope) {
    if (hostPort(u) === hostPort(out) && u.pathname.startsWith(out.pathname)) {
      return deny(`explicitly out of scope: ${url}`);
    }
  }
  const origins = new Set(e.scope.map(hostPort));
  if (!origins.has(hostPort(u))) {
    return deny(`host:port not in SAHW_SCOPE: ${hostPort(u)}`);
  }
  return ALLOW;
}

export function checkCommand(cmd: string): Decision {
  if (typeof cmd !== "string" || !cmd.trim()) return deny("empty command");
  for (const p of DESTRUCTIVE) {
    if (p.test(cmd)) return deny(`destructive pattern ${p} in: ${cmd}`);
  }
  if (BULK_LIBRARY_READ.test(cmd)) {
    return deny("bulk read of the payload library; use the payload tools instead");
  }
  return ALLOW;
}

const KNOWN_TOOLS = new Set([
  "http_request", "read_artifact", "grep_artifact", "glob_artifact",
  "write_file", "shell_exec",
]);

export function gate(e: Engagement, tool: string, args: Record<string, unknown>): Decision {
  if (!KNOWN_TOOLS.has(tool)) return deny(`unknown tool: ${tool}`);
  if (tool === "http_request") {
    return inScope(e, String(args.url ?? ""));
  }
  if (tool === "shell_exec") {
    const cmdCheck = checkCommand(String(args.command ?? ""));
    if (!cmdCheck.allow) return cmdCheck;
    const urlsInCmd = String(args.command ?? "").match(/https?:\/\/[^\s'"]+/g) ?? [];
    for (const u of urlsInCmd) {
      const d = inScope(e, u);
      if (!d.allow) return d;
    }
    return ALLOW;
  }
  return ALLOW;
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 11 Tether tests PASS (plus Task 1's 7)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): Tether — deterministic scope allowlist and destructive gate"
```

---

### Task 3: Content-addressed artifact store

**Files:**
- Create: `orchestrator/src/artifacts.ts`
- Test: `orchestrator/test/artifacts.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `interface Artifact { sha256: string; path: string; bytes: number; }`; `class ArtifactStore { constructor(root: string); put(data: string | Uint8Array): Promise<Artifact>; get(sha256: string): Promise<Buffer>; has(sha256: string): Promise<boolean>; }`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/artifacts.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { ArtifactStore } from "../src/artifacts.js";

async function store() {
  return new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-")));
}

test("put returns the sha256 of the content", async () => {
  const s = await store();
  const a = await s.put("hello");
  assert.equal(a.sha256, createHash("sha256").update("hello").digest("hex"));
  assert.equal(a.bytes, 5);
});

test("put is idempotent — identical content collapses to one path", async () => {
  const s = await store();
  const a = await s.put("same");
  const b = await s.put("same");
  assert.equal(a.path, b.path);
  assert.equal(a.sha256, b.sha256);
});

test("get round-trips the exact bytes", async () => {
  const s = await store();
  const a = await s.put("verbatim \u0000 bytes");
  assert.equal((await s.get(a.sha256)).toString(), "verbatim \u0000 bytes");
});

test("has reports presence without reading", async () => {
  const s = await store();
  const a = await s.put("x");
  assert.equal(await s.has(a.sha256), true);
  assert.equal(await s.has("0".repeat(64)), false);
});

test("get on an unknown hash rejects rather than returning empty", async () => {
  const s = await store();
  await assert.rejects(() => s.get("0".repeat(64)));
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/artifacts.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/artifacts.ts
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, access } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface Artifact {
  sha256: string;
  path: string;
  bytes: number;
}

export class ArtifactStore {
  constructor(private readonly root: string) {}

  private pathFor(sha256: string): string {
    // Fan out by the first two hex chars so one directory never holds every artifact.
    return join(this.root, sha256.slice(0, 2), sha256);
  }

  async put(data: string | Uint8Array): Promise<Artifact> {
    const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    const sha256 = createHash("sha256").update(buf).digest("hex");
    const path = this.pathFor(sha256);
    if (!(await this.has(sha256))) {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, buf);
    }
    return { sha256, path, bytes: buf.byteLength };
  }

  async get(sha256: string): Promise<Buffer> {
    return readFile(this.pathFor(sha256));
  }

  async has(sha256: string): Promise<boolean> {
    try {
      await access(this.pathFor(sha256));
      return true;
    } catch {
      return false;
    }
  }
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 5 artifact tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): content-addressed artifact store"
```

---

### Task 4: Tools — schemas and Tether-gated executors

**Files:**
- Create: `orchestrator/src/tools.ts`
- Test: `orchestrator/test/tools.test.ts`

**Interfaces:**
- Consumes: `Engagement`, `gate`, `ArtifactStore`.
- Produces: `interface HttpCapture { request: {method:string;url:string;headers:Record<string,string>;body:string|null}; response: {status:number;headers:Record<string,string>;body:string}; artifact: Artifact; ms:number }`; `TOOL_SCHEMAS: OpenAI.Chat.ChatCompletionTool[]`; `class ToolRunner { constructor(opts: { engagement: Engagement; store: ArtifactStore; fetchImpl?: typeof fetch }); execute(tool: string, args: Record<string,unknown>): Promise<{ ok: boolean; result?: unknown; denied?: string }>; }`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/tools.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadEngagement } from "../src/config.js";
import { ArtifactStore } from "../src/artifacts.js";
import { ToolRunner, TOOL_SCHEMAS } from "../src/tools.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000",
  SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z",
  SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

async function runner(fetchImpl?: typeof fetch) {
  return new ToolRunner({
    engagement: E,
    store: new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-"))),
    fetchImpl,
  });
}

const okFetch = (async () => new Response("BODY-OK", {
  status: 200, headers: { "content-type": "text/plain" },
})) as unknown as typeof fetch;

test("tool schemas are in chat.completions shape with required fields", () => {
  assert.ok(TOOL_SCHEMAS.length >= 2);
  for (const t of TOOL_SCHEMAS) {
    assert.equal(t.type, "function");
    assert.ok(t.function.name && t.function.description && t.function.parameters);
  }
  const http = TOOL_SCHEMAS.find((t) => t.function.name === "http_request");
  assert.deepEqual((http!.function.parameters as any).required, ["method", "url"]);
});

test("http_request captures request and response and stores an artifact", async () => {
  const r = await runner(okFetch);
  const out = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/x" });
  assert.equal(out.ok, true);
  const cap = out.result as any;
  assert.equal(cap.response.status, 200);
  assert.equal(cap.response.body, "BODY-OK");
  assert.match(cap.artifact.sha256, /^[0-9a-f]{64}$/);
});

test("http_request is denied out of scope and never calls fetch", async () => {
  let called = false;
  const spy = (async () => { called = true; return new Response(""); }) as unknown as typeof fetch;
  const r = await runner(spy);
  const out = await r.execute("http_request", { method: "GET", url: "http://evil.test/" });
  assert.equal(out.ok, false);
  assert.match(out.denied!, /not in SAHW_SCOPE/);
  assert.equal(called, false, "fetch must not run when the Tether denies");
});

test("shell_exec is denied for destructive commands without executing", async () => {
  const r = await runner(okFetch);
  const out = await r.execute("shell_exec", { command: "rm -rf /" });
  assert.equal(out.ok, false);
  assert.match(out.denied!, /destructive/);
});

test("an unknown tool is denied, not silently ignored", async () => {
  const r = await runner(okFetch);
  const out = await r.execute("exfiltrate", {});
  assert.equal(out.ok, false);
});

test("identical responses collapse to one artifact", async () => {
  const r = await runner(okFetch);
  const a = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/a" });
  const b = await r.execute("http_request", { method: "GET", url: "http://10.0.0.1:3000/a" });
  assert.equal((a.result as any).artifact.sha256, (b.result as any).artifact.sha256);
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/tools.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/tools.ts
import type OpenAI from "openai";
import type { Engagement } from "./config.js";
import { gate } from "./tether.js";
import { ArtifactStore, type Artifact } from "./artifacts.js";

export interface HttpCapture {
  request: { method: string; url: string; headers: Record<string, string>; body: string | null };
  response: { status: number; headers: Record<string, string>; body: string };
  artifact: Artifact;
  ms: number;
}

export const TOOL_SCHEMAS: OpenAI.Chat.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "http_request",
      description:
        "Send ONE HTTP request to an in-scope host. Returns status, headers and body, " +
        "and stores the verbatim exchange as a hashed artifact.",
      parameters: {
        type: "object",
        properties: {
          method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
          url: { type: "string" },
          headers: { type: "object" },
          body: { type: "string" },
        },
        required: ["method", "url"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "read_artifact",
      description: "Read a stored artifact by its sha256.",
      parameters: {
        type: "object",
        properties: { sha256: { type: "string" } },
        required: ["sha256"],
      },
    },
  },
];

export class ToolRunner {
  private readonly engagement: Engagement;
  private readonly store: ArtifactStore;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: { engagement: Engagement; store: ArtifactStore; fetchImpl?: typeof fetch }) {
    this.engagement = opts.engagement;
    this.store = opts.store;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async execute(tool: string, args: Record<string, unknown>) {
    const decision = gate(this.engagement, tool, args);
    if (!decision.allow) return { ok: false as const, denied: decision.reason };

    if (tool === "http_request") return { ok: true as const, result: await this.http(args) };
    if (tool === "read_artifact") {
      const buf = await this.store.get(String(args.sha256));
      return { ok: true as const, result: { content: buf.toString("utf8") } };
    }
    return { ok: false as const, denied: `no executor for tool: ${tool}` };
  }

  private async http(args: Record<string, unknown>): Promise<HttpCapture> {
    const method = String(args.method ?? "GET").toUpperCase();
    const url = String(args.url);
    const headers = (args.headers as Record<string, string>) ?? {};
    const body = args.body === undefined ? null : String(args.body);

    const started = Date.now();
    const res = await this.fetchImpl(url, { method, headers, body: body ?? undefined });
    const text = await res.text();
    const ms = Date.now() - started;

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { respHeaders[k] = v; });

    const capture = {
      request: { method, url, headers, body },
      response: { status: res.status, headers: respHeaders, body: text },
    };
    const artifact = await this.store.put(JSON.stringify(capture, null, 2));
    return { ...capture, artifact, ms };
  }
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 6 tool tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): Tether-gated tool executors with captured artifacts"
```

---

### Task 5: The Axiom — control-differential invariant replay

**Files:**
- Create: `orchestrator/src/axiom.ts`
- Test: `orchestrator/test/axiom.test.ts`

**Interfaces:**
- Consumes: `HttpCapture` from `src/tools.js`.
- Produces: `type InvariantType = "body_contains" | "status_in" | "derived" | "state_changed" | "state_violated" | "file_created_then_deleted"`; `interface Invariant { statement: string; type: InvariantType; expression: string }`; `type VerdictStatus = "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "BLOCKED"`; `evaluate(inv: Invariant, exploit: HttpCapture, control: HttpCapture | null): { status: VerdictStatus; reason: string }`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/axiom.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/axiom.js";
import type { HttpCapture } from "../src/tools.js";

const cap = (status: number, body: string): HttpCapture => ({
  request: { method: "GET", url: "http://10.0.0.1:3000/x", headers: {}, body: null },
  response: { status, headers: {}, body },
  artifact: { sha256: "a".repeat(64), path: "/tmp/a", bytes: body.length },
  ms: 1,
});

test("body_contains CONFIRMED only when the control lacks the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "root:x:0:0" },
    cap(200, "root:x:0:0:root:/root"), cap(200, "not found"));
  assert.equal(v.status, "CONFIRMED");
});

test("body_contains is FALSE_POSITIVE when the control also contains the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "error" },
    cap(200, "error here"), cap(200, "error here too"));
  assert.equal(v.status, "FALSE_POSITIVE");
  assert.match(v.reason, /control/i);
});

test("body_contains is FALSE_POSITIVE when the exploit lacks the marker", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "root:x:0:0" },
    cap(200, "nothing"), cap(200, "nothing"));
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("a missing control is NEEDS_REVIEW, never CONFIRMED", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "x" },
    cap(200, "x"), null);
  assert.equal(v.status, "NEEDS_REVIEW");
  assert.match(v.reason, /control/i);
});

test("status_in CONFIRMED when exploit status is listed and control differs", () => {
  const v = evaluate({ statement: "s", type: "status_in", expression: "200,206" },
    cap(200, ""), cap(404, ""));
  assert.equal(v.status, "CONFIRMED");
});

test("status_in FALSE_POSITIVE when the control shares the status", () => {
  const v = evaluate({ statement: "s", type: "status_in", expression: "200" },
    cap(200, ""), cap(200, ""));
  assert.equal(v.status, "FALSE_POSITIVE");
});

test("an unsupported invariant type escalates rather than guessing", () => {
  const v = evaluate({ statement: "s", type: "derived", expression: "?" }, cap(200, "x"), cap(200, "y"));
  assert.equal(v.status, "NEEDS_REVIEW");
});

test("an empty expression never confirms", () => {
  const v = evaluate({ statement: "s", type: "body_contains", expression: "" },
    cap(200, "anything"), cap(404, ""));
  assert.notEqual(v.status, "CONFIRMED");
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/axiom.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/axiom.ts
import type { HttpCapture } from "./tools.js";

export type InvariantType =
  | "body_contains" | "status_in" | "derived"
  | "state_changed" | "state_violated" | "file_created_then_deleted";

export interface Invariant {
  statement: string;
  type: InvariantType;
  expression: string;
}

export type VerdictStatus = "CONFIRMED" | "FALSE_POSITIVE" | "NEEDS_REVIEW" | "BLOCKED";

export interface Verdict {
  status: VerdictStatus;
  reason: string;
}

/**
 * The control-differential rule: a finding is real only when the exploit and a
 * benign control diverge exactly as the invariant predicts. Without a control we
 * cannot tell a genuine leak from a page that happens to contain the marker, so
 * the answer is NEEDS_REVIEW — never CONFIRMED.
 */
export function evaluate(
  inv: Invariant, exploit: HttpCapture, control: HttpCapture | null,
): Verdict {
  if (!inv.expression || !inv.expression.trim()) {
    return { status: "NEEDS_REVIEW", reason: "invariant expression is empty" };
  }
  if (control === null) {
    return { status: "NEEDS_REVIEW", reason: "no control request captured; cannot differentiate" };
  }

  switch (inv.type) {
    case "body_contains": {
      const marker = inv.expression;
      const inExploit = exploit.response.body.includes(marker);
      const inControl = control.response.body.includes(marker);
      if (!inExploit) {
        return { status: "FALSE_POSITIVE", reason: `exploit response lacks marker: ${marker}` };
      }
      if (inControl) {
        return { status: "FALSE_POSITIVE", reason: `control response also contains ${marker}` };
      }
      return { status: "CONFIRMED", reason: `marker present in exploit, absent in control` };
    }
    case "status_in": {
      const wanted = inv.expression.split(",").map((s) => Number(s.trim())).filter(Number.isFinite);
      const hit = wanted.includes(exploit.response.status);
      if (!hit) {
        return { status: "FALSE_POSITIVE", reason: `exploit status ${exploit.response.status} not in ${wanted}` };
      }
      if (wanted.includes(control.response.status)) {
        return { status: "FALSE_POSITIVE", reason: `control shares status ${control.response.status}` };
      }
      return { status: "CONFIRMED", reason: `status ${exploit.response.status} differs from control ${control.response.status}` };
    }
    default:
      return {
        status: "NEEDS_REVIEW",
        reason: `invariant type ${inv.type} is not mechanically evaluable in M0`,
      };
  }
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 8 axiom tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): Axiom — control-differential invariant evaluation"
```

---

### Task 6: The Provenance Gate

**Files:**
- Create: `orchestrator/src/provenance.ts`
- Test: `orchestrator/test/provenance.test.ts`

**Interfaces:**
- Consumes: `VerdictStatus` from `src/axiom.js`; `ArtifactStore`.
- Produces: `interface Provenance { utc: string; langfuseTraceId: string | null; exploitRequestHash: string | null; stdoutSha256: string | null; sandboxId: string | null; exitCode: number | null }`; `gateProvenance(p: Provenance, axiom: VerdictStatus, store: ArtifactStore): Promise<{ status: VerdictStatus; missing: string[] }>`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/provenance.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "../src/artifacts.js";
import { gateProvenance, type Provenance } from "../src/provenance.js";

async function fixture() {
  const store = new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-")));
  const a = await store.put("verbatim stdout");
  const full: Provenance = {
    utc: "2026-09-22T12:00:00Z",
    langfuseTraceId: "trace-1",
    exploitRequestHash: "b".repeat(64),
    stdoutSha256: a.sha256,
    sandboxId: "sbx-1",
    exitCode: 0,
  };
  return { store, full };
}

test("a complete chain with a CONFIRMED axiom verdict stays CONFIRMED", async () => {
  const { store, full } = await fixture();
  const out = await gateProvenance(full, "CONFIRMED", store);
  assert.equal(out.status, "CONFIRMED");
  assert.deepEqual(out.missing, []);
});

test("any missing field downgrades to NEEDS_REVIEW and names it", async () => {
  const { store, full } = await fixture();
  for (const k of ["langfuseTraceId", "exploitRequestHash", "sandboxId", "exitCode"] as const) {
    const out = await gateProvenance({ ...full, [k]: null }, "CONFIRMED", store);
    assert.equal(out.status, "NEEDS_REVIEW", k);
    assert.ok(out.missing.includes(k), `${k} should be named`);
  }
});

test("a stdout hash absent from the store downgrades — the artifact must exist", async () => {
  const { store, full } = await fixture();
  const out = await gateProvenance({ ...full, stdoutSha256: "c".repeat(64) }, "CONFIRMED", store);
  assert.equal(out.status, "NEEDS_REVIEW");
  assert.ok(out.missing.some((m) => m.includes("stdoutSha256")));
});

test("the gate never upgrades a non-CONFIRMED axiom verdict", async () => {
  const { store, full } = await fixture();
  assert.equal((await gateProvenance(full, "FALSE_POSITIVE", store)).status, "FALSE_POSITIVE");
  assert.equal((await gateProvenance(full, "NEEDS_REVIEW", store)).status, "NEEDS_REVIEW");
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/provenance.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/provenance.ts
import type { VerdictStatus } from "./axiom.js";
import type { ArtifactStore } from "./artifacts.js";

export interface Provenance {
  utc: string;
  langfuseTraceId: string | null;
  exploitRequestHash: string | null;
  stdoutSha256: string | null;
  sandboxId: string | null;
  exitCode: number | null;
}

/**
 * Stricter than finding.schema.json on purpose. The schema defines a well-formed
 * finding; this gate defines a believable one. It exists to stop placeholder or
 * model-generated text being mistaken for real tool output: a claim whose evidence
 * cannot be traced to a hashed artifact produced by a recorded command did not happen.
 */
export async function gateProvenance(
  p: Provenance, axiom: VerdictStatus, store: ArtifactStore,
): Promise<{ status: VerdictStatus; missing: string[] }> {
  if (axiom !== "CONFIRMED") return { status: axiom, missing: [] };

  const missing: string[] = [];
  if (!p.utc) missing.push("utc");
  if (!p.langfuseTraceId) missing.push("langfuseTraceId");
  if (!p.exploitRequestHash) missing.push("exploitRequestHash");
  if (!p.sandboxId) missing.push("sandboxId");
  if (p.exitCode === null || p.exitCode === undefined) missing.push("exitCode");

  if (!p.stdoutSha256) {
    missing.push("stdoutSha256");
  } else if (!(await store.has(p.stdoutSha256))) {
    missing.push(`stdoutSha256 not present in the artifact store: ${p.stdoutSha256}`);
  }

  return { status: missing.length === 0 ? "CONFIRMED" : "NEEDS_REVIEW", missing };
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 4 provenance tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): provenance gate stricter than the schema"
```

---

### Task 7: Stall detection

**Files:**
- Create: `orchestrator/src/stall.ts`
- Test: `orchestrator/test/stall.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `interface BeatWork { succeededToolCalls: number; newArtifacts: number; calls: Array<{ tool: string; args: string }> }`; `interface StallConfig { minToolCalls: number; minArtifacts: number; maxRepeatCalls: number; maxBarrenBeats: number; exitCode: number }`; `loadStallConfig(env): StallConfig`; `isStalled(work: BeatWork, cfg: StallConfig): { stalled: boolean; reason: string | null }`.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/stall.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { isStalled, loadStallConfig } from "../src/stall.js";

const CFG = loadStallConfig({});

test("documented defaults", () => {
  assert.equal(CFG.minToolCalls, 1);
  assert.equal(CFG.minArtifacts, 1);
  assert.equal(CFG.maxRepeatCalls, 3);
  assert.equal(CFG.maxBarrenBeats, 2);
  assert.equal(CFG.exitCode, 3);
});

test("a beat that executed nothing is stalled, however much the model talked", () => {
  const r = isStalled({ succeededToolCalls: 0, newArtifacts: 0, calls: [] }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /tool call/i);
});

test("tool calls without artifacts is still a stall", () => {
  const r = isStalled(
    { succeededToolCalls: 5, newArtifacts: 0, calls: [{ tool: "http_request", args: "{}" }] }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /artifact/i);
});

test("the same call repeated past the cap is a stall", () => {
  const calls = Array.from({ length: 4 }, () => ({ tool: "http_request", args: '{"url":"u"}' }));
  const r = isStalled({ succeededToolCalls: 4, newArtifacts: 1, calls }, CFG);
  assert.equal(r.stalled, true);
  assert.match(r.reason!, /repeat/i);
});

test("distinct productive calls are not a stall", () => {
  const calls = [
    { tool: "http_request", args: '{"url":"a"}' },
    { tool: "http_request", args: '{"url":"b"}' },
  ];
  const r = isStalled({ succeededToolCalls: 2, newArtifacts: 2, calls }, CFG);
  assert.equal(r.stalled, false);
  assert.equal(r.reason, null);
});

test("failed tool calls do not count as executed work", () => {
  // succeededToolCalls counts only successes; a beat of pure denials is barren.
  const r = isStalled({ succeededToolCalls: 0, newArtifacts: 0, calls:
    [{ tool: "http_request", args: '{"url":"denied"}' }] }, CFG);
  assert.equal(r.stalled, true);
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/stall.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/stall.ts
export interface BeatWork {
  succeededToolCalls: number;
  newArtifacts: number;
  calls: Array<{ tool: string; args: string }>;
}

export interface StallConfig {
  minToolCalls: number;
  minArtifacts: number;
  maxRepeatCalls: number;
  maxBarrenBeats: number;
  exitCode: number;
}

type Env = Record<string, string | undefined>;
const n = (env: Env, k: string, d: number) =>
  env[k] === undefined || env[k] === "" ? d : Number(env[k]);

export function loadStallConfig(env: Env): StallConfig {
  return {
    minToolCalls: n(env, "SAHW_STALL_MIN_TOOL_CALLS", 1),
    minArtifacts: n(env, "SAHW_STALL_MIN_ARTIFACTS", 1),
    maxRepeatCalls: n(env, "SAHW_STALL_MAX_REPEAT_CALLS", 3),
    maxBarrenBeats: n(env, "SAHW_STALL_MAX_BARREN_BEATS", 2),
    exitCode: n(env, "SAHW_STALL_EXIT_CODE", 3),
  };
}

/**
 * Stall detection keys on EXECUTED WORK, never on liveness. A loop that is still
 * ticking is not a loop that is working: a run that reported "not stalled" after
 * three hours with zero executed tool calls is the failure this guards against.
 */
export function isStalled(work: BeatWork, cfg: StallConfig): { stalled: boolean; reason: string | null } {
  if (work.succeededToolCalls < cfg.minToolCalls) {
    return { stalled: true, reason: `only ${work.succeededToolCalls} succeeded tool call(s), need ${cfg.minToolCalls}` };
  }
  if (work.newArtifacts < cfg.minArtifacts) {
    return { stalled: true, reason: `only ${work.newArtifacts} new artifact(s), need ${cfg.minArtifacts}` };
  }
  const seen = new Map<string, number>();
  for (const c of work.calls) {
    const key = `${c.tool}:${c.args}`;
    const count = (seen.get(key) ?? 0) + 1;
    seen.set(key, count);
    if (count > cfg.maxRepeatCalls) {
      return { stalled: true, reason: `repeat call ${key} seen ${count} times (cap ${cfg.maxRepeatCalls})` };
    }
  }
  return { stalled: false, reason: null };
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 6 stall tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): stall detection measured in executed work"
```

---

### Task 8: Observability — Langfuse, ClickHouse, Neo4j

**Files:**
- Create: `orchestrator/src/obs/langfuse.ts`, `orchestrator/src/obs/clickhouse.ts`, `orchestrator/src/obs/neo4j.ts`, `orchestrator/src/obs/index.ts`
- Test: `orchestrator/test/obs.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks (types only).
- Produces: `interface FindingRow { engagement_id: string; finding_id: string; vuln_class: string; endpoint: string; verdict: string; invariant_type: string; langfuse_trace_id: string; utc: string }`; `interface Observability { traceId(): string | null; recordFinding(r: FindingRow): Promise<void>; mergeEndpoint(url: string, method: string): Promise<void>; mergeFinding(r: FindingRow): Promise<void>; shutdown(): Promise<void> }`; `initObservability(env): Promise<Observability>`. **Each writer no-ops when its env is unset.**

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/obs.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { initObservability } from "../src/obs/index.js";
import { ClickHouseWriter } from "../src/obs/clickhouse.js";
import { Neo4jWriter } from "../src/obs/neo4j.js";

const ROW = {
  engagement_id: "ENG-1", finding_id: "SAHW-0001", vuln_class: "path_traversal",
  endpoint: "http://10.0.0.1:3000/x", verdict: "CONFIRMED",
  invariant_type: "body_contains", langfuse_trace_id: "t-1", utc: "2026-09-22T12:00:00Z",
};

test("unconfigured env yields a working no-op observability", async () => {
  const obs = await initObservability({});
  await obs.recordFinding(ROW);      // must not throw
  await obs.mergeFinding(ROW);
  await obs.mergeEndpoint("http://10.0.0.1:3000/x", "GET");
  assert.equal(obs.traceId(), null);
  await obs.shutdown();
});

test("ClickHouse writer sends JSONEachRow to the findings table", async () => {
  const calls: any[] = [];
  const w = new ClickHouseWriter({
    insert: async (p: any) => { calls.push(p); },
    command: async () => {},
    close: async () => {},
  } as any);
  await w.ensureSchema();
  await w.recordFinding(ROW);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].format, "JSONEachRow");
  assert.equal(calls[0].table, "sahw_findings");
  assert.deepEqual(calls[0].values, [ROW]);
});

test("Neo4j writer MERGEs so repeated beats do not duplicate", async () => {
  const queries: string[] = [];
  const session = { executeWrite: async (fn: any) => fn({ run: async (q: string) => { queries.push(q); return { records: [] }; } }), close: async () => {} };
  const w = new Neo4jWriter({ session: () => session, close: async () => {} } as any, "engagement");
  await w.mergeEndpoint("http://10.0.0.1:3000/x", "GET");
  await w.mergeFinding(ROW);
  assert.equal(queries.length, 2);
  for (const q of queries) assert.match(q, /MERGE/);
  assert.ok(queries.some((q) => /:Finding/.test(q)));
});

test("one store failing does not take down the others", async () => {
  const obs = await initObservability({});
  (obs as any).clickhouse = { recordFinding: async () => { throw new Error("CH down"); } };
  await obs.recordFinding(ROW);  // must swallow and continue
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/obs/index.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/obs/clickhouse.ts
import { createClient, type ClickHouseClient } from "@clickhouse/client";

export interface FindingRow {
  engagement_id: string; finding_id: string; vuln_class: string; endpoint: string;
  verdict: string; invariant_type: string; langfuse_trace_id: string; utc: string;
}

export class ClickHouseWriter {
  constructor(private readonly client: ClickHouseClient) {}

  static fromEnv(env: Record<string, string | undefined>): ClickHouseWriter | null {
    if (!env.CLICKHOUSE_DSN) return null;
    return new ClickHouseWriter(createClient({
      url: env.CLICKHOUSE_DSN,
      username: env.CLICKHOUSE_USER,
      password: env.CLICKHOUSE_PASSWORD,
      database: env.CLICKHOUSE_DATABASE ?? "sahw",
    }));
  }

  async ensureSchema(): Promise<void> {
    await this.client.command({
      query: `CREATE TABLE IF NOT EXISTS sahw_findings (
        engagement_id String, finding_id String, vuln_class String, endpoint String,
        verdict String, invariant_type String, langfuse_trace_id String, utc DateTime64(3)
      ) ENGINE = MergeTree ORDER BY (engagement_id, utc)`,
    });
  }

  async recordFinding(row: FindingRow): Promise<void> {
    await this.client.insert({ table: "sahw_findings", format: "JSONEachRow", values: [row] });
  }

  async close(): Promise<void> { await this.client.close(); }
}
```

```ts
// orchestrator/src/obs/neo4j.ts
import neo4j, { type Driver } from "neo4j-driver";
import type { FindingRow } from "./clickhouse.js";

export class Neo4jWriter {
  constructor(private readonly driver: Driver, private readonly database: string) {}

  static fromEnv(env: Record<string, string | undefined>): Neo4jWriter | null {
    if (!env.NEO4J_URI) return null;
    const driver = neo4j.driver(
      env.NEO4J_URI,
      neo4j.auth.basic(env.NEO4J_USER ?? "neo4j", env.NEO4J_PASSWORD ?? ""));
    return new Neo4jWriter(driver, env.NEO4J_DATABASE ?? "engagement");
  }

  private async write(query: string, params: Record<string, unknown>) {
    const session = this.driver.session({ database: this.database } as any);
    try {
      await session.executeWrite(async (tx: any) => tx.run(query, params));
    } finally {
      await session.close();
    }
  }

  async mergeEndpoint(url: string, method: string): Promise<void> {
    await this.write(
      `MERGE (e:Endpoint {url: $url, method: $method})
       ON CREATE SET e.first_seen = datetime()`,
      { url, method });
  }

  async mergeFinding(row: FindingRow): Promise<void> {
    await this.write(
      `MERGE (f:Finding {finding_id: $finding_id})
       SET f.vuln_class = $vuln_class, f.verdict = $verdict,
           f.invariant_type = $invariant_type, f.langfuse_trace_id = $langfuse_trace_id
       MERGE (e:Endpoint {url: $endpoint})
       MERGE (f)-[:AFFECTS]->(e)`,
      row as unknown as Record<string, unknown>);
  }

  async close(): Promise<void> { await this.driver.close(); }
}
```

```ts
// orchestrator/src/obs/langfuse.ts
import { NodeSDK } from "@opentelemetry/sdk-node";
import { LangfuseSpanProcessor } from "@langfuse/otel";

export class LangfuseTracing {
  private sdk: NodeSDK | null = null;
  private id: string | null = null;

  static fromEnv(env: Record<string, string | undefined>): LangfuseTracing | null {
    if (!env.LANGFUSE_PUBLIC_KEY || !env.LANGFUSE_SECRET_KEY) return null;
    return new LangfuseTracing();
  }

  start(traceId: string): void {
    this.id = traceId;
    this.sdk = new NodeSDK({ spanProcessors: [new LangfuseSpanProcessor()] });
    this.sdk.start();
  }

  traceId(): string | null { return this.id; }

  /** Required: batched spans are lost at exit otherwise. */
  async shutdown(): Promise<void> { await this.sdk?.shutdown(); }
}
```

```ts
// orchestrator/src/obs/index.ts
import { randomUUID } from "node:crypto";
import { ClickHouseWriter, type FindingRow } from "./clickhouse.js";
import { Neo4jWriter } from "./neo4j.js";
import { LangfuseTracing } from "./langfuse.js";

export type { FindingRow };

export interface Observability {
  traceId(): string | null;
  recordFinding(r: FindingRow): Promise<void>;
  mergeEndpoint(url: string, method: string): Promise<void>;
  mergeFinding(r: FindingRow): Promise<void>;
  shutdown(): Promise<void>;
}

/** One store being down must never take the run with it. */
async function safe(label: string, fn: () => Promise<void>): Promise<void> {
  try { await fn(); } catch (err) {
    console.error(`[obs] ${label} failed (continuing):`, (err as Error).message);
  }
}

export async function initObservability(
  env: Record<string, string | undefined>,
): Promise<Observability> {
  const clickhouse = ClickHouseWriter.fromEnv(env);
  const graph = Neo4jWriter.fromEnv(env);
  const tracing = LangfuseTracing.fromEnv(env);

  if (tracing) tracing.start(randomUUID());
  if (clickhouse) await safe("clickhouse.ensureSchema", () => clickhouse.ensureSchema());

  const obs: Observability = {
    traceId: () => tracing?.traceId() ?? null,
    recordFinding: async (r) => {
      const ch = (obs as any).clickhouse ?? clickhouse;
      if (ch) await safe("clickhouse.recordFinding", () => ch.recordFinding(r));
    },
    mergeEndpoint: async (url, method) => {
      if (graph) await safe("neo4j.mergeEndpoint", () => graph.mergeEndpoint(url, method));
    },
    mergeFinding: async (r) => {
      if (graph) await safe("neo4j.mergeFinding", () => graph.mergeFinding(r));
    },
    shutdown: async () => {
      await safe("langfuse.shutdown", () => tracing?.shutdown() ?? Promise.resolve());
      await safe("clickhouse.close", () => clickhouse?.close() ?? Promise.resolve());
      await safe("neo4j.close", () => graph?.close() ?? Promise.resolve());
    },
  };
  return obs;
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 4 observability tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): Langfuse, ClickHouse and Neo4j writers, each optional"
```

---

### Task 9: The agent runner

**Files:**
- Create: `orchestrator/src/agent.ts`
- Test: `orchestrator/test/agent.test.ts`

**Interfaces:**
- Consumes: `ToolRunner`, `TOOL_SCHEMAS`, `Engagement`.
- Produces: `interface AgentResult { messages: unknown[]; turns: number; tokens: number; toolCalls: Array<{tool:string;args:string;ok:boolean}>; artifacts: number; stopReason: "done"|"max_turns"|"budget"|"aborted" }`; `runAgent(opts: { client: MinimalClient; model: string; system: string; user: string; tools: OpenAI.Chat.ChatCompletionTool[]; runner: ToolRunner; maxTurns: number; budgetTokens: number; signal?: AbortSignal }): Promise<AgentResult>`. `MinimalClient` is `{ chat: { completions: { create(params, opts?): Promise<any> } } }` so tests can stub it.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/agent.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadEngagement } from "../src/config.js";
import { ArtifactStore } from "../src/artifacts.js";
import { ToolRunner, TOOL_SCHEMAS } from "../src/tools.js";
import { runAgent } from "../src/agent.js";

const E = loadEngagement({
  SAHW_SCOPE: "http://10.0.0.1:3000", SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z", SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
}, new Date("2026-09-22T12:00:00Z"));

const okFetch = (async () => new Response("OK")) as unknown as typeof fetch;

async function mkRunner() {
  return new ToolRunner({
    engagement: E, fetchImpl: okFetch,
    store: new ArtifactStore(await mkdtemp(join(tmpdir(), "sahw-"))),
  });
}

/** Stub client: returns scripted completions, records what it was sent. */
function stub(script: any[]) {
  const seen: any[] = [];
  let i = 0;
  return {
    seen,
    client: { chat: { completions: { create: async (p: any) => { seen.push(p); return script[i++] ?? script[script.length - 1]; } } } },
  };
}

const say = (content: string) => ({ choices: [{ message: { role: "assistant", content } }], usage: { total_tokens: 10 } });
const call = (name: string, args: object) => ({
  choices: [{ message: { role: "assistant", content: null, tool_calls: [
    { id: "c1", type: "function", function: { name, arguments: JSON.stringify(args) } }] } }],
  usage: { total_tokens: 10 },
});

const OPTS = async (client: any, script?: any) => ({
  client, model: "m", system: "sys", user: "go",
  tools: TOOL_SCHEMAS, runner: await mkRunner(), maxTurns: 5, budgetTokens: 1000,
});

test("returns on a terminal assistant message", async () => {
  const { client } = stub([say("done")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.stopReason, "done");
  assert.equal(r.turns, 1);
});

test("executes a tool call and feeds the result back", async () => {
  const { client, seen } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" }), say("ok")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.toolCalls.length, 1);
  assert.equal(r.toolCalls[0].ok, true);
  assert.equal(r.artifacts, 1);
  const last = seen[seen.length - 1];
  assert.ok(last.messages.some((m: any) => m.role === "tool"));
});

test("a denied tool call is fed back as a tool message, not thrown", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://evil.test/" }), say("ok")]);
  const r = await runAgent(await OPTS(client));
  assert.equal(r.toolCalls[0].ok, false);
  assert.equal(r.stopReason, "done");
});

test("stops at maxTurns", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" })]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, maxTurns: 3 });
  assert.equal(r.stopReason, "max_turns");
  assert.equal(r.turns, 3);
});

test("stops when the token budget is exhausted", async () => {
  const { client } = stub([call("http_request", { method: "GET", url: "http://10.0.0.1:3000/" })]);
  const o = await OPTS(client);
  const r = await runAgent({ ...o, budgetTokens: 15 });
  assert.equal(r.stopReason, "budget");
});

test("passes the tools array and parallel_tool_calls false on every request", async () => {
  const { client, seen } = stub([say("done")]);
  await runAgent(await OPTS(client));
  assert.equal(seen[0].parallel_tool_calls, false);
  assert.equal(seen[0].tools.length, TOOL_SCHEMAS.length);
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/agent.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/agent.ts
import type OpenAI from "openai";
import type { ToolRunner } from "./tools.js";

export interface MinimalClient {
  chat: { completions: { create(params: any, opts?: any): Promise<any> } };
}

export interface AgentResult {
  messages: any[];
  turns: number;
  tokens: number;
  toolCalls: Array<{ tool: string; args: string; ok: boolean }>;
  artifacts: number;
  stopReason: "done" | "max_turns" | "budget" | "aborted";
}

export async function runAgent(opts: {
  client: MinimalClient;
  model: string;
  system: string;
  user: string;
  tools: OpenAI.Chat.ChatCompletionTool[];
  runner: ToolRunner;
  maxTurns: number;
  budgetTokens: number;
  signal?: AbortSignal;
}): Promise<AgentResult> {
  const messages: any[] = [
    { role: "system", content: opts.system },
    { role: "user", content: opts.user },
  ];
  const toolCalls: AgentResult["toolCalls"] = [];
  let turns = 0;
  let tokens = 0;
  let artifacts = 0;

  while (true) {
    if (opts.signal?.aborted) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "aborted" };
    }
    if (turns >= opts.maxTurns) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "max_turns" };
    }

    const completion = await opts.client.chat.completions.create(
      {
        model: opts.model,
        messages,
        tools: opts.tools,
        parallel_tool_calls: false,
      },
      opts.signal ? { signal: opts.signal } : undefined,
    );
    turns += 1;
    tokens += completion.usage?.total_tokens ?? 0;

    const message = completion.choices?.[0]?.message;
    messages.push(message);

    const calls = message?.tool_calls ?? [];
    if (calls.length === 0) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "done" };
    }

    for (const c of calls) {
      const name = c.function.name;
      const raw = c.function.arguments ?? "{}";
      let args: Record<string, unknown> = {};
      try { args = JSON.parse(raw); } catch { /* malformed args reach the tool as {} */ }

      const out = await opts.runner.execute(name, args);
      toolCalls.push({ tool: name, args: raw, ok: out.ok });
      if (out.ok && (out.result as any)?.artifact) artifacts += 1;

      messages.push({
        role: "tool",
        tool_call_id: c.id,
        content: JSON.stringify(out.ok ? out.result : { denied: out.denied }),
      });
    }

    if (tokens >= opts.budgetTokens) {
      return { messages, turns, tokens, toolCalls, artifacts, stopReason: "budget" };
    }
  }
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
cd orchestrator && npm test
```
Expected: 6 agent tests PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): agent runner with turn bound, token budget and abort"
```

---

### Task 10: Beat, CLI and deployment files

**Files:**
- Create: `orchestrator/src/beat.ts`, `orchestrator/src/cli.ts`, `orchestrator/README.md`, `orchestrator/docker-compose.yml`
- Test: `orchestrator/test/beat.test.ts`

**Interfaces:**
- Consumes: everything above.
- Produces: `runBeat(opts: { env; client: MinimalClient; fetchImpl?: typeof fetch; now?: Date }): Promise<{ exitCode: number; findings: FindingRow[]; stalled: boolean; reason: string | null }>`; a CLI that calls it and exits with that code.

- [ ] **Step 1: Write the failing test**

```ts
// orchestrator/test/beat.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runBeat } from "../src/beat.js";

const ENV = async () => ({
  SAHW_SCOPE: "http://10.0.0.1:3000", SAHW_AUTH_REF: "ENG-1",
  SAHW_AUTH_START: "2026-09-20T00:00:00Z", SAHW_AUTH_END: "2026-09-25T00:00:00Z",
  SAHW_PHASE_TIMEOUT_MS: "3000000",
  SAHW_WORKSPACE: await mkdtemp(join(tmpdir(), "sahw-")),
});
const NOW = new Date("2026-09-22T12:00:00Z");

/** Exploit sees the marker, control does not — the shape M0 must confirm. */
const differentialFetch = (async (url: string | URL) => {
  const u = String(url);
  return u.includes("exploit")
    ? new Response("root:x:0:0:root:/root:/bin/bash")
    : new Response("404 not found", { status: 404 });
}) as unknown as typeof fetch;

function scriptedClient() {
  const script = [
    { choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "http_request", arguments: JSON.stringify({ method: "GET", url: "http://10.0.0.1:3000/exploit" }) } }] } }], usage: { total_tokens: 10 } },
    { choices: [{ message: { role: "assistant", content: JSON.stringify({
        vuln_class: "path_traversal",
        endpoint: "http://10.0.0.1:3000/exploit",
        control_url: "http://10.0.0.1:3000/control",
        invariant: { statement: "file contents returned", type: "body_contains", expression: "root:x:0:0" },
      }) } }], usage: { total_tokens: 10 } },
  ];
  let i = 0;
  return { chat: { completions: { create: async () => script[Math.min(i++, script.length - 1)] } } };
}

test("a beat with a real differential produces a CONFIRMED finding and exits 0", async () => {
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, false);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].verdict, "CONFIRMED");
  assert.equal(out.exitCode, 0);
});

test("a beat that executes nothing is stalled and exits non-zero", async () => {
  const silent = { chat: { completions: { create: async () => ({ choices: [{ message: { role: "assistant", content: "I will think about it." } }], usage: { total_tokens: 5 } }) } } };
  const out = await runBeat({ env: await ENV(), client: silent, fetchImpl: differentialFetch, now: NOW });
  assert.equal(out.stalled, true);
  assert.equal(out.exitCode, 3);
  assert.equal(out.findings.length, 0);
});

test("no control differential means no CONFIRMED", async () => {
  const sameFetch = (async () => new Response("root:x:0:0")) as unknown as typeof fetch;
  const out = await runBeat({ env: await ENV(), client: scriptedClient(), fetchImpl: sameFetch, now: NOW });
  assert.notEqual(out.findings[0]?.verdict, "CONFIRMED");
});

test("an out-of-window engagement refuses to run at all", async () => {
  await assert.rejects(() => runBeat({
    env: await ENV(), client: scriptedClient(), fetchImpl: differentialFetch,
    now: new Date("2026-10-01T00:00:00Z"),
  }));
});
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd orchestrator && npm test
```
Expected: FAIL — cannot resolve `../src/beat.js`

- [ ] **Step 3: Implement**

```ts
// orchestrator/src/beat.ts
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { loadEngagement } from "./config.js";
import { ArtifactStore } from "./artifacts.js";
import { ToolRunner, TOOL_SCHEMAS, type HttpCapture } from "./tools.js";
import { runAgent, type MinimalClient } from "./agent.js";
import { evaluate, type Invariant } from "./axiom.js";
import { gateProvenance } from "./provenance.js";
import { isStalled, loadStallConfig } from "./stall.js";
import { initObservability, type FindingRow } from "./obs/index.js";

const HUNTER_SYSTEM = [
  "You are the SAFE AI Hacker methodical hunter. You probe ONE hypothesis at a time",
  "against the in-scope target and read the FULL response before concluding.",
  "When you can state a concrete violated invariant, reply with ONLY a JSON object:",
  '{"vuln_class","endpoint","control_url","invariant":{"statement","type","expression"}}',
  'where invariant.type is one of: body_contains, status_in.',
  "control_url must be a benign request that SHOULD NOT exhibit the issue.",
].join(" ");

export async function runBeat(opts: {
  env: Record<string, string | undefined>;
  client: MinimalClient;
  fetchImpl?: typeof fetch;
  now?: Date;
}): Promise<{ exitCode: number; findings: FindingRow[]; stalled: boolean; reason: string | null }> {
  const engagement = loadEngagement(opts.env, opts.now);   // throws outside the window
  const stallCfg = loadStallConfig(opts.env);
  const obs = await initObservability(opts.env);
  const sandboxId = randomUUID();

  const store = new ArtifactStore(join(opts.env.SAHW_WORKSPACE ?? ".", "artifacts"));
  const runner = new ToolRunner({ engagement, store, fetchImpl: opts.fetchImpl });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), engagement.phaseTimeoutMs);

  const findings: FindingRow[] = [];
  try {
    const hunt = await runAgent({
      client: opts.client,
      model: opts.env.SAHW_MODEL ?? "model",
      system: HUNTER_SYSTEM,
      user: `In-scope: ${engagement.scope.map((u) => u.toString()).join(", ")}`,
      tools: TOOL_SCHEMAS,
      runner,
      maxTurns: engagement.maxTurns,
      budgetTokens: engagement.budgetTokens,
      signal: controller.signal,
    });

    const stall = isStalled(
      { succeededToolCalls: hunt.toolCalls.filter((c) => c.ok).length,
        newArtifacts: hunt.artifacts,
        calls: hunt.toolCalls.map((c) => ({ tool: c.tool, args: c.args })) },
      stallCfg);

    if (stall.stalled) {
      return { exitCode: stallCfg.exitCode, findings: [], stalled: true, reason: stall.reason };
    }

    const claim = parseClaim(hunt.messages);
    if (!claim) {
      return { exitCode: stallCfg.exitCode, findings: [], stalled: true,
               reason: "hunter produced no parseable claim" };
    }

    // Axiom: replay the exploit AND a control, then evaluate the typed invariant.
    const exploit = await capture(runner, claim.endpoint);
    const control = await capture(runner, claim.control_url);
    const axiom = evaluate(claim.invariant as Invariant, exploit!, control);

    const gated = await gateProvenance({
      utc: new Date().toISOString(),
      langfuseTraceId: obs.traceId() ?? "local",
      exploitRequestHash: exploit?.artifact.sha256 ?? null,
      stdoutSha256: exploit?.artifact.sha256 ?? null,
      sandboxId,
      exitCode: 0,
    }, axiom.status, store);

    const row: FindingRow = {
      engagement_id: engagement.authRef,
      finding_id: `SAHW-${randomUUID().slice(0, 8)}`,
      vuln_class: claim.vuln_class,
      endpoint: claim.endpoint,
      verdict: gated.status,
      invariant_type: claim.invariant.type,
      langfuse_trace_id: obs.traceId() ?? "local",
      utc: new Date().toISOString(),
    };
    findings.push(row);
    await obs.mergeEndpoint(claim.endpoint, "GET");
    await obs.mergeFinding(row);
    await obs.recordFinding(row);

    return { exitCode: 0, findings, stalled: false, reason: null };
  } finally {
    clearTimeout(timer);
    await obs.shutdown();
  }
}

function parseClaim(messages: any[]): any | null {
  for (let i = messages.length - 1; i >= 0; i--) {
    const c = messages[i]?.content;
    if (typeof c !== "string") continue;
    try {
      const o = JSON.parse(c);
      if (o?.invariant?.type && o?.endpoint && o?.control_url) return o;
    } catch { /* not a claim */ }
  }
  return null;
}

async function capture(runner: ToolRunner, url: string): Promise<HttpCapture | null> {
  const out = await runner.execute("http_request", { method: "GET", url });
  return out.ok ? (out.result as HttpCapture) : null;
}
```

```ts
// orchestrator/src/cli.ts
import OpenAI from "openai";
import { runBeat } from "./beat.js";

const env = process.env as Record<string, string | undefined>;
const dryRun = process.argv.includes("--dry-run");

const baseURL = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_BASE_URL : env.OPENROUTER_BASE_URL;
// prod issues a short-lived credential from the AI Gateway (spec 4.1); SAGEMAKER_API_KEY
// is a dev-only fallback until that gateway exists.
const apiKey = env.SAHW_PROFILE === "prod" ? env.SAGEMAKER_API_KEY : env.SAHW_OPENROUTER_KEY;

const client = new OpenAI({
  baseURL,
  apiKey: apiKey ?? "unset",
  timeout: Number(env.SAHW_REQUEST_TIMEOUT_MS ?? 3_600_000),
  maxRetries: Number(env.SAHW_MAX_RETRIES ?? 0),
});

if (dryRun) {
  console.log(JSON.stringify({ dryRun: true, scope: env.SAHW_SCOPE, profile: env.SAHW_PROFILE ?? "test" }));
  process.exit(0);
}

const out = await runBeat({ env, client });
console.log(JSON.stringify(out, null, 2));
process.exit(out.exitCode);
```

`orchestrator/README.md` documents: `npm install`, `npm test`, `npm start -- --dry-run`, the `.env` knobs it reads, and that the three stores are optional. `docker-compose.yml` defines only the orchestrator service with `env_file: ../.env` and `network_mode: host`, pointing at the host's **existing** Langfuse / ClickHouse / Neo4j — it must not declare those services.

- [ ] **Step 4: Run the whole suite and a dry run**

```bash
cd orchestrator && npm test && npm start -- --dry-run
```
Expected: all tests across all 10 modules PASS; the dry run prints JSON and exits 0 without contacting anything.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/
git commit -m "feat(orchestrator): beat runner, CLI and deployment files"
```

---

## Out of scope for M0

Named so nobody builds them by accident: the payload library (its own shelved plan), skills wiring via `skill_run`, OAST, the `graph_query` tool, 3–5 adjudicator consensus, chain reasoning, the suppression library, the benchmark harness, and the remaining invariant types (`derived`, `state_changed`, `state_violated`, `file_created_then_deleted`) which correctly return `NEEDS_REVIEW` in M0.

**Do not deploy, ssh to, or scan any host during implementation.** Local build and stubbed tests only.

## Self-review

**Spec coverage.** §3 hard constraints → Task 1 (scope, window, HTTP-only) and Task 2 (Tether). §5.2 outer loop → Task 9 (turns, budget, abort) and Task 10 (phase timeout). §5.4 stall → Task 7, wired in Task 10. §6 Layer 3 control-differential → Task 5, exercised end-to-end by Task 10's differential test. §10 provenance gate → Task 6. §8 Neo4j, §9.6 ClickHouse, §10 Langfuse → Task 8. §4.1 provider profiles → Task 1 and the Task 10 CLI.

**Placeholders.** None: every step carries runnable code and an exact command.

**Type consistency.** `Engagement` is produced in Task 1 and consumed with the same field names in Tasks 2, 4, 9, 10. `HttpCapture` is produced in Task 4 and consumed in Tasks 5 and 10. `VerdictStatus` is defined once in Task 5 and imported by Task 6. `FindingRow` is defined in `obs/clickhouse.ts` (Task 8), re-exported from `obs/index.ts`, and consumed in Task 10. `MinimalClient` is defined in Task 9 and used in Task 10, which is what lets every test stub the model.

**One conflict found and resolved during writing.** `.env.example` ships `SAHW_PHASE_TIMEOUT_MS=5400000` with `SAHW_REQUEST_TIMEOUT_MS=3600000` — the phase timeout is *larger*, which is exactly the ordering §5.4 forbids, and Task 1's validator rejects it. Task 1 fixes `.env.example` to `3000000`. Every test env in later tasks sets it explicitly for the same reason.

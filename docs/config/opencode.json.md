# `opencode.json` — SAFE AI Hacker (documented config spec)

> **This is a documentation spec, not a wired runtime file.** It shows the intended
> `opencode.json` for each execution-engine container. Keys reflect the OpenCode config
> schema (`provider`, `mcp`, `permission`, `agent`/`.opencode/agents`, `plugin`).
> Secrets are **never** written here — they are injected as environment variables /
> Docker secrets at runtime.

## Design intent

- **Model Routing Plane.** Default provider is **OpenRouter** (model-agnostic); a
  **SageMaker/GLM** provider is the fallback for sensitive/air-gapped targets. Agents
  reference logical model names (`{{REASONING_MODEL}}`, `{{FAST_MODEL}}`) resolved here.
- **Skills-as-tools.** The existing `./skills` library (36 Anthropic-spec skills) is mounted
  via the `opencode-skills` plugin, so agents call skills as dynamic tools — no re-authoring.
- **MCP servers.** `mcp-patt` (PayloadsAllTheThings retrieval) and `mcp-oast` (out-of-band
  callbacks). **No external closed decision service is embedded** — the framework stays
  self-contained (see below).
- **Deciders are deterministic code + a configurable judge model (jev is NOT in the framework).**
  - **AI Hacker Tether** (scope/safety gate) is **pure deterministic code**: a scope allowlist
    derived from the provided in-scope URLs + a destructive-command AST check. A configurable
    judge model (routed via the provider block — OpenRouter or the SageMaker/GLM fallback) is
    consulted only for genuinely ambiguous escalation — never as the hard gate.
  - **AI Hacker Axiom** (validation core) is **deterministic invariant replay** (body_contains,
    status_in, state_changed, file_created_then_deleted, derived transforms). A configurable
    judge model is used only for fuzzy calls (e.g. severity band) or to escalate to the
    `adjudicator` agent / a human. jev/TypeSafe is intentionally excluded from the shipped system.
- **Permission map + Tether.** Wildcard `permission` sets baseline tool posture; the
  **Tether** plugin (`tool.execute.before`) is the hard enforcement point (scope + destructive
  AST). **No port scanning, no subdomain/CT enumeration** — the Tether denies any
  host/port outside the provided in-scope URLs.

## Reference `opencode.json`

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "provider": {
    "openrouter": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OpenRouter Gateway",
      "options": {
        "baseURL": "https://openrouter.ai/api/v1",
        "headers": { "HTTP-Referer": "https://safe-ai-hacker.local", "X-Title": "SAFE AI Hacker" }
        // OPENROUTER_API_KEY injected via env / Docker secret — never in this file
      },
      "models": {
        "anthropic/claude-<reasoning>": { "name": "REASONING_MODEL" },
        "<fast-cheap-model>":            { "name": "FAST_MODEL" }
      }
    },
    "sagemaker-glm": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "SageMaker Fallback",
      "options": { "baseURL": "https://<sagemaker-endpoint>/openai/v1" },
      "models": { "glm-<ver>": { "name": "GLM Internal" } }
    }
  },

  "mcp": {
    "mcp-patt": { "type": "local", "command": ["node", "mcp/patt/server.js"] },
    "mcp-oast": { "type": "local", "command": ["node", "mcp/oast/server.js"] }
    // No external closed decision service. Axiom/Tether are deterministic code +
    // a configurable judge model (routed via the provider block below) for fuzzy calls only.
  },

  "permission": {
    "bash": "ask",            // baseline; the Tether plugin makes the real allow/deny call
    "webfetch": "ask",
    "edit": "deny",           // relaxed to "allow" only for exploit-constructor's container
    "mcp-patt_*": "allow",
    "mcp-oast_*": "allow"
  },

  "plugin": [
    ".opencode/plugin/tether.js",   // tool.execute.before: deterministic scope + destructive-AST gate
    ".opencode/plugin/ledger.js",     // event stream -> Langfuse + ClickHouse
    "opencode-skills"                 // mounts ./skills as dynamic tools
  ]
}
```

## Per-agent overrides (in `.opencode/agents/*.md` frontmatter, not here)
- `recon`, `client-intel`, `state-mapper`: `bash: allow`, `webfetch: allow` (HTTP-only; Tether-gated).
- `threat-model`, `novelty-synthesizer`, `stateful-prober`, `chain-reasoner`, `adjudicator`:
  `bash: deny`, `webfetch: deny` (read/reason only — they propose, they do not act).
- `exploit-constructor`: `bash: allow`, `edit: allow`, isolated network.

## Runtime secrets (env / Docker secrets — never in the workspace)
`OPENROUTER_API_KEY`, SageMaker credentials (judge + fallback model), Langfuse keys, ClickHouse DSN.
(No TypeSafe/jev key — jev is not part of the framework.)

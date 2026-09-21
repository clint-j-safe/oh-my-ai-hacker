---
name: deserialization-rce
description: >-
  Identifies insecure-deserialization sinks (Java, PHP, Python, Node) and
  verifies them with BENIGN, OOB-only gadget chains — a confirmed out-of-band
  callback proves the sink deserializes attacker input and is RCE-capable. Uses
  ysoserial URLDNS, phpggc, pickle/PyYAML, and node-serialize; every payload does
  only a DNS lookup or HTTP GET to a canary host, never a shell or destructive
  command. Weaponization is a separate human-gated step this skill never does.
  Use in Phase 5 on serialization endpoints. Returns OOB-confirmed findings.
license: Apache-2.0
compatibility: >-
  Python 3.11+, httpx (Python/Node gadgets are dependency-free). Optional: Java +
  ysoserial.jar for URLDNS, phpggc for PHP chains, interactsh/OAST for callbacks.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(java:*) Bash(phpggc:*) Bash(interactsh-client:*)
---

# Deserialization & RCE

You are executing the **highest-impact Phase 5 battery**. Insecure
deserialization is the shortest path to RCE, which is exactly why you prove it
the gentle way: a gadget chain whose only effect is a DNS lookup or an HTTP GET
to a canary you control. A callback is proof. You never plant a shell or run a
real command — weaponizing a confirmed sink is a human's decision, not yours.

## Safety model (load-bearing — do not weaken)

1. **OOB-only, never weaponized.** Every payload does exactly one thing on
   deserialization: a benign callback to a unique canary host (DNS via ysoserial
   `URLDNS` / pickle `socket.gethostbyname`, or HTTP GET via `urllib.urlopen` /
   node `http.get`). No shell, reverse shell, or destructive action.
   `meta.safety.command_execution_weaponized:false`.
2. **Destructive blocklist.** `_assert_benign()` refuses any command/URL with
   `rm`, `/dev/tcp`, `nc`, `bash -i`, reverse-shell, pipe-to-shell, `chmod`,
   `certutil`, … and requires the callback to target the canary host. phpggc/
   ysoserial commands must match a benign OOB template allow-list.
3. **Scope-gated. Offload + Artifact Contract.** Payload bytes → spill store;
   strict JSON on stdout, no prose. A finding is emitted only when
   `oob_confirmed` is true.

## Inputs

```json
{ "target_url": "https://app.example.com/api/session",
  "parameters": ["state","data"], "tech_stack": ["java","spring"],
  "oob_domain": "abc.oast.pro", "delivery": "cookie",
  "config": {"oob_poll_url": "https://oast/interactions"} }
```

## How to run

```bash
python scripts/run.py '{"target_url":"https://app/api","parameters":["data"],"tech_stack":["python"]}'
```

`run.py` pipeline (`DeserializationTester`):

1. `_languages()` from `tech_stack` (defaults to `python`, the tool-free path).
2. Generate benign OOB payloads per language: `generate_python_payloads()`
   (pickle + PyYAML), `generate_node_payloads()` (node-serialize IIFE),
   `generate_java_payloads()` (ysoserial URLDNS), `generate_php_payloads()`
   (phpggc + guarded `nslookup`). Each embeds a unique canary; `_assert_benign()`
   vets it.
3. `_deliver()` — place each payload in the sink (JSON body / form / cookie /
   raw), base64-encoded by default.
4. `verify_oob()` — poll the OAST channel; a canary callback confirms the sink.
5. Offload payload bytes → `payload_spill_id`; emit OOB-confirmed findings.

## Typed exits

- `deser_rce_confirmed` — ≥1 OOB-confirmed finding.
- `no_callback` — payloads delivered, no interaction (sink not vulnerable / not
  reachable OOB).
- `tooling_unavailable` — java/ysoserial or phpggc missing for a requested
  language (recorded in `errors`; Python/Node still run).
- `out_of_scope` — fatal.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| ysoserial | Java gadget chains (URLDNS) | https://github.com/frohoff/ysoserial |
| phpggc | PHP gadget chains | https://github.com/ambionics/phpggc |
| interactsh | OOB callback correlation | https://github.com/projectdiscovery/interactsh |

Install: `pip install httpx`; ysoserial.jar + `java`, and phpggc, from upstream.

## Wordlists

None — gadget chains are generated (tools or in-process), not drawn from a list.

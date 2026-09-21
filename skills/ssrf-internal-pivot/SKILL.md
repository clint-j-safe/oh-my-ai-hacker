---
name: ssrf-internal-pivot
description: >-
  Tests parameters for Server-Side Request Forgery using loopback/IP-encoding
  bypasses, cloud-metadata (AWS/GCP/Azure IMDS) reachability, internal-host
  fingerprinting, and blind SSRF via OOB canary callbacks. Detection and
  read-only proof only — it proves the server can be coerced into fetching an
  attacker-chosen URL and reads NON-sensitive metadata as proof; the IAM
  credential path is never fetched. Use in Phase 5 on parameters that take a URL.
  Returns findings with offloaded internal responses. Do NOT use for internal
  exploitation.
license: Apache-2.0
compatibility: >-
  Python 3.11+, httpx. Optional: interactsh-client (or an OAST poll endpoint)
  for blind SSRF correlation. Network access to the in-scope target.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(interactsh-client:*)
---

# SSRF & Internal Pivot

You are executing a **Phase 5 offensive battery**. You prove that a URL
parameter causes the server to make requests you control — to its own loopback,
to internal hosts, or to the cloud metadata service — and you read just enough
to prove it. You do not steal cloud credentials and you do not exploit internal
services.

## Safety model (load-bearing — do not weaken)

1. **No credential theft.** The AWS IAM `security-credentials` path, Azure
   `identity/oauth2/token`, and GCP `service-accounts` are hard-excluded and
   never sent. IMDS reachability is proven with benign paths (instance-id, the
   meta-data index). `meta.safety.credential_paths_probed` is always `false`.
2. **Read-only, http(s) only.** GET probes only; no `file://`/`gopher://`, no
   writes, no exploitation of a reached internal service beyond a fingerprinting
   GET. `meta.safety.internal_exploitation:false`.
3. **Scope-gated.** Only the in-scope `target_url` host is driven; out of scope
   is fatal before any probe.
4. **Offload + Artifact Contract.** Full internal responses → spill store; strict
   JSON on stdout, no prose.

## Inputs

```json
{ "target_url": "https://app.example.com/proxy?url=1",
  "parameters": ["url","callback","redirect"],
  "oob_domain": "abc.oast.pro",
  "config": {"internal_targets": ["http://10.0.0.5:8080/"],
             "oob_poll_url": "https://oast.example/interactions"} }
```

## How to run

```bash
python scripts/run.py '{"target_url":"https://app.example.com/proxy?url=1","parameters":["url"]}'
```

`run.py` pipeline (`SSRFTester`):

1. Scope check (fatal if out of scope). Load payloads from
   `assets/ssrf-payloads.txt` (+ `config.internal_targets`); credential paths
   are stripped on load.
2. Per-parameter **control baseline** (fetch a closed internal port) so a real
   internal hit is distinguished from the app's normal error response.
3. `test_bypasses_and_metadata()` — inject each loopback/encoding/metadata probe;
   classify by response signature (`cloud_metadata` vs `full_response`) and
   fingerprint the internal `Server`.
4. `test_blind_oob()` — inject canary OOB hosts, then `_poll_oob()` correlates
   callbacks via `config.oob_poll_url` / interactsh-client. Uncorrelated
   canaries are reported as pending for the OOB handler (component #18).
5. Offload each internal response → `evidence_spill_id`.

## Typed exits

- `ssrf_confirmed` — ≥1 finding (full_response / cloud_metadata / blind_oob).
- `metadata_reachable` — a `cloud_metadata` finding (high severity; IAM path NOT
  retrieved — flag for human-gated escalation).
- `no_ssrf` — parameters tested, no internal reach.
- `out_of_scope` — fatal (`meta.status: "error"`).

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| interactsh | OOB/OAST blind-SSRF callback correlation | https://github.com/projectdiscovery/interactsh |
| httpx | Async HTTP probing | https://github.com/encode/httpx |

Install: `pip install httpx` (+ interactsh-client from upstream for OOB).

## Wordlists

`assets/ssrf-payloads.txt` — loopback/IP-encoding bypasses, benign cloud-metadata
paths (IAM credential path excluded), and the OOB canary template. For a broader
manual set: SecLists SSRF
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SSRF).

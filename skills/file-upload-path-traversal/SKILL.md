---
name: file-upload-path-traversal
description: >-
  Tests file-upload endpoints for MIME/magic-byte filter bypasses using BENIGN
  canary polyglots, and file-inclusion sinks for LFI (path traversal, php://filter
  source disclosure) and RFI (OOB-only). Uploads carry a harmless echo-canary PHP
  (never a webshell) and run only with mutation authorization; LFI reads benign
  targets only; RFI is confirmed by OOB callback with no shell served. Use in
  Phase 5 on upload and inclusion sinks. Returns findings with offloaded evidence.
license: Apache-2.0
compatibility: Python 3.11+, httpx. Optional interactsh/OAST for RFI.
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  phase: "5"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*) Bash(interactsh-client:*)
---

# File Upload & Path Traversal

You are executing a **Phase 5 offensive battery** with real RCE potential. You
prove that an upload filter can be bypassed and that traversal/inclusion sinks
reach files or remote URLs — and you prove it with the gentlest possible
evidence: a file that echoes a canary, a read of a public file, a DNS ping. You
never plant a shell.

## Safety model (load-bearing — do not weaken)

1. **Benign uploads, never webshells.** Polyglots carry `<?php echo '<canary>';
   ?>` only — no exec/eval/file-write/network. A rendered canary proves
   execution harmlessly. `meta.safety.webshell_payloads:false`.
2. **Uploads are mutations.** They run only under `config.authorize_mutations`
   (mutation budget) and are recorded in `meta.mutations` (with the stored path)
   for cleanup. Unauthorized ⇒ uploads skipped, LFI/RFI still run.
3. **LFI reads benign targets only.** `/etc/passwd`, `/etc/hostname`, php filter
   source disclosure — `shadow`/`id_rsa`/`.aws`/`.env`/`wp-config` are
   hard-excluded. Read-only.
4. **RFI is OOB-only.** A canary URL's fetch is confirmed by callback; **no shell
   is served** (`rfi_shell_served:false`).
5. **Scope-gated. Offload + Artifact Contract.** Uploaded content + LFI responses
   → spill store; strict JSON on stdout, no prose.

## Inputs

```json
{ "target_base": "https://app.example.com",
  "upload_endpoints": [{"url": "/upload", "field": "file"}],
  "inclusion_sinks": [{"url": "/view", "param": "page"}],
  "oob_domain": "abc.oast.pro",
  "config": {"authorize_mutations": true} }
```

## How to run

```bash
python scripts/run.py '{"target_base":"https://app","inclusion_sinks":[{"url":"/view","param":"page"}]}'
```

`run.py` pipeline (`UploadLFITester`):

1. `test_polyglot_uploads()` (gated) — post each `assets/polyglots/manifest.json`
   polyglot with a spoofed content-type; locate the stored URL; fetch it; a
   rendered canary = execution.
2. `test_lfi_traversal()` — traversal payloads for benign targets + php://filter
   source disclosure; passwd/PHP-source signatures confirm.
3. `test_rfi_oob()` — inject a canary URL; correlate a callback via the OOB
   poller; no shell served.
4. Offload evidence → `evidence_spill_id`; record uploads in `meta.mutations`.

## Typed exits

- `upload_rce` — a `malicious_upload` with `code_executed:true`.
- `lfi_confirmed` / `rfi_confirmed` — inclusion sink reached a file / remote URL.
- `uploads_authorization_required` — upload endpoints present but no mutation
  budget (LFI/RFI still ran).
- `no_findings` — sinks tested, nothing confirmed.

## External tools

| Tool | Purpose | URL |
| --- | --- | --- |
| interactsh | RFI OOB callback correlation | https://github.com/projectdiscovery/interactsh |
| httpx | Async HTTP / multipart uploads | https://github.com/encode/httpx |

Install: `pip install httpx`.

## Wordlists

`assets/polyglots/manifest.json` — benign canary polyglots (magic bytes + echo
PHP). Reference sets: SecLists File-Upload
(https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/File-Upload) and
LFI (https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI).

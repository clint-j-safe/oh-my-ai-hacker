# Artifact Contract — `file-upload-path-traversal`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (no endpoints, no httpx) the skill emits a schema-valid artifact
with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "file-upload-path-traversal artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["vuln_class", "endpoint", "payload"],
        "properties": {
          "vuln_class": { "enum": ["malicious_upload","LFI","RFI"] },
          "endpoint": { "type": "string" },
          "payload": { "type": "string" },
          "accessed_file": { "type": "string" },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `confidence`, `code_executed`, `meta`,
`scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target_base": "https://app.example.com",
  "upload_endpoints": [{"url": "/upload", "field": "file"}],
  "inclusion_sinks": [{"url": "/view", "param": "page"}],
  "oob_domain": "abc.oast.pro",
  "scope_policy_spill_id": "abc123",
  "config": {"authorize_mutations": false, "oob_poll_url": "https://oast/interactions",
             "lfi_targets": ["/etc/passwd"], "lfi_php_targets": ["index.php"],
             "upload_field": "file"}
}
```

* `upload_endpoints` — each `{url, field}` (multipart file field name).
* `inclusion_sinks` — each `{url, param}` (the LFI/RFI parameter).
* `oob_domain` / `config.oob_poll_url` — RFI OOB correlation.
* `config.lfi_targets` — benign files to read (default `/etc/passwd`,
  `/etc/hostname`); `lfi_php_targets` — source files for php://filter disclosure.

---

## 3. Safety model (real RCE potential — read this)

| Class | Proof | Guard |
| --- | --- | --- |
| **malicious_upload** | A benign canary polyglot (`<?php echo '<canary>'; ?>`) bypasses the filter; if the canary renders on access, code executed (`code_executed:true`). | **Never a webshell** — no exec/eval/file-write/network. Uploads mutate, so they run only under `config.authorize_mutations` (mutation budget) and are recorded in `meta.mutations` for cleanup. `meta.safety.webshell_payloads:false`. |
| **LFI** | Path traversal / php://filter reads a **benign** target (`/etc/passwd`, `/etc/hostname`, source disclosure). | Credential/secret files (`shadow`, `id_rsa`, `.aws/credentials`, `.env`, `wp-config`, …) are hard-excluded. Read-only. `meta.safety.lfi_targets_benign:true`. |
| **RFI** | A canary URL is injected and its fetch is confirmed by an **OOB callback**. | **No shell is ever served** — there is no remote code to execute. `meta.safety.rfi_shell_served:false`. |

Uploads without authorization are skipped (LFI/RFI still run);
`meta.uploads_authorization_required` flags this. Scope-gated; uploaded content
and LFI responses offloaded to `evidence_spill_id`.

---

## 4. Detection

* **Uploads** — each polyglot is posted with a spoofed content-type; the stored
  URL is located from the response and fetched. Canary in the response ⇒
  execution (`confirmed`); a stored PHP-extension file that didn't render ⇒
  filter bypass (`suspected`).
* **LFI** — traversal payloads (`../`×N, `....//`, `%2e%2e%2f`, encoded) for each
  benign target; a `/etc/passwd` signature (`root:.*:0:0:`) or a php://filter
  base64 blob that decodes to PHP source (`<?php`) confirms it.
* **RFI** — a canary URL injected into the sink; an OOB interaction carrying the
  canary confirms the server fetched it.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"vuln_class": "malicious_upload", "endpoint": "https://app.example.com/upload",
     "payload": "avatar.php (image/gif, magic=gif89a_php)",
     "accessed_file": "https://app.example.com/uploads/avatar.php",
     "confidence": "confirmed", "code_executed": true, "evidence_spill_id": "9f2a…"},
    {"vuln_class": "LFI", "endpoint": "https://app.example.com/view",
     "payload": "../../../../../../../../etc/passwd", "accessed_file": "/etc/passwd",
     "confidence": "confirmed", "code_executed": false, "evidence_spill_id": "0f1e…"},
    {"vuln_class": "RFI", "endpoint": "https://app.example.com/view",
     "payload": "http://rfi9a8b.abc.oast.pro/probe.txt", "accessed_file": "",
     "confidence": "confirmed", "code_executed": false, "evidence_spill_id": "7c1e…"}
  ],
  "meta": {"skill": "file-upload-path-traversal", "status": "ok",
           "counts": {"malicious_upload": 1, "LFI": 1, "RFI": 1},
           "safety": {"uploads_authorized": true, "webshell_payloads": false,
                      "lfi_targets_benign": true, "rfi_shell_served": false},
           "mutations": [{"action": "file_upload", "endpoint": "…/upload",
                          "filename": "avatar.php", "benign_canary": "UPL…"}]},
  "scope_summary": {"policy_present": true},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.webshell_payloads` / `rfi_shell_served` are `false` and
   `lfi_targets_benign` is `true`; no finding `payload`/`accessed_file` contains
   an excluded credential/secret path.
3. every `malicious_upload` has a matching `meta.mutations` entry (cleanup handle).
4. every finding's `evidence_spill_id` resolves in the spill store.

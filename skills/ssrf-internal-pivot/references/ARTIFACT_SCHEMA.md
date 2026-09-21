# Artifact Contract — `ssrf-internal-pivot`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (out of scope, no params, no httpx) the skill emits a schema-valid
artifact with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ssrf-internal-pivot artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["parameter", "ssrf_type", "evidence_spill_id"],
        "properties": {
          "parameter": { "type": "string" },
          "ssrf_type": { "enum": ["full_response","blind_oob","cloud_metadata"] },
          "payload": { "type": "string" },
          "internal_ip_reached": { "type": "string" },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `server_fingerprint`, `status`, `confidence`,
`meta`, `scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target_url": "https://app.example.com/proxy?url=1",
  "parameters": ["url", "callback", "redirect"],
  "oob_domain": "abc123.oast.pro",
  "scope_policy_spill_id": "abc123",
  "config": {
    "internal_targets": ["http://10.0.0.5:8080/", "http://192.168.1.10/"],
    "oob_poll_url": "https://oast.example/interactions",
    "concurrency": 8
  }
}
```

* `target_url` (**required**) — the endpoint whose parameter is fetched
  server-side (the SSRF sink), in scope.
* `parameters` (**required**) — parameters to inject the probe URL into.
* `oob_domain` — OAST/interactsh domain for blind SSRF canaries.
* `config.internal_targets` — extra internal URLs (e.g. from recon) to probe.
* `config.oob_poll_url` — an interactsh-style endpoint returning a JSON array
  (or `{interactions:[…]}`) of interaction strings, used to correlate canaries.

---

## 3. Safety model (offensive tooling — read this)

| Guard | Enforcement |
| --- | --- |
| Credential paths | `iam/security-credentials`, Azure `identity/oauth2/token`, GCP `service-accounts` are hard-excluded from probing (`_forbidden`) and never sent. `meta.safety.credential_paths_probed` is always `false`, and each evidence blob records `credential_paths_probed:false`. |
| Read-only | Only `http`/`https` GET probes. No `file://`/`gopher://`, no writes, no exploitation of a reached internal service beyond a GET used to fingerprint. `meta.safety.internal_exploitation:false`. |
| Proof | Cloud SSRF is proven via benign metadata (instance-id / meta-data index); the IAM key path is never fetched. |
| Scope | Only the in-scope `target_url` host is driven; out of scope → fatal before any probe. |
| Offload | Full internal response bodies → `evidence_spill_id` (truncated to 20 KB in spill), never inlined. |

---

## 4. Detection methods → `ssrf_type`

* **cloud_metadata** — the reached response carries metadata signatures
  (`instance-id`, `computeMetadata`, `Metadata-Flavor`, `azEnvironment`, …) or
  the payload host is a known IMDS host.
* **full_response** — the target reflected an internal service's response (a
  `Server:` banner like `nginx`, a private-range host, or an internal HTML
  title) that differs from the per-parameter control baseline.
* **blind_oob** — an injected canary host produced an OOB interaction correlated
  via the poller (`confidence: confirmed`). Canaries with no callback within the
  wait window are reported in `errors` as pending, for the OOB-handling
  component (#18) to correlate later.

`internal_ip_reached` is the probe URL's host; `server_fingerprint` is the
detected internal server token.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"parameter": "url", "ssrf_type": "cloud_metadata",
     "payload": "http://169.254.169.254/latest/meta-data/instance-id",
     "internal_ip_reached": "169.254.169.254", "server_fingerprint": "",
     "status": 200, "evidence_spill_id": "9f2a1c7b6d4e0a53"},
    {"parameter": "url", "ssrf_type": "full_response",
     "payload": "http://127.0.0.1/", "internal_ip_reached": "127.0.0.1",
     "server_fingerprint": "nginx", "status": 200, "evidence_spill_id": "0f1e2d3c4b5a6978"},
    {"parameter": "callback", "ssrf_type": "blind_oob",
     "payload": "http://s1a2b3.abc123.oast.pro/", "internal_ip_reached": "",
     "confidence": "confirmed", "evidence_spill_id": "7c1e9a0b4d5f2318"}
  ],
  "meta": {"skill": "ssrf-internal-pivot", "status": "ok", "payloads_tried": 15,
           "oob_canaries_injected": 2,
           "safety": {"credential_paths_probed": false, "internal_exploitation": false, "read_only": true}},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.credential_paths_probed` and `internal_exploitation` are `false`
   and no finding `payload` contains an excluded credential path.
3. every finding's `evidence_spill_id` resolves in the spill store.
4. the driven host equals `scope_summary.target_host` and was in scope.

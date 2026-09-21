# Artifact Contract — `deserialization-rce`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (out of scope, no params) the skill emits a schema-valid artifact
with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "deserialization-rce artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["language", "gadget_chain", "parameter"],
        "properties": {
          "language": { "enum": ["java","php","python","node","ruby"] },
          "gadget_chain": { "type": "string" },
          "parameter": { "type": "string" },
          "payload_spill_id": { "type": "string" },
          "oob_confirmed": { "type": "boolean" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `meta`, `scope_summary`, `errors`):
`references/artifact.schema.json`. **A finding is only emitted when
`oob_confirmed` is true** — a callback proves the sink deserialized our input.

---

## 2. Input contract

```json
{
  "target_url": "https://app.example.com/api/session",
  "parameters": ["state", "data"],
  "tech_stack": ["java", "spring"],
  "oob_domain": "abc.oast.pro",
  "delivery": "json | form | cookie | raw",
  "scope_policy_spill_id": "abc123",
  "config": {"oob_poll_url": "https://oast/interactions", "encoding": "base64",
             "phpggc_chain": "Guzzle/FW1"}
}
```

* `tech_stack` selects the gadget languages (`java`/`php`/`python`/`node`).
  With none recognized it defaults to `python` (the tool-free, safest path).
* `delivery` — where the payload is placed (JSON body / form / cookie / raw body).
* `oob_domain` / `config.oob_poll_url` — the OOB channel for callback correlation.

---

## 3. Safety model (the highest-impact skill — read this)

| Guard | Enforcement |
| --- | --- |
| **OOB-only, never weaponized** | Every payload does exactly one thing on deserialization: a benign callback to a unique canary host — a DNS resolution (ysoserial `URLDNS`, pickle `socket.gethostbyname`) or an HTTP GET (`urllib.request.urlopen`, node `http.get`). No shell, reverse shell, file/registry/network action beyond the ping. `meta.safety.command_execution_weaponized:false`. |
| **Destructive blocklist** | `_assert_benign()` refuses any embedded command/URL containing `rm`, `/dev/tcp`, `nc`, `bash -i`, reverse-shell, pipe-to-shell, `chmod`, `certutil`, etc., **and** requires the callback to target the canary host — no arbitrary destinations. phpggc/ysoserial commands must additionally match an allow-list of benign OOB templates (`nslookup`/`host`/`dig`/`curl -s <canary>`). |
| **Scope** | Only the in-scope target host is driven. |
| **Custody** | Generated payload bytes (base64) + descriptors are offloaded to `payload_spill_id`. |

Weaponizing a confirmed sink (real command execution) is a **separate,
human-gated escalation** this skill never performs.

---

## 4. Gadget chains

| Language | Chain | Callback |
| --- | --- | --- |
| Java | `URLDNS` (preferred — pure DNS, no command) via ysoserial | DNS lookup of the canary |
| PHP | `phpggc <chain> system "nslookup <canary>"` (guarded) | DNS lookup |
| Python | `pickle` (`urllib.request.urlopen` / `socket.gethostbyname`), PyYAML `!!python/object/apply` | HTTP GET / DNS |
| Node | `node-serialize` IIFE `http.get(<canary>)` | HTTP GET |

Java/PHP require `java`+`ysoserial.jar` / `phpggc`; absent tools are recorded in
`errors` and skipped. The Python path is dependency-free.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"language": "python", "gadget_chain": "pickle:urlopen", "parameter": "data",
     "payload_spill_id": "9f2a1c7b6d4e0a53", "oob_confirmed": true}
  ],
  "meta": {"skill": "deserialization-rce", "status": "ok", "languages": ["python"],
           "payloads_generated": 3, "oob_interactions": 1,
           "safety": {"oob_only": true, "command_execution_weaponized": false,
                      "destructive_blocklist": true, "callback_forms": ["dns","http_get"]}},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. `meta.safety.command_execution_weaponized` is `false` and `oob_only` is
   `true`; no payload descriptor contains a destructive token.
3. every finding has `oob_confirmed: true` and a resolving `payload_spill_id`.
4. the driven host equals `scope_summary.target_host` and was in scope.

# Artifact Contract — `injection-battery-xxe-ssti-nosql`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Observer. On
fatal error (out of scope, no params) the skill emits a schema-valid artifact
with empty `findings` and `meta.status == "error"`.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "injection-battery-xxe-ssti-nosql artifact",
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["vuln_class", "parameter", "payload"],
        "properties": {
          "vuln_class": { "enum": ["XXE","SSTI","NoSQL"] },
          "parameter": { "type": "string" },
          "payload": { "type": "string" },
          "engine_identified": { "type": "string" },
          "evidence_spill_id": { "type": "string" }
        }
      }
    }
  }
}
```

Machine copy (incl. additive `confidence`, `rce_capable`, `rce_executed`,
`rce_poc`, `meta`, `scope_summary`, `errors`): `references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "target_url": "https://app.example.com/greet",
  "parameters": ["name", "xml_data"],
  "tech_stack": ["php", "twig"],
  "oob_domain": "abc.oast.pro",
  "method": "POST",
  "content_type": "query | form | json | xml",
  "scope_policy_spill_id": "abc123",
  "config": {"oob_poll_url": "https://oast/interactions", "xxe_file": "/etc/hostname"}
}
```

* `content_type` decides delivery + which classes run: `xml` → XXE; `json`/`form`
  → NoSQL (+ SSTI); `query` → SSTI (+ NoSQL bracket form). `tech_stack` orders
  SSTI engine identification and can force XXE/NoSQL.
* `oob_domain` / `config.oob_poll_url` — blind XXE OOB correlation.

---

## 3. Safety model (offensive tooling — read this)

| Class | What is proven | What is NOT done |
| --- | --- | --- |
| **SSTI** | Code evaluation via arithmetic (`{{a*b}}` → product, random canary) + engine ID. | RCE is **emitted as `rce_poc` for human escalation, never executed** (`rce_executed:false`). tplmap runs detection-only; `--os-cmd`/`--os-shell`/`--reverse-shell`/upload/download are blocklisted (`_assert_safe_tplmap`). |
| **XXE** | Blind OOB callback, or in-band **benign** file read (`/etc/hostname`). | No entity-expansion / billion-laughs (DoS) payloads (`dos_entities:false`); no secret/credential file paths. |
| **NoSQL** | Read-only operator inference (`$ne`/`$gt`/`$regex`/`$exists`) via baseline differential. | No `$where` arbitrary-JS execution (`where_js_exec:false`). |

`meta.safety` echoes `{rce_executed:false, dos_entities:false, where_js_exec:false,
read_only_proof:true}` for the Observer to assert. Scope-gated; raw responses
offloaded to `evidence_spill_id`.

---

## 4. Detection details

* **SSTI** — for each arithmetic wrapper (`{{ }}`, `${ }`, `#{ }`, `<%= %>`, …),
  the payload is confirmed only when the **product appears and the literal
  wrapper does not** (evaluated, not reflected). Engine identified by
  distinctive probes (`{{7*'7'}}` → `7777777` Jinja2 vs `49` Twig; `${7*7}`
  Freemarker/Mako; `[[${7*7}]]` Thymeleaf; …).
* **XXE** — OOB entity canary correlated via the poller (`confirmed`), else an
  in-band file entity whose resolved content differs from an entity-free control.
* **NoSQL** — baseline (random value) vs operator injection; a flip to `2xx`
  from `401/403`, a large data increase, an auth-token appearing, or a Mongo
  error signature marks the finding.

---

## 5. Example artifact (abridged)

```json
{
  "findings": [
    {"vuln_class": "SSTI", "parameter": "name",
     "payload": "{{ 431*277 }}", "engine_identified": "Jinja2",
     "confidence": "confirmed", "rce_capable": true, "rce_executed": false,
     "rce_poc": "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
     "evidence_spill_id": "9f2a1c7b6d4e0a53"},
    {"vuln_class": "XXE", "parameter": "xml_data",
     "payload": "<?xml ...<!ENTITY xxe SYSTEM \"file:///etc/hostname\">...&xxe;...",
     "engine_identified": "external_entity_file:/etc/hostname",
     "confidence": "confirmed", "evidence_spill_id": "0f1e2d3c4b5a6978"},
    {"vuln_class": "NoSQL", "parameter": "username",
     "payload": "{\"$ne\": null}", "engine_identified": "operator_injection",
     "confidence": "confirmed", "evidence_spill_id": "7c1e9a0b4d5f2318"}
  ],
  "meta": {"skill": "injection-battery-xxe-ssti-nosql", "status": "ok",
           "classes_planned": ["SSTI","NoSQL"],
           "safety": {"rce_executed": false, "dos_entities": false,
                      "where_js_exec": false, "read_only_proof": true}},
  "scope_summary": {"policy_present": true, "target_host": "app.example.com"},
  "errors": []
}
```

---

## 6. Observer-side validation (reference)

1. stdout parses as JSON and validates against §1 / `artifact.schema.json`.
2. every SSTI finding has `rce_executed == false`; `meta.safety` flags are all
   the safe values (a `true` on `rce_executed`/`dos_entities`/`where_js_exec`
   quarantines the run).
3. every finding's `evidence_spill_id` resolves in the spill store.
4. the driven host equals `scope_summary.target_host` and was in scope.

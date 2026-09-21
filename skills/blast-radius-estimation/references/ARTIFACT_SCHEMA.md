# Artifact Contract — `blast-radius-estimation`

One strict JSON object on stdout matching the schema below. No prose; logs to
stderr. A non-parseable/invalid output is a **failure** to the Proposer. This
skill **sends no traffic** (`meta.sends_traffic:false`) and is **advisory only**
(`meta.advisory_only:true`) — the deterministic Safety Gate and the mutation
budget enforce; this only recommends.

---

## 1. JSON Schema (Draft 2020-12)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "blast-radius-estimation artifact",
  "type": "object",
  "required": ["risk_grade", "gentle_probe", "justification"],
  "properties": {
    "risk_grade": { "enum": ["read_only", "mutating", "destructive", "account_creating"] },
    "gentle_probe": {
      "type": "object",
      "properties": {
        "payload": { "type": "string" },
        "method":  { "type": "string" }
      }
    },
    "justification": { "type": "string" },
    "estimated_mutation_cost": {
      "type": "integer",
      "description": "State mutations the gentle probe will consume (0 for read-only)."
    }
  }
}
```

Machine copy (incl. additive `meta`/`errors` and richer `gentle_probe` fields):
`references/artifact.schema.json`.

---

## 2. Input contract

```json
{
  "proposed_action": {
    "url": "https://app.example.com/api/orders/42",
    "method": "DELETE",
    "payload": "'; DROP TABLE users;-- -",
    "vuln_class": "SQLi"
  },
  "config": {"oob_domain": "abc.oast.pro"}
}
```

* `proposed_action` — **required.** `url`, `method`, `payload`, `vuln_class` are
  all used; any may be empty. `vuln_class` is normalized (case/spacing/hyphens).
* `config.oob_domain` — the controlled OOB/OAST canary domain used to build
  out-of-band probes (SSRF/XXE/RCE). Defaults to `oob.canary.invalid` when absent.

---

## 3. Classification (`risk_grade`)

Grades, from gentlest to most severe: `read_only` < `account_creating` ≈
`mutating` < `destructive`. The grade of the **proposed** action is the higher of:

* **Payload verb** — destructive SQL/command verbs (`DROP/DELETE/TRUNCATE/ALTER/
  SHUTDOWN/xp_cmdshell`) ⇒ `destructive`; mutating verbs (`INSERT/UPDATE/REPLACE/
  MERGE/GRANT`) ⇒ `mutating`.
* **Vuln class intrinsic** — e.g. `rce`/`command_injection`/`deserialization` ⇒
  `destructive`; `stored_xss`/`file_upload`/`business_logic`/`csrf` ⇒ `mutating`;
  `sqli`/`xss`/`ssrf`/`ssti`/`xxe`/`idor`/`lfi`/`open_redirect` ⇒ `read_only` (to
  *confirm*); registration/signup ⇒ `account_creating`.
* **HTTP method baseline** — `GET/HEAD/OPTIONS` ⇒ `read_only`, `POST/PUT/PATCH` ⇒
  `mutating`, `DELETE` ⇒ `destructive`.

Account-creation endpoints (by class or URL like `/register`, `/signup`) are
graded `account_creating` outright.

---

## 4. Gentle-probe selection (the point of the skill)

For each vuln class, the gentlest confirming probe — benign, minimal, ideally
observational — with a per-run `canary` (`BR<hash8>`):

| Class | Gentle probe | Grade |
| --- | --- | --- |
| SQLi | boolean `' AND 1=1-- -` (time `SLEEP(5)` fallback) — reads/writes nothing | read_only |
| XSS | `<img src=x onerror=console.log('BR..')>` — execution marker, no exfil | read_only |
| SSRF | OOB callback `http://BR...oob/` — **never** metadata/internal | read_only |
| SSTI | `{{7*7}}` expecting `49` — no system calls | read_only |
| XXE | OOB external entity — no local file read | read_only |
| RCE / cmd / deser | benign OOB **DNS** callback — no command output/side effects | read_only |
| IDOR / BOLA | **read** one other-user resource — never delete/modify | read_only |
| NoSQLi | `{"$ne": null}` true/false differential — no data change | read_only |
| LFI / traversal | read `/etc/hostname` (benign) — **not** `/etc/shadow` | read_only |
| open redirect | benign canary destination | read_only |
| file upload | one benign `.txt` canary — no webshell | mutating (1) |
| business logic / CSRF | exactly ONE transaction, aborted before commit | mutating (1) |
| account creation | exactly ONE labelled test account | account_creating (1) |
| unknown | downgrade to a read-only re-issue | read_only |

**Invariants.** The probe grade is always `<=` the proposed grade (never
upgrades). A `destructive` proposal is never passed through: it is downgraded to
a read-only/OOB confirmation and `meta.recommend_abort_original:true`. Every
generated probe is asserted free of destructive OS/SQL tokens before emission; a
stray token neutralizes the probe to a plain read.

---

## 5. Example artifact (abridged — destructive SQLi proposal)

```json
{
  "risk_grade": "destructive",
  "gentle_probe": {"payload": "' AND 1=1-- -", "method": "GET"},
  "justification": "Proposed action graded 'destructive' (critical) because destructive SQL/command verb in payload. Selected gentle probe 'boolean-differential' — SQLi via boolean/time differential — reads nothing, writes nothing — which is 'read_only' and costs 0 state mutation(s). The original is DESTRUCTIVE and must not be executed as-is; confirm with the gentle probe and route any real exploitation through the sandbox/PoC path.",
  "estimated_mutation_cost": 0,
  "meta": {"skill": "blast-radius-estimation", "advisory_only": true, "severity": "critical",
           "proposed_grade": "destructive", "probe_grade": "read_only", "requires_oob": false,
           "recommend_abort_original": true, "original_impact": "irreversible",
           "mutation_budget_units": 0, "sends_traffic": false, "canary": "BR1a2b3c4d"},
  "errors": []
}
```

---

## 6. Proposer / budget-side use (reference)

1. Validate against §1 / `artifact.schema.json`.
2. Prefer `gentle_probe` over the raw action; charge the mutation budget
   `estimated_mutation_cost` (== `meta.mutation_budget_units`).
3. If `meta.recommend_abort_original` is `true`, do **not** submit the original
   destructive action; use the probe to confirm, then hand real exploitation to
   the sandbox/PoC path.
4. If `meta.requires_oob` is `true`, pair with `oob-blind-vuln-correlation` for
   confirmation.
5. Advisory only — the deterministic Safety Gate and mutation budget remain the
   enforcing authorities.

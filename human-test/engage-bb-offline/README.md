# UnSAFE Bank — Black-Box Engagement Offline Package

Self-contained offline copy of the black-box penetration test, taken from the operator host
`root@143.244.130.163:/opt/engage-bb/` on **2026-09-20**.

**Original archive:** `engage-bb-offline.tar.gz`
**Archive SHA-256:** `a9ecbefb550c2b850ed726048befd0547e4c0f8f0f580e8e72573368aa0b1cee`

## Contents

| Path | What it is |
|---|---|
| `report/report.md` | Full black-box report (target/operator IPs in clear) |
| `report/report-redacted.md` | Redacted copy (IPs replaced with placeholders) |
| `report/engagement-turn-log.md` | Step-by-step turn log with rationale and decisions |
| `report/artifact-index.txt` | SHA-256 of every collected artifact (189 files) |
| `audit.sh`, `audit.log` | Command wrapper and its 41 UTC-stamped target-facing invocations |
| `evidence/` | Request/response captures, extracted data, balance/statement proofs, phpinfo, CORS, SSRF attempts |
| `scans/` | `nmap -sV` output (XML, greppable, plain) |
| `web/` | Target-served client assets: JS bundles, recovered source maps, `ffuf` output, wordlist |
| `exploit/` | Test harness and PoC scripts (`api.py`, `t*.py`, helpers, `f9_proof.log`) |
| `recon/` | Passive notes (empty — the targets are IPs; no DNS/subdomain surface) |

Note: `exploit/__pycache__/` is an incidental Python bytecode cache from running the harness.

## Verify integrity

```bash
cd engage-bb-offline
shasum -a 256 report/artifact-index.txt      # compare against the operator host copy
while read -r h p; do [ "$(shasum -a 256 "$p" | awk '{print $1}')" = "$h" ] \
  && echo "OK $p" || echo "FAIL $p"; done < report/artifact-index.txt
```

All 189 entries verified at the time this copy was made.

## Engagement quick facts

- **Targets:** `http://139.59.15.10:3000/` (SPA), `http://139.59.15.10/api/` (PHP API)
- **Method:** black box — no application source read, no internet research; target-served
  JavaScript and its exposed source maps were used as the app's own public interface
- **Test accounts created:** `BNK95153` (A), `BNK00623` (B) — all state-changing tests confined to these
- **Cleanup:** balances restored, passwords restored, test beneficiary deleted, RCE proof file
  self-deleted (verified HTTP 404)

## Handling

Contains live secrets recovered during the test (database credential, application encryption key,
JWT signing key) because they are the subject of findings and are needed for remediation.
Treat as confidential.

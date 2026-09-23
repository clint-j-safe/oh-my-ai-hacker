---
name: payload-library
description: >-
  Queryable payload/wordlist arsenal. Given a vuln_class (and optional technique),
  returns a small, TARGETED set of probe strings — from the shipped wordlists and
  payload files (sqli/xxe/xss/ssrf injection sets, jwt secret candidates, directory
  wordlist, mass-assignment fields, path-traversal sequences, business-logic
  boundary values) plus curated built-ins — for the caller to fire via http_request.
  Makes NO network calls (pure file lookup). Use it to triage cheaply: pull one or a
  few probes for the class you are testing, fire them, and escalate a heavier set or
  a confirmation tool ONLY when a probe already shows a positive/near-positive signal
  on a specific endpoint+parameter. Returns a payloads artifact.
license: Apache-2.0
compatibility: "Python 3.11+, standard library only. No network, no third-party deps."
metadata:
  author: loop-engineered-pentest
  version: "1.0"
  loop-component: "4-dispatcher"
  artifact-schema: references/ARTIFACT_SCHEMA.md
allowed-tools: Bash(python:*)
---

# Payload Library (queryable arsenal)

You are pulling targeted probe strings from the engagement's arsenal so you do not
guess payloads or blindly iterate a wordlist. Query by `vuln_class`; narrow with
`technique` when you know the sub-approach.

## Contract
- Input: `{"vuln_class": "sqli", "technique": "error", "limit": 8}` (technique/limit optional).
- Output: strict JSON artifact (see references/ARTIFACT_SCHEMA.md) — a bounded list
  of `{value, note}` payloads, where `note` names the response signal that confirms a hit.

## Tradecraft (why this exists)
Cheap-probe-first, escalate-on-signal. Do NOT run a heavy tool (sqlmap/ghauri) or a
full wordlist against every endpoint — that wastes budget, floods traffic, and buries
signal. Instead: pull ONE cheap probe per (endpoint, parameter), fire it, read the
response. Only when you see the signal the `note` describes (a DB error, a reflected
marker, a behavioral/oracle differential) do you escalate — pull the fuller set for
that class or invoke the confirmation skill — and only on THAT endpoint+parameter.

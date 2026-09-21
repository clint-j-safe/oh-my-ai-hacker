# SDD ledger — plan: /Users/clintjosy/.claude/plans/safe-ai-hacker-serene-adleman.md

## Setup
- Spec (binding authority): docs/superpowers/specs/2026-09-22-safe-ai-hacker-design.md
- Workspace: .worktrees/feat-sahw-control-plane (git worktree, branch feat/sahw-control-plane)
- Baseline commit: fdad0a8

## Rulings
- Ruling: Build in a git worktree `feat/sahw-control-plane` off the baseline commit (repo had no commits, so a baseline snapshot commit was made first; no "main" content was at risk). — Cost if wrong: none material.
- Ruling: jev is a development-time validation aid ONLY, never a runtime dependency. Axiom/Tether are pure deterministic TypeScript (+ configurable judge model via OpenCode provider for fuzzy calls). User explicitly instructed "don't ingest jev into the framework". — Cost if wrong: framework gains an external closed-service dependency it was designed to avoid.

## Pre-flight (shared interfaces)
- scope → tether: Tether consumes Scope's normalized host:port allowlist.
- tether → orchestrator: Orchestrator calls Tether.decide before dispatching any tool action.
- axiom → orchestrator: Orchestrator calls Axiom.verify to finalize a finding.
- artifact-store → axiom/orchestrator: provenance (sha256, sandbox_id) stored by ArtifactStore, referenced by Axiom verdict + Provenance Gate.
- budget → orchestrator: Orchestrator checks Budget before each turn.

## Tasks
- [ ] Task 1: Scope allowlist (src/scope.ts)
- [ ] Task 2: Tether gate (src/tether.ts)
- [ ] Task 3: Axiom verdict (src/axiom.ts)
- [ ] Task 4: Artifact store + provenance (src/artifact-store.ts)
- [ ] Task 5: Budget governor (src/budget.ts)
- [ ] Task 6: Orchestrator phase machine + OpenCode SDK (src/orchestrator.ts)
- [ ] Task 7: opencode.json + agents + plugins (tether/ledger)
- [ ] Task 8: Alpine per-tool containers + docker-compose
- [ ] Task 9: OOB + reverse-shell listener
- [ ] Task 10: Deploy to root@143.244.130.163
Task 1: complete (commits fdad0a8..HEAD, tests: npx vitest run src/scope.test.ts -> 13/13 pass)
Task 2: complete (tests: npx vitest run src/tether.test.ts -> 22/22 pass)
Task 3: complete (tests: npx vitest run src/axiom.test.ts -> 13/13 pass)
  Ruling: body_contains "marker in both exploit+control" -> FALSE_POSITIVE (was NEEDS_REVIEW). Differential test failing disproves the claim. jev cross-check agreed (0.91). Cost if wrong: a real finding whose control was mis-built would be auto-dismissed; mitigated by exploit-constructor emitting a proper control.
Task 4: complete (tests: npx vitest run src/artifact-store.test.ts -> 7/7 pass)
Task 5: complete (tests: npx vitest run src/budget.test.ts -> 6/6 pass)
Task 6: complete (tests: npx vitest run -> 72/72 pass)
  Ruling: Budget got canContinue() (strict < on all limits) as the pre-turn gate; check() (> limit) remains the post-turn overage detector. Cost if wrong: none material (complementary).

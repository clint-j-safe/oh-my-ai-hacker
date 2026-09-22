"""Benchmark scoring harness for the human-test 28-finding ground truth.

Deliberately kept as a stdlib-only, top-level Python package (bench/), separate from
orchestrator/src (TypeScript). This is a structural guarantee, not a convention: the
orchestrator literally cannot `import` this package, so the answer key it reads
(docs/bench/human-test-benchmark.md) can never leak into an agent's context via a
code path. Nothing in orchestrator/ may import from this package, and nothing in
here may import from orchestrator/.
"""

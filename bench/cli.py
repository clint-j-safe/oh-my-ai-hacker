"""CLI entry point: `python3 -m bench.cli --run FILE [--run FILE ...] [--report]`
or `... < run_output.json`.

Reads run output JSON (a single {"exitCode",...,"findings":[...]} object, or a JSON
array of such objects — several beats), scores CONFIRMED findings against the
docs/bench/human-test-benchmark.md answer key, and prints the coverage JSON shape to
stdout. Diagnostics (and, with --report, a human-readable summary) go to stderr.

Exit 0 on a successful scoring run (regardless of the score). Non-zero only on a
usage or parse error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .rubric import DEFAULT_RUBRIC_PATH, VALID_INVARIANT_TYPES, load_rubric
from .scoring import RunFinding, score


class UsageError(Exception):
    """Raised for any usage/parse error; caught in main() and turned into exit 2."""


def _load_run_objects(raw_text: str, source: str) -> list[dict]:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise UsageError(f"{source}: invalid JSON ({e})") from e

    objs = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    for i, obj in enumerate(objs):
        if not isinstance(obj, dict):
            raise UsageError(f"{source}: element {i} is not a JSON object")
        if "findings" not in obj or not isinstance(obj["findings"], list):
            raise UsageError(f"{source}: element {i} has no 'findings' array")
        findings.extend(obj["findings"])
    return findings


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bench", description="Score a run against the human-test ground truth.")
    p.add_argument("--run", action="append", default=[], metavar="FILE", help="run-output JSON file (repeatable)")
    p.add_argument("--report", action="store_true", help="also write a human-readable summary to stderr")
    p.add_argument(
        "--rubric",
        default=str(DEFAULT_RUBRIC_PATH),
        metavar="FILE",
        help="path to the answer key markdown (default: docs/bench/human-test-benchmark.md)",
    )
    return p.parse_args(argv)


def _render_report(rows, result_dict: str, coverage_by_id: dict) -> str:
    lines: list[str] = []
    no_auth = [r for r in coverage_by_id["rows"] if r["auth"].strip().lower() == "none"]
    authed = [r for r in coverage_by_id["rows"] if r["auth"].strip().lower() != "none"]

    def tally(group):
        c = sum(1 for r in group if r["status"] == "covered")
        p = sum(1 for r in group if r["status"] == "partial")
        m = sum(1 for r in group if r["status"] == "missed")
        return c, p, m, len(group)

    lines.append("=== Per-tier breakdown ===")
    for label, group in (("No-auth findings", no_auth), ("Authenticated findings", authed)):
        c, p, m, n = tally(group)
        lines.append(f"{label}: covered {c}/{n}  partial {p}/{n}  missed {m}/{n}")

    lines.append("")
    lines.append("=== Missed (aim here next) ===")
    missed = [r for r in coverage_by_id["rows"] if r["status"] == "missed"]
    if not missed:
        lines.append("(none — every ground-truth row is at least partially covered)")
    else:
        for r in missed:
            lines.append(f"  {r['id']:<6} {r['vuln_class']:<32} expects invariant type `{r['invariant_type']}`")

    lines.append("")
    lines.append("=== Partial (right class+endpoint, wrong invariant proof) ===")
    partial = [r for r in coverage_by_id["rows"] if r["status"] == "partial"]
    if not partial:
        lines.append("(none)")
    else:
        for r in partial:
            lines.append(f"  {r['id']:<6} {r['vuln_class']:<32} expects invariant type `{r['invariant_type']}`")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = _parse_args(argv)

        rubric_path = Path(args.rubric)
        if not rubric_path.exists():
            raise UsageError(f"rubric file not found: {rubric_path}")
        rows = load_rubric(rubric_path)
        if len(rows) != 28:
            raise UsageError(
                f"expected exactly 28 ground-truth rows in {rubric_path}, parsed {len(rows)} — "
                "the rubric's shape may have changed; refusing to score against a partial rubric"
            )
        for row in rows:
            if not row.vuln_class:
                raise UsageError(f"{row.id}: parsed empty vuln_class")
            if row.invariant_type not in VALID_INVARIANT_TYPES:
                raise UsageError(f"{row.id}: invariant type {row.invariant_type!r} is not a recognised type")

        raw_dicts: list[dict] = []
        if args.run:
            for path in args.run:
                p = Path(path)
                if not p.exists():
                    raise UsageError(f"--run file not found: {path}")
                raw_dicts.extend(_load_run_objects(p.read_text(encoding="utf-8"), source=path))
        else:
            stdin_text = sys.stdin.read()
            if not stdin_text.strip():
                raise UsageError("no --run file given and stdin is empty")
            raw_dicts.extend(_load_run_objects(stdin_text, source="<stdin>"))

        findings: list[RunFinding] = []
        for d in raw_dicts:
            try:
                findings.append(RunFinding.from_dict(d))
            except ValueError as e:
                raise UsageError(str(e)) from e

        engagement_id = next((f.engagement_id for f in findings if f.engagement_id), "")
        utcs = [f.utc for f in findings if f.utc]
        run_utc = max(utcs) if utcs else datetime.now(timezone.utc).isoformat()

        result = score(rows, findings, engagement_id=engagement_id, run_utc=run_utc)
        result_dict = result.to_dict()

        if args.report:
            by_id = {row.id: row for row in rows}
            report_rows = [
                {
                    "id": c["ground_truth_id"],
                    "status": c["status"],
                    "auth": by_id[c["ground_truth_id"]].auth,
                    "vuln_class": by_id[c["ground_truth_id"]].vuln_class,
                    "invariant_type": by_id[c["ground_truth_id"]].invariant_type,
                }
                for c in result_dict["coverage"]
            ]
            print(_render_report(rows, result_dict, {"rows": report_rows}), file=sys.stderr)

        print(json.dumps(result_dict, indent=2))
        return 0

    except UsageError as e:
        print(f"bench: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

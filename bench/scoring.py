"""Scores a run's CONFIRMED findings against the ground-truth rubric.

STDLIB ONLY. See bench/rubric.py for how the answer key is parsed, and
docs/bench/human-test-benchmark.md for the scoring contract this implements.

Only verdict == "CONFIRMED" findings ever score (NEEDS_REVIEW / FALSE_POSITIVE /
BLOCKED never count as covered/partial, and never count as false positives either —
they simply don't participate).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .rubric import Endpoint, GroundTruthRow, normalize_path

CONFIRMED = "CONFIRMED"

# The one positive-control check that is structurally verifiable from the thin
# run-finding record (vuln_class + endpoint only, no evidence text): SQLi is
# confined to beneficiary/fetch (§7 of the source report). Other positive controls
# in the rubric (e.g. "forged JWT alone doesn't authenticate", "SSRF didn't reach an
# internal service") describe a claim's *content*, not its vuln_class/endpoint, and
# so cannot be distinguished from a legitimate finding using only this record shape
# — they are documented as a known limitation rather than guessed at.
_SQLI_CONFINED_TO = "/api/beneficiary/fetch"


def _parse_finding_endpoint(url: str) -> tuple[Optional[str], Optional[int], str]:
    """Parse a run finding's `endpoint` URL string into (host, port, path)."""
    if not url:
        return None, None, ""
    parts = urlsplit(url)
    if parts.scheme in ("http", "https"):
        host = parts.hostname.lower() if parts.hostname else None
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        return host, port, normalize_path(parts.path)
    # No scheme: defensively treat the whole string as a bare path.
    return None, None, normalize_path(url)


@dataclass
class RunFinding:
    engagement_id: str
    finding_id: str
    vuln_class: str
    endpoint: str
    verdict: str
    invariant_type: str
    langfuse_trace_id: Optional[str] = None
    utc: Optional[str] = None
    host: Optional[str] = field(init=False, default=None)
    port: Optional[int] = field(init=False, default=None)
    path: str = field(init=False, default="")

    def __post_init__(self):
        self.host, self.port, self.path = _parse_finding_endpoint(self.endpoint)

    @classmethod
    def from_dict(cls, d: dict) -> "RunFinding":
        missing = [k for k in ("finding_id", "vuln_class", "endpoint", "verdict") if not d.get(k)]
        if missing:
            raise ValueError(f"finding record missing required field(s) {missing}: {d!r}")
        return cls(
            engagement_id=d.get("engagement_id") or "",
            finding_id=d["finding_id"],
            vuln_class=d["vuln_class"],
            endpoint=d["endpoint"],
            verdict=d["verdict"],
            invariant_type=d.get("invariant_type") or "",
            langfuse_trace_id=d.get("langfuse_trace_id"),
            utc=d.get("utc"),
        )


def endpoint_matches(row: GroundTruthRow, finding: RunFinding) -> bool:
    if row.scope:
        if row.scope_hosts and finding.host not in row.scope_hosts:
            return False
        for prefix in row.exclude_path_prefixes:
            if finding.path == prefix or finding.path.startswith(prefix + "/"):
                return False
        return True

    for ep in row.endpoints:
        if ep.host is not None and ep.host != finding.host:
            continue
        if ep.port is not None and ep.port != finding.port:
            continue
        if ep.path != finding.path:
            continue
        return True
    return False


def _matched_endpoint_desc(row: GroundTruthRow, finding: RunFinding) -> str:
    """Human-readable description of which endpoint(s) matched, for the notes field."""
    if row.scope:
        return f"scope-level match on host={finding.host!r}"
    for ep in row.endpoints:
        if ep.host is not None and ep.host != finding.host:
            continue
        if ep.port is not None and ep.port != finding.port:
            continue
        if ep.path != finding.path:
            continue
        return f"endpoint match on path={ep.path!r}"
    return ""


@dataclass
class CoverageEntry:
    ground_truth_id: str
    status: str  # covered | partial | missed
    matched_finding_id: str
    notes: str


@dataclass
class FalsePositiveEntry:
    finding_id: str
    why: str


@dataclass
class ScoreResult:
    engagement_id: str
    run_utc: str
    coverage: list[CoverageEntry]
    false_positives: list[FalsePositiveEntry]

    def to_dict(self) -> dict:
        covered = sum(1 for c in self.coverage if c.status == "covered")
        partial = sum(1 for c in self.coverage if c.status == "partial")
        missed = sum(1 for c in self.coverage if c.status == "missed")
        return {
            "engagement_id": self.engagement_id,
            "run_utc": self.run_utc,
            "coverage": [
                {
                    "ground_truth_id": c.ground_truth_id,
                    "status": c.status,
                    "matched_finding_id": c.matched_finding_id,
                    "notes": c.notes,
                }
                for c in self.coverage
            ],
            "false_positives": [{"finding_id": f.finding_id, "why": f.why} for f in self.false_positives],
            "summary": {
                "covered": covered,
                "partial": partial,
                "missed": missed,
                "false_positives": len(self.false_positives),
                "total_ground_truth": len(self.coverage),
            },
        }


def score(
    rows: list[GroundTruthRow],
    findings: list[RunFinding],
    engagement_id: str = "",
    run_utc: str = "",
) -> ScoreResult:
    confirmed = [f for f in findings if f.verdict == CONFIRMED]

    # candidates[row.id] = list of (finding, status) for CONFIRMED findings whose
    # vuln_class + endpoint match this row, status "covered" (invariant also
    # matches) or "partial" (invariant differs).
    candidates: dict[str, list[tuple[RunFinding, str]]] = {row.id: [] for row in rows}
    # finding_has_any_match[finding_id] = True if ANY row's vuln_class+endpoint
    # matched it (independent of who ends up winning the assignment) — this is
    # what decides "matches no ground-truth row at all" for false-positive purposes.
    finding_has_any_match: dict[str, bool] = {f.finding_id: False for f in confirmed}

    for row in rows:
        for f in confirmed:
            if f.vuln_class != row.vuln_class:
                continue
            if not endpoint_matches(row, f):
                continue
            finding_has_any_match[f.finding_id] = True
            status = "covered" if f.invariant_type == row.invariant_type else "partial"
            candidates[row.id].append((f, status))

    # Collision-safety: one finding must never satisfy two ground-truth rows.
    # Global two-pass greedy assignment: award every possible "covered" match
    # first (across ALL rows), THEN award "partial" matches from whatever
    # findings remain unclaimed. This is what makes "covered beats partial"
    # apply globally rather than row-by-row (e.g. F-01 vs F-13: a full takeover
    # finding claims F-01 as covered in pass one, so it is no longer available
    # for F-13 to pick up as a partial match in pass two).
    claimed_finding_ids: set[str] = set()
    assignment: dict[str, tuple[RunFinding, str]] = {}

    for row in rows:
        covered_candidates = [
            (f, s) for (f, s) in candidates[row.id] if s == "covered" and f.finding_id not in claimed_finding_ids
        ]
        if covered_candidates:
            f, s = covered_candidates[0]
            assignment[row.id] = (f, s)
            claimed_finding_ids.add(f.finding_id)

    for row in rows:
        if row.id in assignment:
            continue
        partial_candidates = [
            (f, s) for (f, s) in candidates[row.id] if f.finding_id not in claimed_finding_ids
        ]
        if partial_candidates:
            f, s = partial_candidates[0]
            assignment[row.id] = (f, s)
            claimed_finding_ids.add(f.finding_id)

    coverage: list[CoverageEntry] = []
    for row in rows:
        if row.id in assignment:
            f, status = assignment[row.id]
            if status == "covered":
                notes = f"{_matched_endpoint_desc(row, f)}; invariant '{f.invariant_type}' as expected"
            else:
                notes = (
                    f"{_matched_endpoint_desc(row, f)}; invariant was '{f.invariant_type}', "
                    f"expected '{row.invariant_type}'"
                )
            coverage.append(
                CoverageEntry(ground_truth_id=row.id, status=status, matched_finding_id=f.finding_id, notes=notes)
            )
        else:
            coverage.append(
                CoverageEntry(
                    ground_truth_id=row.id,
                    status="missed",
                    matched_finding_id="",
                    notes=f"no CONFIRMED finding matched vuln_class={row.vuln_class!r} on a qualifying endpoint",
                )
            )

    false_positives: list[FalsePositiveEntry] = []
    for f in confirmed:
        if f.vuln_class == "sqli" and f.path != normalize_path(_SQLI_CONFINED_TO):
            false_positives.append(
                FalsePositiveEntry(
                    finding_id=f.finding_id,
                    why=(
                        "matches positive control: DB access is parameterised except "
                        f"{_SQLI_CONFINED_TO}; sqli reported on {f.endpoint!r} instead"
                    ),
                )
            )
            continue
        if not finding_has_any_match.get(f.finding_id, False):
            false_positives.append(
                FalsePositiveEntry(
                    finding_id=f.finding_id,
                    why=f"no ground-truth row matches vuln_class={f.vuln_class!r} + endpoint={f.endpoint!r}",
                )
            )

    return ScoreResult(
        engagement_id=engagement_id, run_utc=run_utc, coverage=coverage, false_positives=false_positives
    )

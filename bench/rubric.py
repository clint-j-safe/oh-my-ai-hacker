"""Parses docs/bench/human-test-benchmark.md (the answer key) into structured rows.

This is the ONLY module that reads the answer key file. STDLIB ONLY.

The markdown table has one row per ground-truth finding, F-01..F-28, with columns:
    | ID | vuln_class | Auth | Endpoint (answer key) | Expected invariant (type) | Severity | CVSS | CWE |

Parsing rules (see docs/bench/human-test-benchmark.md itself for the prose this
encodes):
  - vuln_class is the first backticked token in its cell; a trailing `*` (outside the
    backticks, per the file's own convention) marks "class name coined for this
    rubric" and is stripped for comparison purposes.
  - The invariant cell's type is the first backticked token; everything else in that
    cell is prose describing the proof and is ignored.
  - The endpoint cell is free text that may contain: a single endpoint, several
    alternatives (comma/semicolon/"or" separated), a chain (arrow-separated or
    "+"-joined, all of which count as "match ANY member"), a bracketed parameter note
    (dropped — it is not an endpoint), an "excludes `<pattern>`" clause (F-04, carved
    out of the endpoint set rather than added to it), or scope-level prose
    ("platform-wide", "API-wide", "all responses", "all authenticated endpoints", ...)
    meaning "any endpoint on the given host(s) counts, path is not restrictive".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_RUBRIC_PATH = Path(__file__).resolve().parent.parent / "docs" / "bench" / "human-test-benchmark.md"

DEFAULT_PORTS = {"http": 80, "https": 443}

_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")
_METHOD_RE = re.compile(r"^(" + "|".join(_METHODS) + r")\s+(.*)$")
_COLON_PORT_RE = re.compile(r"^:(\d+)(/.*)?$")
_BACKTICK_RE = re.compile(r"`([^`]+)`")
_ROW_RE = re.compile(r"^\|\s*(F-\d+)\s*\|(.+)\|\s*$")
_EXCLUDES_RE = re.compile(
    r"excludes\s+(`[^`]+`(?:\s*(?:,|and|or)\s*`[^`]+`)*)", re.IGNORECASE
)
_CHAIN_REF_RE = re.compile(r"same chain as (F-\d+)", re.IGNORECASE)

# Scope-level phrases: presence means "no specific path — any endpoint on the given
# host(s), if any are named, counts". Matched case-insensitively against the whole
# endpoint cell (not just backticked spans).
_SCOPE_KEYWORDS = (
    "platform-wide",
    "api-wide",
    "all responses",
    "api responses",
    "all authenticated endpoints",
)

VALID_INVARIANT_TYPES = frozenset(
    {
        "body_contains",
        "status_in",
        "derived",
        "state_changed",
        "state_violated",
        "file_created_then_deleted",
        "response_asserted",
    }
)


def normalize_path(path: str) -> str:
    """Canonicalise a URL path for comparison.

    Ignores query strings entirely, and treats an empty path and "/" as the same
    canonical root ("") — this is what lets `http://h:3000/` match an answer-key
    endpoint written as `http://h:3000` (no path at all).
    """
    path = path.split("?", 1)[0]
    if path in ("", "/"):
        return ""
    if path.endswith("/"):
        path = path[:-1]
    return path


@dataclass(frozen=True)
class Endpoint:
    """A single parsed endpoint reference. None fields are wildcards."""

    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""  # canonical via normalize_path(); "" means root/no-path-given

    def key(self):
        return (self.host, self.port, self.path)


@dataclass
class GroundTruthRow:
    id: str
    vuln_class: str
    auth: str
    endpoints: list[Endpoint]
    scope: bool
    scope_hosts: list[str]
    exclude_path_prefixes: list[str]
    invariant_type: str
    severity: str
    cvss: str
    cwe: str
    raw_endpoint_cell: str = field(repr=False, default="")


def _split_row_cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return line.split("|")


def _first_backtick(cell: str) -> Optional[str]:
    m = _BACKTICK_RE.search(cell)
    return m.group(1) if m else None


def _parse_endpoint_token(token: str) -> Optional[Endpoint]:
    """Parse one backtick-quoted span from an endpoint cell into an Endpoint, or
    return None if the span is not endpoint-like (e.g. a parameter name, a header,
    a bare validation note)."""
    token = token.strip()
    if not token:
        return None

    m = _METHOD_RE.match(token)
    rest = m.group(2).strip() if m else token
    if not rest:
        return None

    if rest.startswith("http://") or rest.startswith("https://"):
        parts = urlsplit(rest)
        host = parts.hostname.lower() if parts.hostname else None
        port = parts.port or DEFAULT_PORTS.get(parts.scheme)
        return Endpoint(host=host, port=port, path=normalize_path(parts.path))

    if rest.startswith(":"):
        pm = _COLON_PORT_RE.match(rest)
        if not pm:
            return None
        return Endpoint(host=None, port=int(pm.group(1)), path=normalize_path(pm.group(2) or ""))

    if rest.startswith("/"):
        return Endpoint(host=None, port=None, path=normalize_path(rest))

    # Not endpoint-like: parameter names ("data.userid"), header notes
    # ("Accept: application/xml"), validation-check prose ("type"), etc.
    return None


def _parse_endpoint_cell(cell: str) -> tuple[list[Endpoint], bool, list[str], list[str]]:
    excludes: list[str] = []
    working = cell
    excl_m = _EXCLUDES_RE.search(cell)
    if excl_m:
        for tok in _BACKTICK_RE.findall(excl_m.group(1)):
            prefix = tok.rstrip("*")
            if prefix.endswith("/"):
                prefix = prefix[:-1]
            excludes.append(prefix)
        working = cell[: excl_m.start()] + cell[excl_m.end() :]

    scope = any(kw in cell.lower() for kw in _SCOPE_KEYWORDS)

    endpoints: list[Endpoint] = []
    for tok in _BACKTICK_RE.findall(working):
        ep = _parse_endpoint_token(tok)
        if ep is not None:
            endpoints.append(ep)

    scope_hosts = sorted({e.host for e in endpoints if e.host})
    return endpoints, scope, scope_hosts, excludes


def parse_rubric(text: str) -> list[GroundTruthRow]:
    """Parse the full markdown rubric text into GroundTruthRow objects, one per
    F-XX id, in id order."""
    rows_by_id: dict[str, GroundTruthRow] = {}

    for line in text.splitlines():
        m = _ROW_RE.match(line.strip())
        if not m:
            continue
        gid = m.group(1)
        cells = _split_row_cells(line)
        if len(cells) < 8:
            continue
        # cells: [ID, vuln_class, Auth, Endpoint, Invariant, Severity, CVSS, CWE, ...]
        _id_cell, vuln_cell, auth_cell, endpoint_cell, invariant_cell, sev_cell, cvss_cell, cwe_cell = cells[:8]

        vuln_class = _first_backtick(vuln_cell)
        if vuln_class is None:
            continue
        vuln_class = vuln_class.rstrip("*").strip()

        invariant_type = (_first_backtick(invariant_cell) or "").strip()

        endpoints, scope, scope_hosts, excludes = _parse_endpoint_cell(endpoint_cell)

        rows_by_id[gid] = GroundTruthRow(
            id=gid,
            vuln_class=vuln_class,
            auth=auth_cell.strip(),
            endpoints=endpoints,
            scope=scope,
            scope_hosts=scope_hosts,
            exclude_path_prefixes=excludes,
            invariant_type=invariant_type,
            severity=sev_cell.strip(),
            cvss=cvss_cell.strip(),
            cwe=cwe_cell.strip(),
            raw_endpoint_cell=endpoint_cell.strip(),
        )

    # Second pass: rows that say "same chain as F-XX" (e.g. F-13 referencing F-01)
    # inherit that row's parsed endpoints too — the prose spells the chain out only
    # once and cross-references it the second time, using bare suffixes
    # (`verifyuser`/`reset`) that don't parse as standalone paths on their own.
    for row in rows_by_id.values():
        ref_m = _CHAIN_REF_RE.search(row.raw_endpoint_cell)
        if not ref_m:
            continue
        ref_row = rows_by_id.get(ref_m.group(1))
        if not ref_row:
            continue
        existing = {e.key() for e in row.endpoints}
        for e in ref_row.endpoints:
            if e.key() not in existing:
                row.endpoints.append(e)
                existing.add(e.key())

    return [rows_by_id[k] for k in sorted(rows_by_id, key=lambda x: int(x.split("-")[1]))]


def load_rubric(path: Path = DEFAULT_RUBRIC_PATH) -> list[GroundTruthRow]:
    text = Path(path).read_text(encoding="utf-8")
    return parse_rubric(text)

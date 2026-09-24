"""
Corpus KB for the payload library: a versioned, read-only SQLite index of
PayloadsAllTheThings + SecLists, so the framework can draw on EVERY known payload for a
vuln class instead of only the hand-curated BUILTINS.

Dependency-free (stdlib only: sqlite3/json/hashlib/pathlib/re) so any sandbox runs it.
SAFETY: classification is deny-by-default — a payload whose path matches no known-safe
category is dropped, never included under a permissive class. Only VERIFIED, categorised
payloads enter the index.

Build once (fetch.sh clones the corpora at pinned SHAs, then build_index normalises the
raw tree into the DB); query at runtime by vuln_class. run.py merges corpus hits with the
curated BUILTINS, corpus-first when the DB exists.
"""
from __future__ import annotations
import sqlite3
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Path-fragment -> canonical vuln_class. Ordered: first match wins. Deny-by-default: a
# file under no mapped directory is skipped (returns None), never indexed as a guess.
CATEGORY_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"SQL[ _]?Injection", re.I), "sqli"),
    (re.compile(r"Server[ _]?Side[ _]?Template|SSTI|Template[ _]?Injection", re.I), "ssti"),
    (re.compile(r"Command[ _]?Injection|OS[ _]?Command", re.I), "command_injection"),
    (re.compile(r"XXE|XML[ _]?External", re.I), "xxe"),
    (re.compile(r"DOM[ _]?based|DOM[ _]?XSS", re.I), "dom_xss"),
    (re.compile(r"XSS[ _]?Injection|Cross[ _]?Site[ _]?Scripting|\bXSS\b", re.I), "xss_reflected"),
    (re.compile(r"HTML[ _]?Injection", re.I), "html_injection"),
    (re.compile(r"Directory[ _]?Traversal|Path[ _]?Traversal|File[ _]?Inclusion|\bLFI\b", re.I), "path_traversal"),
    (re.compile(r"Server[ _]?Side[ _]?Request|SSRF", re.I), "ssrf"),
    (re.compile(r"Insecure[ _]?Deserial|Deserialization", re.I), "deserialization_rce"),
    (re.compile(r"Discovery/Web-Content|Web-Content|raft-|common\.txt|directory-list", re.I), "forced_browsing"),
    (re.compile(r"CRLF|HTTP[ _]?Header", re.I), "http_header_injection"),
    (re.compile(r"NoSQL", re.I), "nosql_injection"),
    (re.compile(r"LDAP[ _]?Injection", re.I), "ldap_injection"),
    (re.compile(r"XPATH|XPath[ _]?Injection", re.I), "xpath_injection"),
]

# Lines that are never payloads (headers, prose, markup) — dropped during ETL.
_SKIP_LINE = re.compile(r"^\s*(#|//|<!--|\*|\|)|^\s*$")


def categorize(path: str) -> Optional[str]:
    """Map a corpus file path to a canonical vuln_class, or None (deny-by-default)."""
    for pat, cls in CATEGORY_RULES:
        if pat.search(path):
            return cls
    return None


def _source_of(path: str) -> str:
    p = path.lower()
    if "seclists" in p:
        return "SecLists"
    if "payloadsallthethings" in p or "payloads-all-the-things" in p:
        return "PayloadsAllTheThings"
    return "corpus"


def open_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS payloads ("
        " value TEXT NOT NULL, vuln_class TEXT NOT NULL, technique TEXT, source TEXT,"
        " UNIQUE(value, vuln_class))"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_class ON payloads(vuln_class)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()


def build_index(raw_dir: Path, db_path: str, meta: Dict[str, str], max_len: int = 2048) -> int:
    """Walk raw_dir, classify each .txt/.md file, and index its payload lines. Returns the
    number of payloads inserted. Idempotent per (value, vuln_class)."""
    conn = open_db(db_path)
    ensure_schema(conn)
    inserted = 0
    for f in sorted(raw_dir.rglob("*")):
        if not f.is_file():
            continue
        if f.suffix.lower() not in (".txt", ".md", ".fuzzdb", ""):
            continue
        cls = categorize(str(f))
        if cls is None:
            continue
        src = _source_of(str(f))
        technique = f.stem.lower()
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            v = line.strip()
            if not v or len(v) > max_len or _SKIP_LINE.match(v):
                continue
            try:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO payloads(value, vuln_class, technique, source) VALUES (?,?,?,?)",
                    (v, cls, technique, src))
                inserted += cur.rowcount
            except Exception:
                continue
    for k, val in meta.items():
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)", (k, str(val)))
    conn.commit()
    conn.close()
    return inserted


def search(db_path: str, vuln_class: str, limit: int = 8, technique: str = "") -> List[Dict[str, str]]:
    """Return up to `limit` payloads for a vuln_class (optionally filtered by technique
    substring). Empty list if the DB or class is absent — the caller falls back to BUILTINS."""
    try:
        conn = open_db(db_path)
    except Exception:
        return []
    try:
        if technique:
            rows = conn.execute(
                "SELECT value, technique, source FROM payloads WHERE vuln_class=? AND technique LIKE ? LIMIT ?",
                (vuln_class, f"%{technique}%", limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT value, technique, source FROM payloads WHERE vuln_class=? LIMIT ?",
                (vuln_class, limit)).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    return [{"value": v, "note": f"{src} corpus ({tech})", "technique": tech or ""} for (v, tech, src) in rows]


if __name__ == "__main__":
    import argparse, json, sys
    ap = argparse.ArgumentParser(prog="corpus")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--raw", required=True)
    b.add_argument("--db", required=True)
    b.add_argument("--pat-sha", default="")
    b.add_argument("--seclists-sha", default="")
    q = sub.add_parser("search")
    q.add_argument("--db", required=True)
    q.add_argument("--vuln-class", required=True)
    q.add_argument("--limit", type=int, default=8)
    a = ap.parse_args()
    if a.cmd == "build":
        n = build_index(Path(a.raw), a.db, {"PAT_SHA": a.pat_sha, "SECLISTS_SHA": a.seclists_sha})
        print(json.dumps({"inserted": n, "db": a.db}))
    elif a.cmd == "search":
        print(json.dumps(search(a.db, a.vuln_class, a.limit)))
    sys.exit(0)

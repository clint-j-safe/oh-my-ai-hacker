# Payload Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a versioned, read-only payload and wordlist library, indexed by SQLite/FTS5, that agents reach only through structured tool calls — so corpora never enter prompt context.

**Architecture:** A dependency-free Python package plus two CLIs. ETL normalizes pinned clones of PayloadsAllTheThings and SecLists into JSONL, then into SQLite with an FTS5 index. Queries return **metadata and a set id**; `payload_set_create` materializes matches to a `.txt` and returns its absolute path and SHA-256. The four OpenAI function tools are thin dispatchers over this package, so the library is complete and testable before the TypeScript orchestrator exists.

**Tech Stack:** Python 3.11+, **stdlib only** (`sqlite3`, `json`, `hashlib`, `pathlib`, `argparse`, `unittest`). No pip installs. SQLite ≥ 3.35 with FTS5 (verified available: 3.53.4).

**Spec:** `docs/superpowers/specs/2026-09-22-safe-ai-hacker-design.md` §9 (The Payload Library), with §5.2 (Tether dispatch gate) and §7.0 (tool registry).

## Global Constraints

- **Stdlib only.** `spill_store.py` in `skills/*/scripts/` states the rule: dependency-free so any sandbox can run it. This package follows it. No pytest — tests use `unittest`.
- **Payloads never enter prompt context.** No function returns raw payload text except `wordlist_preview` (hard-capped) and the sample metadata cap in `payload_search`.
- **Deny by default on risk.** A payload that matches no known-safe pattern is classified to the most restrictive class, never the least.
- **`risk_class` is a required enum**: `non_destructive_probe` | `read_only_probe`. Anything else is rejected before a file is written.
- **Sources pinned by commit SHA**, never by branch. `SAHW_PAYLOAD_PAT_SHA`, `SAHW_PAYLOAD_SECLISTS_SHA`.
- **Caps, from env, with these defaults:** `SAHW_PAYLOAD_MAX_SET=500`, `SAHW_WORDLIST_MAX_LINES=5000`, `SAHW_PAYLOAD_PREVIEW_LINES=10`.
- **Paths from env:** `SAHW_PAYLOAD_LIBRARY=/opt/payload-library`, `SAHW_PAYLOAD_DB`, `SAHW_PAYLOAD_SETS`.
- **`raw/` and `db/` are read-only at runtime.** Only `sets/generated/` is written, and only by `payload_set_create`.
- **Commit after every task.** Message prefix `feat(payload-library):`.

---

## File Structure

```
payload_library/
├── README.md                  # what it is, how to build the index, how to query
├── fetch.sh                   # clone PAT + SecLists at pinned SHAs into raw/
├── bin/
│   ├── payload-query          # CLI → src.query
│   └── wordlist-info          # CLI → src.wordlist
├── src/
│   ├── __init__.py
│   ├── config.py              # env resolution + caps, one place
│   ├── schema.py              # DDL, FTS5, open_db()
│   ├── classify.py            # category + risk_class rules (SAFETY-CRITICAL)
│   ├── etl.py                 # raw/ → normalized/*.jsonl → sqlite
│   ├── query.py               # search(), create_set()
│   ├── wordlist.py            # search(), preview()
│   └── tools.py               # 4 OpenAI function schemas + dispatch()
└── tests/
    ├── fixtures/              # tiny fake PAT/SecLists trees
    ├── test_config.py
    ├── test_schema.py
    ├── test_classify.py
    ├── test_etl.py
    ├── test_query.py
    ├── test_wordlist.py
    └── test_tools.py
```

Each `src/` module has one responsibility and is independently testable. `classify.py` is separated from `etl.py` deliberately: risk classification is the safety boundary, and it must be testable without any corpus present.

Run all tests from the repo root: `python3 -m unittest discover -s payload_library/tests -t . -v`

---

### Task 1: Config and caps

**Files:**
- Create: `payload_library/src/__init__.py` (empty)
- Create: `payload_library/src/config.py`
- Test: `payload_library/tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `RISK_CLASSES: tuple[str, ...]`, `Config` dataclass with fields `library: Path`, `db: Path`, `sets: Path`, `max_set: int`, `wordlist_max_lines: int`, `preview_lines: int`; `load_config(env: dict | None = None) -> Config`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_config.py
import unittest
from pathlib import Path
from payload_library.src.config import load_config, RISK_CLASSES


class TestConfig(unittest.TestCase):
    def test_defaults_when_env_empty(self):
        c = load_config({})
        self.assertEqual(c.library, Path("/opt/payload-library"))
        self.assertEqual(c.db, Path("/opt/payload-library/db/payload-library.sqlite3"))
        self.assertEqual(c.sets, Path("/opt/payload-library/sets/generated"))
        self.assertEqual(c.max_set, 500)
        self.assertEqual(c.wordlist_max_lines, 5000)
        self.assertEqual(c.preview_lines, 10)

    def test_env_overrides(self):
        c = load_config({"SAHW_PAYLOAD_LIBRARY": "/tmp/pl", "SAHW_PAYLOAD_MAX_SET": "25"})
        self.assertEqual(c.library, Path("/tmp/pl"))
        self.assertEqual(c.db, Path("/tmp/pl/db/payload-library.sqlite3"))
        self.assertEqual(c.max_set, 25)

    def test_explicit_db_path_wins_over_derived(self):
        c = load_config({"SAHW_PAYLOAD_LIBRARY": "/tmp/pl", "SAHW_PAYLOAD_DB": "/other/x.sqlite3"})
        self.assertEqual(c.db, Path("/other/x.sqlite3"))

    def test_caps_are_clamped_not_trusted(self):
        c = load_config({"SAHW_PAYLOAD_MAX_SET": "999999", "SAHW_PAYLOAD_PREVIEW_LINES": "10000"})
        self.assertEqual(c.max_set, 5000)       # hard ceiling
        self.assertEqual(c.preview_lines, 100)  # hard ceiling

    def test_risk_classes_are_the_two_safe_ones(self):
        self.assertEqual(RISK_CLASSES, ("non_destructive_probe", "read_only_probe"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload-library.tests.test_config -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'payload_library'`

- [ ] **Step 3: Make the package importable, then implement**

The directory is `payload-library` (hyphen), which is not a valid module name. Add a root `conftest`-free shim: create `payload_library/__init__.py` as a symlink-free package that re-exports. Simplest correct approach — rename the directory to `payload_library` and keep the hyphenated name only in docs:

```bash
mkdir -p payload_library/src payload_library/bin payload_library/tests/fixtures
touch payload_library/__init__.py payload_library/src/__init__.py payload_library/tests/__init__.py
```

```python
# payload_library/src/config.py
"""Single source of truth for library paths and caps. Stdlib only."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

RISK_CLASSES: tuple[str, ...] = ("non_destructive_probe", "read_only_probe")

_DEFAULT_LIBRARY = "/opt/payload-library"
_MAX_SET_CEILING = 5000
_WORDLIST_CEILING = 200_000
_PREVIEW_CEILING = 100


@dataclass(frozen=True)
class Config:
    library: Path
    db: Path
    sets: Path
    max_set: int
    wordlist_max_lines: int
    preview_lines: int


def _int(env: dict, key: str, default: int, ceiling: int) -> int:
    try:
        value = int(env.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, ceiling))


def load_config(env: dict | None = None) -> Config:
    env = os.environ if env is None else env
    library = Path(env.get("SAHW_PAYLOAD_LIBRARY") or _DEFAULT_LIBRARY)
    return Config(
        library=library,
        db=Path(env.get("SAHW_PAYLOAD_DB") or library / "db" / "payload-library.sqlite3"),
        sets=Path(env.get("SAHW_PAYLOAD_SETS") or library / "sets" / "generated"),
        max_set=_int(env, "SAHW_PAYLOAD_MAX_SET", 500, _MAX_SET_CEILING),
        wordlist_max_lines=_int(env, "SAHW_WORDLIST_MAX_LINES", 5000, _WORDLIST_CEILING),
        preview_lines=_int(env, "SAHW_PAYLOAD_PREVIEW_LINES", 10, _PREVIEW_CEILING),
    )
```

Update the test imports to `payload_library.src.config`.

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_config -v`
Expected: 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/
git commit -m "feat(payload-library): config resolution with clamped caps"
```

---

### Task 2: Risk classification (safety boundary)

Built before ETL on purpose: it is the gate everything else depends on, and it must be provable without any corpus on disk.

**Files:**
- Create: `payload_library/src/classify.py`
- Test: `payload_library/tests/test_classify.py`

**Interfaces:**
- Consumes: `RISK_CLASSES` from `src.config`.
- Produces: `classify_risk(payload: str) -> str` returning one of `non_destructive_probe`, `read_only_probe`, `state_changing`, `destructive`; `categorize(source_path: str) -> str` returning a dotted category such as `injection.sql`; `is_agent_selectable(risk: str) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_classify.py
import unittest
from payload_library.src.classify import classify_risk, categorize, is_agent_selectable


class TestRisk(unittest.TestCase):
    def test_destructive_verbs_are_destructive(self):
        for p in ["'; DROP TABLE users--", "1; DELETE FROM accounts", "| rm -rf /",
                  "'; TRUNCATE orders--", "$(shutdown -h now)"]:
            self.assertEqual(classify_risk(p), "destructive", p)

    def test_state_changing_writes_are_state_changing(self):
        for p in ["'; INSERT INTO t VALUES(1)--", "1; UPDATE users SET admin=1"]:
            self.assertEqual(classify_risk(p), "state_changing", p)

    def test_read_only_selects_are_read_only(self):
        for p in ["' UNION SELECT version()--", "1' AND (SELECT database())='x"]:
            self.assertEqual(classify_risk(p), "read_only_probe", p)

    def test_inert_markers_are_non_destructive(self):
        for p in ["'", "1'\"", "1=1", "../../etc/passwd", "<sahwXSS>"]:
            self.assertEqual(classify_risk(p), "non_destructive_probe", p)

    def test_common_boolean_probes_are_not_denied_by_default(self):
        # These are the most-used SQLi probes; classifying them destructive would
        # make the library useless for its primary case.
        for p in ["1' OR '1'='1", "' OR 1=1--", "admin'--", "admin'#"]:
            self.assertEqual(classify_risk(p), "non_destructive_probe", p)

    def test_destructive_still_wins_when_hidden_behind_a_probe_shape(self):
        self.assertEqual(classify_risk("'; DROP TABLE t--  -- admin'--"), "destructive")

    def test_shell_read_of_sensitive_files_is_destructive(self):
        self.assertEqual(classify_risk("cat /etc/shadow"), "destructive")
        self.assertEqual(classify_risk("'; EXEC xp_cmdshell('dir')--"), "destructive")

    def test_unknown_payload_denies_by_default(self):
        # Deny by default: unrecognised means most restrictive, not least.
        self.assertEqual(classify_risk("\x00\x01 weird unparseable blob ☃"), "destructive")

    def test_destructive_wins_over_read_only_when_both_present(self):
        self.assertEqual(classify_risk("' UNION SELECT 1--; DROP TABLE t--"), "destructive")

    def test_only_the_two_safe_classes_are_agent_selectable(self):
        self.assertTrue(is_agent_selectable("non_destructive_probe"))
        self.assertTrue(is_agent_selectable("read_only_probe"))
        self.assertFalse(is_agent_selectable("state_changing"))
        self.assertFalse(is_agent_selectable("destructive"))


class TestCategory(unittest.TestCase):
    def test_maps_source_path_to_dotted_category(self):
        self.assertEqual(categorize("raw/PayloadsAllTheThings/SQL Injection/Intruder/x.txt"),
                         "injection.sql")
        self.assertEqual(categorize("raw/PayloadsAllTheThings/XSS Injection/README.md"),
                         "injection.xss")
        self.assertEqual(categorize("raw/SecLists/Discovery/Web-Content/raft-medium.txt"),
                         "discovery.directory")

    def test_unmapped_path_is_uncategorised_not_guessed(self):
        self.assertEqual(categorize("raw/Whatever/novel-thing.txt"), "uncategorised")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_classify -v`
Expected: FAIL — `No module named 'payload_library.src.classify'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/classify.py
"""Risk and category classification. Deny by default: an unrecognised payload
is treated as destructive, never as safe."""
from __future__ import annotations

import re

from .config import RISK_CLASSES

_DESTRUCTIVE = re.compile(
    r"\b(drop\s+(table|database|schema)|truncate|delete\s+from|shutdown|"
    r"rm\s+-[rf]|mkfs|dd\s+if=|format\s+c:|xp_cmdshell|drop\s+user)\b|"
    r"\brm\s+-rf\b",
    re.I,
)
_STATE_CHANGING = re.compile(
    r"\b(insert\s+into|update\s+\w+\s+set|alter\s+table|create\s+(table|user)|"
    r"grant\s+|revoke\s+|load_file\s*\(|into\s+outfile|into\s+dumpfile)\b",
    re.I,
)
_READ_ONLY = re.compile(
    r"\b(union\s+select|select\s+|version\s*\(\s*\)|database\s*\(\s*\)|"
    r"current_user|information_schema|pg_sleep|sleep\s*\(|benchmark\s*\()",
    re.I,
)
# Boolean/inference probes: tautologies and quote+comment terminators. These read
# nothing and change nothing, but deny-by-default would otherwise reject the most
# common SQLi probes outright.
_PROBE = re.compile(
    r"\b(or|and)\s+[\'\"`]?[\w.]+[\'\"`]?\s*(=|<>|!=|like)\s*[\'\"`]?[\w.]+[\'\"`]?"
    r"|[\'\"`]\s*(--|#|/\*)"
    r"|^[\w.@-]{1,32}[\'\"`]\s*(--|#)",
    re.I,
)
# Inert shapes: pure punctuation/digits, traversal markers, tag and template markers.
_INERT = re.compile(
    r"^[\s\'\"`;)\(\]\[<>/\\.%&|#*+=,:!~@$0-9-]*$|"
    r"\.\./|%2e%2e|<[a-z]*sahw|<script|onerror=|\{\{|\$\{",
    re.I,
)

_CATEGORY_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"SQL\s*Injection", re.I), "injection.sql"),
    (re.compile(r"NoSQL\s*Injection", re.I), "injection.nosql"),
    (re.compile(r"XSS\s*Injection|Cross[- ]Site[- ]Scripting", re.I), "injection.xss"),
    (re.compile(r"Command\s*Injection", re.I), "injection.command"),
    (re.compile(r"Server\s*Side\s*Template", re.I), "injection.ssti"),
    (re.compile(r"XXE\s*Injection", re.I), "injection.xxe"),
    (re.compile(r"Directory\s*Traversal|File\s*Inclusion", re.I), "traversal.path"),
    (re.compile(r"Server\s*Side\s*Request\s*Forgery", re.I), "ssrf"),
    (re.compile(r"Insecure\s*Deserialization", re.I), "deserialization"),
    (re.compile(r"Discovery/Web-Content", re.I), "discovery.directory"),
    (re.compile(r"Discovery/DNS", re.I), "discovery.subdomain"),
    (re.compile(r"Usernames", re.I), "credential.username"),
    (re.compile(r"Passwords", re.I), "credential.password"),
)


def classify_risk(payload: str) -> str:
    if not isinstance(payload, str) or not payload.strip():
        return "destructive"
    if _DESTRUCTIVE.search(payload):
        return "destructive"
    if _STATE_CHANGING.search(payload):
        return "state_changing"
    if _READ_ONLY.search(payload):
        return "read_only_probe"
    if _PROBE.search(payload) or _INERT.search(payload):
        return "non_destructive_probe"
    return "destructive"  # deny by default


def categorize(source_path: str) -> str:
    for pattern, category in _CATEGORY_RULES:
        if pattern.search(source_path):
            return category
    return "uncategorised"


def is_agent_selectable(risk: str) -> bool:
    return risk in RISK_CLASSES
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_classify -v`
Expected: 12 tests PASS. This ruleset was verified against all 24 cases before the plan was written; if a case fails, the regex was mistyped — compare character by character rather than rewriting it.

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/classify.py payload_library/tests/test_classify.py
git commit -m "feat(payload-library): deny-by-default risk classification"
```

---

### Task 3: SQLite schema with FTS5

**Files:**
- Create: `payload_library/src/schema.py`
- Test: `payload_library/tests/test_schema.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `open_db(path: Path, read_only: bool = True) -> sqlite3.Connection`; `create_schema(conn) -> None`; `insert_payload(conn, *, payload, category, risk_class, tech, cwe, source_path, source_repo) -> int`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_schema.py
import sqlite3
import tempfile
import unittest
from pathlib import Path
from payload_library.src.schema import open_db, create_schema, insert_payload


class TestSchema(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.sqlite3"
        self.conn = open_db(self.db, read_only=False)
        create_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_insert_and_retrieve(self):
        rid = insert_payload(self.conn, payload="' UNION SELECT version()--",
                             category="injection.sql", risk_class="read_only_probe",
                             tech="postgres", cwe="CWE-89",
                             source_path="raw/PAT/SQL Injection/x.txt", source_repo="PAT")
        row = self.conn.execute("SELECT payload, tech FROM payloads WHERE id=?", (rid,)).fetchone()
        self.assertEqual(row[0], "' UNION SELECT version()--")
        self.assertEqual(row[1], "postgres")

    def test_fts_finds_by_payload_text(self):
        insert_payload(self.conn, payload="' UNION SELECT version()--", category="injection.sql",
                       risk_class="read_only_probe", tech="postgres", cwe="CWE-89",
                       source_path="p", source_repo="PAT")
        hits = self.conn.execute(
            "SELECT rowid FROM payloads_fts WHERE payloads_fts MATCH ?", ("version",)).fetchall()
        self.assertEqual(len(hits), 1)

    def test_identical_payload_in_same_category_is_deduped(self):
        a = insert_payload(self.conn, payload="'", category="injection.sql",
                           risk_class="non_destructive_probe", tech=None, cwe=None,
                           source_path="a", source_repo="PAT")
        b = insert_payload(self.conn, payload="'", category="injection.sql",
                           risk_class="non_destructive_probe", tech=None, cwe=None,
                           source_path="b", source_repo="PAT")
        self.assertEqual(a, b)
        count = self.conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
        self.assertEqual(count, 1)

    def test_read_only_connection_rejects_writes(self):
        self.conn.close()
        ro = open_db(self.db, read_only=True)
        with self.assertRaises(sqlite3.OperationalError):
            ro.execute("INSERT INTO payloads(payload, category, risk_class, sha256) "
                       "VALUES('x','y','z','w')")
        ro.close()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_schema -v`
Expected: FAIL — `No module named 'payload_library.src.schema'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/schema.py
"""SQLite storage with an FTS5 index over payload text. Stdlib only."""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

_DDL = """
CREATE TABLE IF NOT EXISTS payloads (
    id          INTEGER PRIMARY KEY,
    payload     TEXT NOT NULL,
    category    TEXT NOT NULL,
    risk_class  TEXT NOT NULL,
    tech        TEXT,
    cwe         TEXT,
    source_path TEXT,
    source_repo TEXT,
    sha256      TEXT NOT NULL,
    UNIQUE(sha256, category)
);
CREATE INDEX IF NOT EXISTS idx_payloads_cat  ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payloads_risk ON payloads(risk_class);
CREATE INDEX IF NOT EXISTS idx_payloads_tech ON payloads(tech);

CREATE VIRTUAL TABLE IF NOT EXISTS payloads_fts
    USING fts5(payload, category, tech, content='payloads', content_rowid='id');

CREATE TRIGGER IF NOT EXISTS payloads_ai AFTER INSERT ON payloads BEGIN
    INSERT INTO payloads_fts(rowid, payload, category, tech)
    VALUES (new.id, new.payload, new.category, new.tech);
END;

CREATE TABLE IF NOT EXISTS wordlists (
    id          INTEGER PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    category    TEXT NOT NULL,
    line_count  INTEGER NOT NULL,
    byte_size   INTEGER NOT NULL,
    source_repo TEXT
);
CREATE INDEX IF NOT EXISTS idx_wordlists_cat ON wordlists(category);

CREATE TABLE IF NOT EXISTS build_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def open_db(path: Path, read_only: bool = True) -> sqlite3.Connection:
    path = Path(path)
    if read_only:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_DDL)
    conn.commit()


def insert_payload(conn, *, payload, category, risk_class,
                   tech=None, cwe=None, source_path=None, source_repo=None) -> int:
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    existing = conn.execute(
        "SELECT id FROM payloads WHERE sha256=? AND category=?", (digest, category)).fetchone()
    if existing:
        return int(existing["id"])
    cur = conn.execute(
        "INSERT INTO payloads(payload, category, risk_class, tech, cwe, "
        "source_path, source_repo, sha256) VALUES (?,?,?,?,?,?,?,?)",
        (payload, category, risk_class, tech, cwe, source_path, source_repo, digest))
    conn.commit()
    return int(cur.lastrowid)
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_schema -v`
Expected: 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/schema.py payload_library/tests/test_schema.py
git commit -m "feat(payload-library): sqlite schema with FTS5 index and dedup"
```

---

### Task 4: ETL — raw corpora to indexed rows

**Files:**
- Create: `payload_library/src/etl.py`
- Create: `payload_library/tests/fixtures/` (tiny fake trees, written by the test)
- Test: `payload_library/tests/test_etl.py`

**Interfaces:**
- Consumes: `classify_risk`, `categorize` from `src.classify`; `open_db`, `create_schema`, `insert_payload` from `src.schema`.
- Produces: `extract_payloads(path: Path) -> list[str]`; `build_index(raw_root: Path, db_path: Path, meta: dict[str, str]) -> dict` returning `{"payloads": int, "wordlists": int, "skipped": int}`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_etl.py
import tempfile
import unittest
from pathlib import Path
from payload_library.src.etl import extract_payloads, build_index
from payload_library.src.schema import open_db


class TestExtract(unittest.TestCase):
    def test_strips_markdown_fences_and_comments(self):
        p = Path(tempfile.mkdtemp()) / "x.md"
        p.write_text("# Heading\n\n```sql\n' OR 1=1--\n' UNION SELECT version()--\n```\n\nprose\n")
        self.assertEqual(extract_payloads(p), ["' OR 1=1--", "' UNION SELECT version()--"])

    def test_plain_txt_is_line_per_payload_minus_blanks_and_hashes(self):
        p = Path(tempfile.mkdtemp()) / "x.txt"
        p.write_text("# comment\n\n../../etc/passwd\n\n..%2f..%2fetc%2fpasswd\n")
        self.assertEqual(extract_payloads(p), ["../../etc/passwd", "..%2f..%2fetc%2fpasswd"])


class TestBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        pat = self.root / "raw" / "PayloadsAllTheThings" / "SQL Injection"
        pat.mkdir(parents=True)
        (pat / "probes.txt").write_text("'\n' UNION SELECT version()--\n'; DROP TABLE t--\n")
        sec = self.root / "raw" / "SecLists" / "Discovery" / "Web-Content"
        sec.mkdir(parents=True)
        (sec / "small.txt").write_text("admin\nlogin\napi\n")
        self.db = self.root / "db" / "t.sqlite3"

    def tearDown(self):
        self.tmp.cleanup()

    def test_indexes_payloads_with_risk_and_category(self):
        stats = build_index(self.root / "raw", self.db, {"PAT_SHA": "abc123"})
        self.assertEqual(stats["payloads"], 3)
        conn = open_db(self.db, read_only=True)
        rows = {r["payload"]: r["risk_class"]
                for r in conn.execute("SELECT payload, risk_class FROM payloads")}
        self.assertEqual(rows["'"], "non_destructive_probe")
        self.assertEqual(rows["' UNION SELECT version()--"], "read_only_probe")
        self.assertEqual(rows["'; DROP TABLE t--"], "destructive")
        cats = {r["category"] for r in conn.execute("SELECT DISTINCT category FROM payloads")}
        self.assertEqual(cats, {"injection.sql"})
        conn.close()

    def test_registers_wordlists_with_counts(self):
        build_index(self.root / "raw", self.db, {})
        conn = open_db(self.db, read_only=True)
        wl = conn.execute("SELECT * FROM wordlists WHERE category='discovery.directory'").fetchone()
        self.assertEqual(wl["line_count"], 3)
        self.assertGreater(wl["byte_size"], 0)
        conn.close()

    def test_records_pinned_shas_in_build_meta(self):
        build_index(self.root / "raw", self.db, {"PAT_SHA": "abc123", "SECLISTS_SHA": "def456"})
        conn = open_db(self.db, read_only=True)
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM build_meta")}
        self.assertEqual(meta["PAT_SHA"], "abc123")
        self.assertEqual(meta["SECLISTS_SHA"], "def456")
        conn.close()

    def test_rebuild_is_idempotent(self):
        a = build_index(self.root / "raw", self.db, {})
        b = build_index(self.root / "raw", self.db, {})
        conn = open_db(self.db, read_only=True)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0], a["payloads"])
        conn.close()
        self.assertEqual(a["payloads"], b["payloads"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_etl -v`
Expected: FAIL — `No module named 'payload_library.src.etl'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/etl.py
"""raw/ corpora -> classified rows in SQLite. Stdlib only, idempotent."""
from __future__ import annotations

import re
from pathlib import Path

from .classify import categorize, classify_risk
from .schema import create_schema, insert_payload, open_db

_FENCE = re.compile(r"^```")
_WORDLIST_CATEGORIES = {"discovery.directory", "discovery.subdomain",
                        "credential.username", "credential.password"}
_MAX_PAYLOAD_LEN = 4096


def extract_payloads(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if path.suffix.lower() in (".md", ".markdown"):
        out, inside = [], False
        for line in lines:
            if _FENCE.match(line.strip()):
                inside = not inside
                continue
            if inside and line.strip():
                out.append(line.rstrip())
        return out
    return [ln.rstrip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def build_index(raw_root: Path, db_path: Path, meta: dict[str, str]) -> dict:
    raw_root, db_path = Path(raw_root), Path(db_path)
    conn = open_db(db_path, read_only=False)
    create_schema(conn)
    stats = {"payloads": 0, "wordlists": 0, "skipped": 0}

    for path in sorted(raw_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".txt", ".md", ".markdown"):
            continue
        rel = str(path.relative_to(raw_root.parent))
        category = categorize(rel)
        if category == "uncategorised":
            stats["skipped"] += 1
            continue
        repo = path.relative_to(raw_root).parts[0] if path.relative_to(raw_root).parts else None

        if category in _WORDLIST_CATEGORIES:
            lines = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace"))
            conn.execute(
                "INSERT INTO wordlists(path, category, line_count, byte_size, source_repo) "
                "VALUES (?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET "
                "line_count=excluded.line_count, byte_size=excluded.byte_size",
                (str(path), category, lines, path.stat().st_size, repo))
            stats["wordlists"] += 1
            continue

        for payload in extract_payloads(path):
            if len(payload) > _MAX_PAYLOAD_LEN:
                stats["skipped"] += 1
                continue
            insert_payload(conn, payload=payload, category=category,
                           risk_class=classify_risk(payload), tech=None, cwe=None,
                           source_path=rel, source_repo=repo)
            stats["payloads"] += 1

    for key, value in (meta or {}).items():
        conn.execute("INSERT INTO build_meta(key, value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    conn.commit()
    stats["payloads"] = conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
    conn.close()
    return stats
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_etl -v`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/etl.py payload_library/tests/test_etl.py
git commit -m "feat(payload-library): idempotent ETL with pinned-SHA build metadata"
```

---

### Task 5: Query and set materialization

The core safety surface: this is where a `risk_class` is enforced and where a file gets written.

**Files:**
- Create: `payload_library/src/query.py`
- Test: `payload_library/tests/test_query.py`

**Interfaces:**
- Consumes: `Config`, `RISK_CLASSES` from `src.config`. Takes an open `conn` as an argument — it does not import `src.schema`.
- Produces: `search(conn, *, category, risk_class, tech=None, cwe=None, max_payloads=50, sample=3) -> dict`; `create_set(conn, cfg, *, set_name, query_params) -> dict`. `search` returns `{"count", "category", "risk_class", "techs", "sample", "truncated"}`. `create_set` returns `{"set_id", "path", "line_count", "sha256"}`. Both raise `ValueError` on a rejected `risk_class`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_query.py
import hashlib
import tempfile
import unittest
from pathlib import Path
from payload_library.src.config import load_config
from payload_library.src.query import search, create_set
from payload_library.src.schema import open_db, create_schema, insert_payload


def _seed(conn):
    rows = [("'", "non_destructive_probe", None),
            ("' UNION SELECT version()--", "read_only_probe", "postgres"),
            ("' UNION SELECT database()--", "read_only_probe", "mysql"),
            ("'; DROP TABLE t--", "destructive", None)]
    for payload, risk, tech in rows:
        insert_payload(conn, payload=payload, category="injection.sql", risk_class=risk,
                       tech=tech, cwe="CWE-89", source_path="p", source_repo="PAT")


class TestQuery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = open_db(self.root / "t.sqlite3", read_only=False)
        create_schema(self.conn)
        _seed(self.conn)
        self.cfg = load_config({"SAHW_PAYLOAD_LIBRARY": str(self.root), "SAHW_PAYLOAD_MAX_SET": "2"})

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_search_filters_by_risk_class(self):
        r = search(self.conn, category="injection.sql", risk_class="read_only_probe")
        self.assertEqual(r["count"], 2)

    def test_search_never_returns_destructive_rows(self):
        r = search(self.conn, category="injection.sql", risk_class="non_destructive_probe")
        self.assertEqual(r["count"], 1)
        self.assertNotIn("DROP", " ".join(r["sample"]))

    def test_search_rejects_unsafe_risk_class(self):
        for bad in ["destructive", "state_changing", "", None, "anything"]:
            with self.assertRaises(ValueError):
                search(self.conn, category="injection.sql", risk_class=bad)

    def test_search_sample_is_capped(self):
        r = search(self.conn, category="injection.sql", risk_class="read_only_probe", sample=1)
        self.assertEqual(len(r["sample"]), 1)

    def test_search_filters_by_tech(self):
        r = search(self.conn, category="injection.sql", risk_class="read_only_probe", tech="postgres")
        self.assertEqual(r["count"], 1)


class TestCreateSet(TestQuery):
    def test_writes_file_and_returns_hash(self):
        out = create_set(self.conn, self.cfg, set_name="sqli-ro",
                         query_params={"category": "injection.sql", "risk_class": "read_only_probe"})
        path = Path(out["path"])
        self.assertTrue(path.is_file())
        self.assertEqual(out["line_count"], 2)
        self.assertEqual(out["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_respects_max_set_cap(self):
        cfg = load_config({"SAHW_PAYLOAD_LIBRARY": str(self.root), "SAHW_PAYLOAD_MAX_SET": "1"})
        out = create_set(self.conn, cfg, set_name="capped",
                         query_params={"category": "injection.sql", "risk_class": "read_only_probe"})
        self.assertEqual(out["line_count"], 1)

    def test_refuses_unsafe_risk_class_and_writes_nothing(self):
        with self.assertRaises(ValueError):
            create_set(self.conn, self.cfg, set_name="bad",
                       query_params={"category": "injection.sql", "risk_class": "destructive"})
        self.assertEqual(list(self.cfg.sets.glob("bad*")), [])

    def test_set_name_is_sanitised_against_traversal(self):
        out = create_set(self.conn, self.cfg, set_name="../../etc/evil",
                         query_params={"category": "injection.sql", "risk_class": "read_only_probe"})
        self.assertTrue(Path(out["path"]).resolve().is_relative_to(self.cfg.sets.resolve()))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_query -v`
Expected: FAIL — `No module named 'payload_library.src.query'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/query.py
"""Indexed selection. Returns metadata and paths — never bulk payload text."""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

from .config import RISK_CLASSES, Config

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _require_safe_risk(risk_class) -> str:
    if risk_class not in RISK_CLASSES:
        raise ValueError(
            f"risk_class must be one of {RISK_CLASSES}; got {risk_class!r}. "
            "Destructive and state-changing payloads are not agent-selectable.")
    return risk_class


def _where(category, risk_class, tech, cwe):
    clauses, params = ["category = ?", "risk_class = ?"], [category, risk_class]
    if tech:
        clauses.append("tech = ?"); params.append(tech)
    if cwe:
        clauses.append("cwe = ?"); params.append(cwe)
    return " AND ".join(clauses), params


def search(conn, *, category, risk_class, tech=None, cwe=None,
           max_payloads=50, sample=3) -> dict:
    _require_safe_risk(risk_class)
    where, params = _where(category, risk_class, tech, cwe)
    count = conn.execute(f"SELECT COUNT(*) FROM payloads WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT payload FROM payloads WHERE {where} LIMIT ?", [*params, max(0, int(sample))]
    ).fetchall()
    techs = [r[0] for r in conn.execute(
        f"SELECT DISTINCT tech FROM payloads WHERE {where} AND tech IS NOT NULL", params)]
    return {"count": count, "category": category, "risk_class": risk_class,
            "techs": techs, "sample": [r["payload"] for r in rows],
            "truncated": count > max_payloads}


def create_set(conn, cfg: Config, *, set_name: str, query_params: dict) -> dict:
    risk_class = _require_safe_risk(query_params.get("risk_class"))
    category = query_params.get("category")
    where, params = _where(category, risk_class, query_params.get("tech"), query_params.get("cwe"))
    limit = min(int(query_params.get("max_payloads", cfg.max_set)), cfg.max_set)
    rows = conn.execute(
        f"SELECT payload FROM payloads WHERE {where} LIMIT ?", [*params, limit]).fetchall()

    safe = _SAFE_NAME.sub("-", set_name).strip("-") or "set"
    set_id = f"{safe}-{uuid.uuid4().hex[:8]}"
    cfg.sets.mkdir(parents=True, exist_ok=True)
    path = (cfg.sets / f"{set_id}.txt").resolve()
    if not path.is_relative_to(cfg.sets.resolve()):
        raise ValueError("refusing to write outside the generated-sets directory")

    body = "".join(f"{r['payload']}\n" for r in rows)
    path.write_text(body, encoding="utf-8")
    return {"set_id": set_id, "path": str(path), "line_count": len(rows),
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest()}
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_query -v`
Expected: **14** tests PASS — 9 methods are defined, but `TestCreateSet(TestQuery)` re-runs TestQuery's 5, so 5 + (5 + 4) = 14. A count of 9 means the subclass did not inherit.

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/query.py payload_library/tests/test_query.py
git commit -m "feat(payload-library): risk-gated search and set materialization"
```

---

### Task 6: Wordlist search and preview

**Files:**
- Create: `payload_library/src/wordlist.py`
- Test: `payload_library/tests/test_wordlist.py`

**Interfaces:**
- Consumes: `Config` from `src.config`.
- Produces: `search(conn, cfg, *, category, max_lines=None) -> list[dict]`; `preview(cfg, *, path, n=None) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_wordlist.py
import tempfile
import unittest
from pathlib import Path
from payload_library.src.config import load_config
from payload_library.src.schema import open_db, create_schema
from payload_library.src.wordlist import search, preview


class TestWordlist(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.lib = self.root / "lib"
        (self.lib / "raw").mkdir(parents=True)
        self.small = self.lib / "raw" / "small.txt"
        self.small.write_text("admin\nlogin\napi\nassets\nbackup\n")
        self.cfg = load_config({"SAHW_PAYLOAD_LIBRARY": str(self.lib),
                                "SAHW_WORDLIST_MAX_LINES": "10",
                                "SAHW_PAYLOAD_PREVIEW_LINES": "2"})
        self.conn = open_db(self.root / "t.sqlite3", read_only=False)
        create_schema(self.conn)
        for path, lines in ((str(self.small), 5), ("/lib/raw/huge.txt", 500_000)):
            self.conn.execute("INSERT INTO wordlists(path, category, line_count, byte_size, "
                              "source_repo) VALUES (?,?,?,?,?)",
                              (path, "discovery.directory", lines, lines * 6, "SecLists"))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_search_applies_tier_cap(self):
        results = search(self.conn, self.cfg, category="discovery.directory")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["line_count"], 5)

    def test_explicit_max_lines_cannot_exceed_the_tier_cap(self):
        results = search(self.conn, self.cfg, category="discovery.directory", max_lines=1_000_000)
        self.assertEqual(len(results), 1)

    def test_preview_is_capped_and_returns_text(self):
        out = preview(self.cfg, path=str(self.small), n=999)
        self.assertEqual(out["lines"], ["admin", "login"])
        self.assertEqual(out["returned"], 2)

    def test_preview_refuses_paths_outside_the_library(self):
        outside = self.root / "outside.txt"
        outside.write_text("secret\n")
        with self.assertRaises(ValueError):
            preview(self.cfg, path=str(outside))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_wordlist -v`
Expected: FAIL — `No module named 'payload_library.src.wordlist'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/wordlist.py
"""Wordlist metadata and bounded preview. Never returns a whole list."""
from __future__ import annotations

from pathlib import Path

from .config import Config


def search(conn, cfg: Config, *, category: str, max_lines: int | None = None) -> list[dict]:
    cap = min(int(max_lines), cfg.wordlist_max_lines) if max_lines else cfg.wordlist_max_lines
    rows = conn.execute(
        "SELECT path, category, line_count, byte_size, source_repo FROM wordlists "
        "WHERE category = ? AND line_count <= ? ORDER BY line_count DESC", (category, cap)
    ).fetchall()
    return [dict(r) for r in rows]


def preview(cfg: Config, *, path: str, n: int | None = None) -> dict:
    target = Path(path).resolve()
    if not target.is_relative_to(cfg.library.resolve()):
        raise ValueError(f"refusing to read outside the payload library: {target}")
    limit = min(int(n), cfg.preview_lines) if n else cfg.preview_lines
    lines: list[str] = []
    with target.open("r", encoding="utf-8", errors="replace") as fh:
        for _, line in zip(range(limit), fh):
            lines.append(line.rstrip("\n"))
    return {"path": str(target), "lines": lines, "returned": len(lines)}
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_wordlist -v`
Expected: 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/wordlist.py payload_library/tests/test_wordlist.py
git commit -m "feat(payload-library): tier-capped wordlist search and bounded preview"
```

---

### Task 7: OpenAI function-tool schemas and dispatcher

**Files:**
- Create: `payload_library/src/tools.py`
- Test: `payload_library/tests/test_tools.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `TOOL_SCHEMAS: list[dict]` (OpenAI `chat.completions` function-tool shape); `dispatch(name: str, arguments: dict, *, conn, cfg) -> dict`.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_tools.py
import tempfile
import unittest
from pathlib import Path
from payload_library.src.config import load_config
from payload_library.src.schema import open_db, create_schema, insert_payload
from payload_library.src.tools import TOOL_SCHEMAS, dispatch


class TestSchemas(unittest.TestCase):
    def test_exactly_four_tools_in_chat_completions_shape(self):
        names = [t["function"]["name"] for t in TOOL_SCHEMAS]
        self.assertEqual(sorted(names),
                         ["payload_search", "payload_set_create",
                          "wordlist_preview", "wordlist_search"])
        for t in TOOL_SCHEMAS:
            self.assertEqual(t["type"], "function")
            self.assertIn("parameters", t["function"])
            self.assertTrue(t["function"]["description"])

    def test_risk_class_is_required_and_enumerated_to_safe_values(self):
        fn = next(t["function"] for t in TOOL_SCHEMAS if t["function"]["name"] == "payload_search")
        self.assertIn("risk_class", fn["parameters"]["required"])
        self.assertEqual(fn["parameters"]["properties"]["risk_class"]["enum"],
                         ["non_destructive_probe", "read_only_probe"])


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.conn = open_db(self.root / "t.sqlite3", read_only=False)
        create_schema(self.conn)
        insert_payload(self.conn, payload="' UNION SELECT version()--", category="injection.sql",
                       risk_class="read_only_probe", tech="postgres", cwe="CWE-89",
                       source_path="p", source_repo="PAT")
        self.cfg = load_config({"SAHW_PAYLOAD_LIBRARY": str(self.root)})

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_routes_payload_search(self):
        out = dispatch("payload_search",
                       {"category": "injection.sql", "risk_class": "read_only_probe"},
                       conn=self.conn, cfg=self.cfg)
        self.assertEqual(out["count"], 1)

    def test_routes_payload_set_create_and_returns_a_path(self):
        out = dispatch("payload_set_create",
                       {"set_name": "s", "query_params":
                        {"category": "injection.sql", "risk_class": "read_only_probe"}},
                       conn=self.conn, cfg=self.cfg)
        self.assertTrue(Path(out["path"]).is_file())
        self.assertIn("sha256", out)

    def test_unknown_tool_is_an_error_not_a_silent_pass(self):
        with self.assertRaises(KeyError):
            dispatch("rm_rf", {}, conn=self.conn, cfg=self.cfg)

    def test_unsafe_risk_class_surfaces_as_a_structured_error(self):
        out = dispatch("payload_search",
                       {"category": "injection.sql", "risk_class": "destructive"},
                       conn=self.conn, cfg=self.cfg)
        self.assertIn("error", out)
        self.assertIn("risk_class", out["error"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_tools -v`
Expected: FAIL — `No module named 'payload_library.src.tools'`

- [ ] **Step 3: Implement**

```python
# payload_library/src/tools.py
"""The four OpenAI function tools. Chat Completions shape — the Responses API
is not assumed (see spec section 5.1)."""
from __future__ import annotations

from . import query as _query
from . import wordlist as _wordlist
from .config import RISK_CLASSES

_RISK = {"type": "string", "enum": list(RISK_CLASSES),
         "description": "Only these two are agent-selectable."}

TOOL_SCHEMAS: list[dict] = [
    {"type": "function", "function": {
        "name": "payload_search",
        "description": ("Search indexed payloads by category, tech, CWE and risk. Returns "
                        "counts and a small metadata sample — NEVER the full payload set."),
        "parameters": {"type": "object", "properties": {
            "category": {"type": "string", "description": "e.g. 'injection.sql'"},
            "tech": {"type": "string", "description": "e.g. 'postgres'"},
            "cwe": {"type": "string", "description": "e.g. 'CWE-89'"},
            "risk_class": _RISK,
            "max_payloads": {"type": "integer", "default": 50},
        }, "required": ["category", "risk_class"]}}},
    {"type": "function", "function": {
        "name": "payload_set_create",
        "description": ("Write matched payloads to a temporary .txt and return its absolute "
                        "path, line count and sha256, for use by ffuf, sqlmap or a script."),
        "parameters": {"type": "object", "properties": {
            "set_name": {"type": "string", "description": "e.g. 'sqli-postgres-small'"},
            "query_params": {"type": "object", "description": "Same fields as payload_search."},
        }, "required": ["set_name", "query_params"]}}},
    {"type": "function", "function": {
        "name": "wordlist_search",
        "description": "Find wordlist metadata (path, line count, byte size), capped by tier.",
        "parameters": {"type": "object", "properties": {
            "category": {"type": "string", "description": "e.g. 'discovery.directory'"},
            "max_lines": {"type": "integer", "description": "Cannot exceed the configured tier cap."},
        }, "required": ["category"]}}},
    {"type": "function", "function": {
        "name": "wordlist_preview",
        "description": "Return the first n lines of a wordlist inside the library. Hard-capped.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "n": {"type": "integer", "default": 10},
        }, "required": ["path"]}}},
]


def _payload_search(args, *, conn, cfg):
    return _query.search(conn, category=args["category"], risk_class=args.get("risk_class"),
                         tech=args.get("tech"), cwe=args.get("cwe"),
                         max_payloads=int(args.get("max_payloads", 50)))


def _payload_set_create(args, *, conn, cfg):
    return _query.create_set(conn, cfg, set_name=args["set_name"],
                             query_params=args.get("query_params") or {})


def _wordlist_search(args, *, conn, cfg):
    return {"results": _wordlist.search(conn, cfg, category=args["category"],
                                        max_lines=args.get("max_lines"))}


def _wordlist_preview(args, *, conn, cfg):
    return _wordlist.preview(cfg, path=args["path"], n=args.get("n"))


_HANDLERS = {
    "payload_search": _payload_search,
    "payload_set_create": _payload_set_create,
    "wordlist_search": _wordlist_search,
    "wordlist_preview": _wordlist_preview,
}


def dispatch(name: str, arguments: dict, *, conn, cfg) -> dict:
    if name not in _HANDLERS:
        raise KeyError(f"unknown payload-library tool: {name!r}")
    try:
        return _HANDLERS[name](arguments or {}, conn=conn, cfg=cfg)
    except ValueError as exc:
        return {"error": str(exc)}
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `python3 -m unittest payload_library.tests.test_tools -v`
Expected: 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/src/tools.py payload_library/tests/test_tools.py
git commit -m "feat(payload-library): OpenAI function-tool schemas and dispatcher"
```

---

### Task 8: CLIs, pinned fetch, and README

**Files:**
- Create: `payload_library/bin/payload-query`, `payload_library/bin/wordlist-info`
- Create: `payload_library/fetch.sh`
- Create: `payload_library/README.md`
- Test: `payload_library/tests/test_cli.py`

**Interfaces:**
- Consumes: `dispatch` from `src.tools`; `load_config` from `src.config`; `open_db` from `src.schema`; `build_index` from `src.etl`.
- Produces: two executables that print one JSON object to stdout and exit non-zero on error.

- [ ] **Step 1: Write the failing test**

```python
# payload_library/tests/test_cli.py
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from payload_library.src.schema import open_db, create_schema, insert_payload

ROOT = Path(__file__).resolve().parents[2]


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lib = Path(self.tmp.name)
        conn = open_db(self.lib / "db" / "payload-library.sqlite3", read_only=False)
        create_schema(conn)
        insert_payload(conn, payload="' UNION SELECT version()--", category="injection.sql",
                       risk_class="read_only_probe", tech="postgres", cwe="CWE-89",
                       source_path="p", source_repo="PAT")
        conn.close()
        self.env = {"SAHW_PAYLOAD_LIBRARY": str(self.lib), "PATH": "/usr/bin:/bin",
                    "PYTHONPATH": str(ROOT)}

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "payload_library/bin/payload-query"), *args],
                              capture_output=True, text=True, env=self.env)

    def test_search_prints_json_and_exits_zero(self):
        r = self._run("search", "--category", "injection.sql",
                      "--risk-class", "read_only_probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["count"], 1)

    def test_unsafe_risk_class_exits_non_zero(self):
        r = self._run("search", "--category", "injection.sql", "--risk-class", "destructive")
        self.assertNotEqual(r.returncode, 0)

    def test_stdout_is_json_only_no_prose(self):
        r = self._run("search", "--category", "injection.sql", "--risk-class", "read_only_probe")
        json.loads(r.stdout)  # raises if prose leaked onto stdout


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `python3 -m unittest payload_library.tests.test_cli -v`
Expected: FAIL — the `payload-query` file does not exist

- [ ] **Step 3: Implement**

```python
#!/usr/bin/env python3
# payload_library/bin/payload-query
"""CLI over the payload index. Strict JSON on stdout, diagnostics on stderr."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from payload_library.src.config import load_config          # noqa: E402
from payload_library.src.etl import build_index             # noqa: E402
from payload_library.src.schema import open_db              # noqa: E402
from payload_library.src.tools import dispatch              # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(prog="payload-query")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search")
    s.add_argument("--category", required=True)
    s.add_argument("--risk-class", required=True)
    s.add_argument("--tech")
    s.add_argument("--cwe")
    s.add_argument("--max-payloads", type=int, default=50)

    c = sub.add_parser("create-set")
    c.add_argument("--set-name", required=True)
    c.add_argument("--category", required=True)
    c.add_argument("--risk-class", required=True)
    c.add_argument("--tech")

    b = sub.add_parser("build")
    b.add_argument("--raw", required=True)
    b.add_argument("--pat-sha", default="")
    b.add_argument("--seclists-sha", default="")

    args = ap.parse_args()
    cfg = load_config()

    if args.cmd == "build":
        stats = build_index(Path(args.raw), cfg.db,
                            {"PAT_SHA": args.pat_sha, "SECLISTS_SHA": args.seclists_sha})
        print(json.dumps(stats))
        return 0

    conn = open_db(cfg.db, read_only=(args.cmd == "search"))
    try:
        if args.cmd == "search":
            out = dispatch("payload_search", {
                "category": args.category, "risk_class": args.risk_class,
                "tech": args.tech, "cwe": args.cwe, "max_payloads": args.max_payloads},
                conn=conn, cfg=cfg)
        else:
            out = dispatch("payload_set_create", {
                "set_name": args.set_name,
                "query_params": {"category": args.category, "risk_class": args.risk_class,
                                 "tech": args.tech}}, conn=conn, cfg=cfg)
    finally:
        conn.close()

    if "error" in out:
        print(out["error"], file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
#!/usr/bin/env python3
# payload_library/bin/wordlist-info
"""CLI over the wordlist index. Strict JSON on stdout."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from payload_library.src.config import load_config          # noqa: E402
from payload_library.src.schema import open_db              # noqa: E402
from payload_library.src.tools import dispatch              # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(prog="wordlist-info")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("search")
    s.add_argument("--category", required=True)
    s.add_argument("--max-lines", type=int)
    p = sub.add_parser("preview")
    p.add_argument("--path", required=True)
    p.add_argument("-n", type=int, default=10)

    args = ap.parse_args()
    cfg = load_config()
    conn = open_db(cfg.db, read_only=True)
    try:
        if args.cmd == "search":
            out = dispatch("wordlist_search",
                           {"category": args.category, "max_lines": args.max_lines},
                           conn=conn, cfg=cfg)
        else:
            out = dispatch("wordlist_preview", {"path": args.path, "n": args.n},
                           conn=conn, cfg=cfg)
    finally:
        conn.close()

    if "error" in out:
        print(out["error"], file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

```bash
#!/usr/bin/env bash
# payload_library/fetch.sh — clone sources at PINNED commits, then build the index.
# A corpus that shifts underneath you invalidates every replay that referenced it.
set -euo pipefail

LIB="${SAHW_PAYLOAD_LIBRARY:-/opt/payload-library}"
PAT_SHA="${SAHW_PAYLOAD_PAT_SHA:?set SAHW_PAYLOAD_PAT_SHA to a commit SHA}"
SECLISTS_SHA="${SAHW_PAYLOAD_SECLISTS_SHA:?set SAHW_PAYLOAD_SECLISTS_SHA to a commit SHA}"

clone_pinned() {
  local url="$1" dest="$2" sha="$3"
  rm -rf "$dest"; mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$url"
  git -C "$dest" fetch -q --depth 1 origin "$sha"
  git -C "$dest" checkout -q FETCH_HEAD
  [ "$(git -C "$dest" rev-parse HEAD)" = "$sha" ] || { echo "SHA mismatch in $dest" >&2; exit 1; }
}

mkdir -p "$LIB/raw" "$LIB/db" "$LIB/normalized" "$LIB/sets/generated"
clone_pinned https://github.com/swisskyrepo/PayloadsAllTheThings "$LIB/raw/PayloadsAllTheThings" "$PAT_SHA"
clone_pinned https://github.com/danielmiessler/SecLists          "$LIB/raw/SecLists"             "$SECLISTS_SHA"

python3 "$(dirname "$0")/bin/payload-query" build \
  --raw "$LIB/raw" --pat-sha "$PAT_SHA" --seclists-sha "$SECLISTS_SHA"

chmod -R a-w "$LIB/raw" "$LIB/db"
echo "built: $LIB" >&2
```

`payload_library/README.md` documents: the three commands (`fetch.sh`, `payload-query build`, `payload-query search|create-set`, `wordlist-info search|preview`), the env knobs from `.env.example`, the read-only mount requirement, and the rule that `raw/` is never read by `shell_exec`.

- [ ] **Step 4: Run the whole suite**

```bash
chmod +x payload_library/bin/payload-query payload_library/bin/wordlist-info payload_library/fetch.sh
python3 -m unittest discover -s payload_library/tests -t . -v
```
Expected: all tests across all 8 modules PASS

- [ ] **Step 5: Commit**

```bash
git add payload_library/bin payload_library/fetch.sh payload_library/README.md payload_library/tests/test_cli.py
git commit -m "feat(payload-library): CLIs, pinned-SHA fetch, and README"
```

---

## Out of scope for this plan

Named so nobody builds them by accident:

- **Tether enforcement** of `risk_class` gating and the anti-`cat` rule (spec §9.4) lives in the TypeScript orchestrator's dispatch wrapper, which does not exist yet. This library enforces risk at the query layer; the Tether is the second, independent gate.
- **ClickHouse `payload_usage_events`** (spec §9.6) — emitted by the orchestrator when it dispatches a tool call, not by this package.
- **Wiring the four tools into agent requests** — the agent files already declare them in `tools:`; the orchestrator binds `TOOL_SCHEMAS` and `dispatch` when it is built.
- **The 36 skills stay untouched** (spec §9.5). Do not edit `skills/`.

## Self-review

**Spec coverage.** §9.1 layout → Task 8 `fetch.sh`. §9.2 four tools → Task 7, backed by Tasks 5–6. §9.3 workflow → Task 5 `create_set` returns the path the workflow needs. §9.4 governance: immutability → Task 8 `chmod -R a-w`; risk gating → Tasks 2 and 5, with the orchestrator half listed out of scope. §9.5 boundaries → out-of-scope section. §9.6 observability → out of scope, correctly, since the orchestrator emits it. Pinned SHAs → Tasks 4 and 8.

**Placeholders.** None: every step carries runnable code and an exact command.

**Type consistency.** `Config` fields (`library`, `db`, `sets`, `max_set`, `wordlist_max_lines`, `preview_lines`) are used identically in Tasks 5, 6, 7, 8. `RISK_CLASSES` is defined once in `config.py` and imported by `classify.py`, `query.py` and `tools.py`. `create_set` returns `{set_id, path, line_count, sha256}` in Task 5 and is consumed with those exact keys in Tasks 7 and 8. `dispatch(name, arguments, *, conn, cfg)` has one signature throughout.

**One thing to watch during execution.** Task 1 renames the directory from `payload-library` to `payload_library` so it is importable. The spec's §9.1 layout diagram shows the hyphenated *mount path* `/opt/payload-library`, which is correct and unchanged — only the source directory in this repo uses the underscore.

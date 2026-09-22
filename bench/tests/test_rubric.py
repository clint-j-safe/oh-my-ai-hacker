import unittest

from bench.rubric import (
    DEFAULT_RUBRIC_PATH,
    VALID_INVARIANT_TYPES,
    Endpoint,
    load_rubric,
    normalize_path,
    parse_rubric,
)


class TestRealRubricParses(unittest.TestCase):
    """Parses the ACTUAL docs/bench/human-test-benchmark.md file (not a fixture)."""

    @classmethod
    def setUpClass(cls):
        cls.rows = load_rubric(DEFAULT_RUBRIC_PATH)

    def test_exactly_28_rows(self):
        # If the rubric's shape changes (rows added/removed/malformed), this must
        # fail loudly rather than silently scoring against a partial rubric.
        self.assertEqual(len(self.rows), 28, f"expected 28 rows, got {len(self.rows)}")

    def test_ids_are_f01_through_f28_in_order(self):
        expected = [f"F-{i:02d}" for i in range(1, 29)]
        self.assertEqual([r.id for r in self.rows], expected)

    def test_every_row_has_nonempty_vuln_class(self):
        for row in self.rows:
            self.assertTrue(row.vuln_class, f"{row.id} has empty vuln_class")
            self.assertNotIn("*", row.vuln_class, f"{row.id} vuln_class still carries a trailing asterisk")
            self.assertNotIn("`", row.vuln_class, f"{row.id} vuln_class leaked a backtick")

    def test_every_row_has_valid_invariant_type(self):
        for row in self.rows:
            self.assertIn(
                row.invariant_type,
                VALID_INVARIANT_TYPES,
                f"{row.id} has invariant type {row.invariant_type!r}, not one of {sorted(VALID_INVARIANT_TYPES)}",
            )

    def test_every_row_has_at_least_one_endpoint_or_is_scope_level(self):
        for row in self.rows:
            self.assertTrue(
                row.endpoints or row.scope,
                f"{row.id} parsed with no endpoints and is not scope-level — endpoint cell was "
                f"{row.raw_endpoint_cell!r}",
            )

    def test_f04_excludes_otp_paths(self):
        row = {r.id: r for r in self.rows}["F-04"]
        self.assertTrue(row.scope)
        self.assertIn("/api/otp", row.exclude_path_prefixes)

    def test_f13_inherits_f01_chain_endpoints(self):
        by_id = {r.id: r for r in self.rows}
        f01_keys = {e.key() for e in by_id["F-01"].endpoints}
        f13_keys = {e.key() for e in by_id["F-13"].endpoints}
        # F-13's cell says "same chain as F-01" and uses bare suffixes
        # (`verifyuser`/`reset`) that don't parse standalone; it should inherit
        # F-01's fully-qualified chain endpoints via the cross-reference.
        self.assertTrue(f01_keys.issubset(f13_keys), f"F-13 endpoints {f13_keys} missing F-01's {f01_keys}")

    def test_f01_chain_has_four_endpoints(self):
        row = {r.id: r for r in self.rows}["F-01"]
        paths = {e.path for e in row.endpoints}
        self.assertEqual(
            paths,
            {
                "/api/password/forgot",
                "/api/password/verifyuser",
                "/api/password/reset",
                "/api/login",
            },
        )

    def test_scope_rows_identified(self):
        by_id = {r.id: r for r in self.rows}
        for gid in ("F-04", "F-08", "F-14", "F-20", "F-26", "F-27"):
            self.assertTrue(by_id[gid].scope, f"{gid} should be scope-level")
        for gid in ("F-02", "F-05", "F-06", "F-11", "F-17", "F-24"):
            self.assertFalse(by_id[gid].scope, f"{gid} should NOT be scope-level")


class TestSyntheticParsing(unittest.TestCase):
    """Smaller, hand-built rubric fragments to pin down specific parsing rules."""

    def _row(self, text: str):
        header = (
            "| ID | vuln_class | Auth | Endpoint (answer key) | Expected invariant (type) | Severity | CVSS | CWE |\n"
            "|----|---|---|---|---|---|---|---|\n"
        )
        rows = parse_rubric(header + text)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_vuln_class_asterisk_stripped(self):
        row = self._row("| F-01 | `user_enumeration`* | none | `GET /api/x` | `body_contains` (x) | Medium | 5.3 | CWE-1 |")
        self.assertEqual(row.vuln_class, "user_enumeration")

    def test_multiple_comma_endpoints(self):
        row = self._row(
            "| F-01 | `x` | none | `POST /api/a`, `POST /api/b` | `body_contains` (x) | Medium | 5.3 | CWE-1 |"
        )
        paths = sorted(e.path for e in row.endpoints)
        self.assertEqual(paths, ["/api/a", "/api/b"])

    def test_or_alternative_endpoints(self):
        row = self._row(
            "| F-01 | `x` | none | `POST /api/a` or `POST /api/b` | `body_contains` (x) | Medium | 5.3 | CWE-1 |"
        )
        paths = sorted(e.path for e in row.endpoints)
        self.assertEqual(paths, ["/api/a", "/api/b"])

    def test_parenthesised_param_dropped(self):
        row = self._row(
            "| F-01 | `x` | none | `POST /api/a` (`data.foo`) | `body_contains` (x) | Medium | 5.3 | CWE-1 |"
        )
        paths = [e.path for e in row.endpoints]
        self.assertEqual(paths, ["/api/a"])

    def test_scope_level_no_path(self):
        row = self._row(
            "| F-01 | `x` | none | platform-wide, e.g. `GET /api/` | `derived` (x) | Medium | 5.3 | CWE-1 |"
        )
        self.assertTrue(row.scope)

    def test_normalize_path_root_and_empty_equal(self):
        self.assertEqual(normalize_path(""), normalize_path("/"))
        self.assertEqual(normalize_path("/"), "")

    def test_normalize_path_strips_query_and_trailing_slash(self):
        self.assertEqual(normalize_path("/api/show?file=/etc/passwd"), "/api/show")
        self.assertEqual(normalize_path("/api/show/"), "/api/show")


if __name__ == "__main__":
    unittest.main()

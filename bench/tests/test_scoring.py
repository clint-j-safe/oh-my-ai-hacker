import unittest

from bench.rubric import Endpoint, GroundTruthRow
from bench.scoring import RunFinding, score


def make_row(
    id_,
    vuln_class,
    endpoints=None,
    invariant_type="body_contains",
    scope=False,
    scope_hosts=None,
    exclude_path_prefixes=None,
    auth="none",
):
    return GroundTruthRow(
        id=id_,
        vuln_class=vuln_class,
        auth=auth,
        endpoints=endpoints or [],
        scope=scope,
        scope_hosts=scope_hosts or [],
        exclude_path_prefixes=exclude_path_prefixes or [],
        invariant_type=invariant_type,
        severity="High",
        cvss="7.5",
        cwe="CWE-1",
    )


def make_finding(
    finding_id="SAHW-0001",
    vuln_class="sqli",
    endpoint="http://168.144.155.177/api/beneficiary/fetch",
    verdict="CONFIRMED",
    invariant_type="body_contains",
):
    return RunFinding(
        engagement_id="ENG-1",
        finding_id=finding_id,
        vuln_class=vuln_class,
        endpoint=endpoint,
        verdict=verdict,
        invariant_type=invariant_type,
        langfuse_trace_id="trace-1",
        utc="2026-09-22T00:00:00Z",
    )


def cov_by_id(result_dict):
    return {c["ground_truth_id"]: c for c in result_dict["coverage"]}


class TestCoveredPartialMissed(unittest.TestCase):
    def test_covered_when_class_endpoint_and_invariant_all_match(self):
        row = make_row(
            "F-06", "sqli", endpoints=[Endpoint(path="/api/beneficiary/fetch")], invariant_type="body_contains"
        )
        finding = make_finding(invariant_type="body_contains")
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-06"]["status"], "covered")
        self.assertEqual(cov_by_id(result)["F-06"]["matched_finding_id"], "SAHW-0001")
        self.assertEqual(result["summary"]["covered"], 1)
        self.assertEqual(result["summary"]["false_positives"], 0)

    def test_partial_when_endpoint_matches_but_invariant_differs(self):
        row = make_row(
            "F-06", "sqli", endpoints=[Endpoint(path="/api/beneficiary/fetch")], invariant_type="body_contains"
        )
        finding = make_finding(invariant_type="status_in")  # wrong proof type
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-06"]["status"], "partial")
        self.assertEqual(cov_by_id(result)["F-06"]["matched_finding_id"], "SAHW-0001")

    def test_missed_when_nothing_matches(self):
        row = make_row("F-02", "idor", endpoints=[Endpoint(path="/api/account/details")])
        result = score([row], []).to_dict()
        self.assertEqual(cov_by_id(result)["F-02"]["status"], "missed")
        self.assertEqual(cov_by_id(result)["F-02"]["matched_finding_id"], "")


class TestVerdictFiltering(unittest.TestCase):
    def test_needs_review_does_not_score_as_covered(self):
        row = make_row(
            "F-06", "sqli", endpoints=[Endpoint(path="/api/beneficiary/fetch")], invariant_type="body_contains"
        )
        finding = make_finding(verdict="NEEDS_REVIEW", invariant_type="body_contains")
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-06"]["status"], "missed")
        self.assertEqual(result["summary"]["covered"], 0)
        # A NEEDS_REVIEW finding is also not a false positive -- it simply doesn't play.
        self.assertEqual(result["summary"]["false_positives"], 0)

    def test_false_positive_and_blocked_also_excluded(self):
        row = make_row(
            "F-06", "sqli", endpoints=[Endpoint(path="/api/beneficiary/fetch")], invariant_type="body_contains"
        )
        for verdict in ("FALSE_POSITIVE", "BLOCKED"):
            f = make_finding(verdict=verdict, invariant_type="body_contains")
            result = score([row], [f]).to_dict()
            self.assertEqual(cov_by_id(result)["F-06"]["status"], "missed", f"verdict={verdict}")


class TestFalsePositives(unittest.TestCase):
    def test_finding_matching_nothing_is_a_false_positive(self):
        row = make_row("F-02", "idor", endpoints=[Endpoint(path="/api/account/details")])
        finding = make_finding(
            finding_id="SAHW-9999", vuln_class="xss_reflected", endpoint="http://h/api/contactUs"
        )
        result = score([row], [finding]).to_dict()
        self.assertEqual(result["summary"]["false_positives"], 1)
        self.assertEqual(result["false_positives"][0]["finding_id"], "SAHW-9999")
        # And it must not have been silently counted as covering the unrelated row.
        self.assertEqual(cov_by_id(result)["F-02"]["status"], "missed")

    def test_sqli_outside_beneficiary_fetch_is_positive_control_false_positive(self):
        row = make_row(
            "F-06", "sqli", endpoints=[Endpoint(path="/api/beneficiary/fetch")], invariant_type="body_contains"
        )
        finding = make_finding(vuln_class="sqli", endpoint="http://h/api/login", invariant_type="body_contains")
        result = score([row], [finding]).to_dict()
        self.assertEqual(result["summary"]["false_positives"], 1)
        self.assertIn("positive control", result["false_positives"][0]["why"])
        self.assertEqual(cov_by_id(result)["F-06"]["status"], "missed")


class TestEndpointNormalization(unittest.TestCase):
    def test_default_port_http_matches_explicit_80(self):
        row = make_row("F-08", "info_disclosure", endpoints=[Endpoint(host="h", port=80, path="/api")])
        finding = make_finding(vuln_class="info_disclosure", endpoint="http://h/api", invariant_type="body_contains")
        row.invariant_type = "body_contains"
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-08"]["status"], "covered")

    def test_trailing_slash_ignored_root_vs_no_path(self):
        # GT written as host:port only (no path at all) must match a run finding
        # whose URL is the bare root "http://h:3000/".
        row = make_row("F-20", "clickjacking", endpoints=[Endpoint(host="h", port=3000, path="")])
        finding = make_finding(vuln_class="clickjacking", endpoint="http://h:3000/", invariant_type="body_contains")
        row.invariant_type = "body_contains"
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-20"]["status"], "covered")

    def test_trailing_slash_does_not_match_unrelated_path(self):
        row = make_row("F-05", "path_traversal", endpoints=[Endpoint(path="/api/show")])
        finding = make_finding(
            vuln_class="path_traversal", endpoint="http://h:3000/", invariant_type="body_contains"
        )
        row.invariant_type = "body_contains"
        result = score([row], [finding]).to_dict()
        # Root path must NOT satisfy a row that requires a specific different path.
        self.assertEqual(cov_by_id(result)["F-05"]["status"], "missed")

    def test_query_string_ignored(self):
        row = make_row("F-05", "path_traversal", endpoints=[Endpoint(path="/api/show")], invariant_type="body_contains")
        finding = make_finding(
            vuln_class="path_traversal",
            endpoint="http://h/api/show?file=/etc/passwd",
            invariant_type="body_contains",
        )
        result = score([row], [finding]).to_dict()
        self.assertEqual(cov_by_id(result)["F-05"]["status"], "covered")


class TestCollisionSafety(unittest.TestCase):
    """Mirrors the F-01/F-13 disambiguation: two rows share vuln_class and an
    overlapping endpoint set but expect different invariant types. One finding
    must never satisfy both."""

    def test_one_finding_cannot_satisfy_two_rows(self):
        shared_endpoint = Endpoint(path="/api/password/reset")
        row_full_takeover = make_row(
            "F-01", "auth_bypass", endpoints=[shared_endpoint], invariant_type="state_changed"
        )
        row_no_second_factor = make_row(
            "F-13", "auth_bypass", endpoints=[shared_endpoint], invariant_type="derived"
        )
        finding = make_finding(
            finding_id="SAHW-0042",
            vuln_class="auth_bypass",
            endpoint="http://h/api/password/reset",
            invariant_type="state_changed",  # only matches F-01's expected type
        )
        result = score([row_full_takeover, row_no_second_factor], [finding]).to_dict()
        by_id = cov_by_id(result)

        self.assertEqual(by_id["F-01"]["status"], "covered")
        self.assertEqual(by_id["F-01"]["matched_finding_id"], "SAHW-0042")

        # F-13 must NOT be auto-satisfied (covered OR partial) by the same finding.
        self.assertEqual(by_id["F-13"]["status"], "missed")
        self.assertEqual(by_id["F-13"]["matched_finding_id"], "")

        # The finding was consumed by a real ground-truth row, so it is not a
        # false positive either.
        self.assertEqual(result["summary"]["false_positives"], 0)

    def test_two_findings_can_independently_satisfy_both_rows(self):
        shared_endpoint = Endpoint(path="/api/password/reset")
        row_full_takeover = make_row(
            "F-01", "auth_bypass", endpoints=[shared_endpoint], invariant_type="state_changed"
        )
        row_no_second_factor = make_row(
            "F-13", "auth_bypass", endpoints=[shared_endpoint], invariant_type="derived"
        )
        f1 = make_finding(
            finding_id="SAHW-0001",
            vuln_class="auth_bypass",
            endpoint="http://h/api/password/reset",
            invariant_type="state_changed",
        )
        f2 = make_finding(
            finding_id="SAHW-0002",
            vuln_class="auth_bypass",
            endpoint="http://h/api/password/reset",
            invariant_type="derived",
        )
        result = score([row_full_takeover, row_no_second_factor], [f1, f2]).to_dict()
        by_id = cov_by_id(result)
        self.assertEqual(by_id["F-01"]["status"], "covered")
        self.assertEqual(by_id["F-01"]["matched_finding_id"], "SAHW-0001")
        self.assertEqual(by_id["F-13"]["status"], "covered")
        self.assertEqual(by_id["F-13"]["matched_finding_id"], "SAHW-0002")


if __name__ == "__main__":
    unittest.main()

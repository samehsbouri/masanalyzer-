"""Analyzer-set tests: all M1..M10 run, fire on vulnerable fixtures, and
never abort the scan when an analyzer breaks."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from collections import Counter

from masanalyzer.analysis import ANALYZERS, run_analyzers
from masanalyzer.analysis import m01, m04, m05
from masanalyzer.model import FindingCollector
from masanalyzer.owasp import ORDER
from masanalyzer.packaging import prepare_target
from masanalyzer.testing import (
    build_android_tree,
    build_ios_tree,
)


class TempBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="masan_analysis_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def android_target(self):
        tree = build_android_tree(os.path.join(self.tmp, "android"))
        return prepare_target(tree)

    def ios_target(self):
        tree = build_ios_tree(os.path.join(self.tmp, "ios"))
        return prepare_target(tree)


class TestRegistry(TempBase):
    def test_all_ten_analyzers_registered(self) -> None:
        self.assertEqual(
            [cid for cid, _ in ANALYZERS], ORDER,
            "analyzers must be registered in OWASP order",
        )
        for cid, fn in ANALYZERS:
            self.assertTrue(callable(fn))

    def test_registry_runs_and_covers_all(self) -> None:
        target = self.android_target()
        collector = FindingCollector()
        covered, failures, count = run_analyzers(target, collector)
        self.assertEqual(failures, [])
        self.assertEqual(count, 10)
        self.assertEqual(covered, ORDER)
        self.assertGreater(len(collector.findings), 0)

    def test_broken_analyzer_recorded_not_raised(self) -> None:
        def boom(target):
            raise RuntimeError("synthetic analyzer bug")

        target = self.android_target()
        collector = FindingCollector()
        saved = ANALYZERS[:]
        ANALYZERS[:] = [("M1", boom)] + ANALYZERS[1:]
        try:
            covered, failures, count = run_analyzers(target, collector)
        finally:
            ANALYZERS[:] = saved
        self.assertEqual(len(failures), 1)
        self.assertIn("RuntimeError", failures[0])
        self.assertEqual(count, 9)  # the broken one did not count
        self.assertNotIn("M1", covered)


class TestRulesFire(TempBase):
    """Sanity: key rules fire on the deliberately vulnerable fixtures."""

    def test_android_rule_coverage(self) -> None:
        target = self.android_target()
        collector = FindingCollector()
        covered, failures, count = run_analyzers(target, collector)
        hit = Counter(f.rule_id for f in collector.findings)
        hits = set(hit)
        expected = {
            "MAS-CRED-002",     # M1 hardcoded api key in LoginActivity.java
            "MAS-AUTH-001",     # M3 exported provider w/o permission
            "MAS-NET-002",      # M5 NSC cleartext
            "MAS-NET-003",      # M5 user certs trust anchors
            "MAS-BIN-001",      # M7 debuggable
        }
        missing = expected - hits
        self.assertEqual(missing, set(), f"missing rules: {missing}; got {sorted(hits)}")
        # every finding is tagged with a valid OWASP id
        for f in collector.findings:
            self.assertIn(f.owasp, ORDER)

    def test_ios_rule_coverage(self) -> None:
        target = self.ios_target()
        collector = FindingCollector()
        covered, failures, count = run_analyzers(target, collector)
        self.assertEqual(failures, [])
        hit = Counter(f.rule_id for f in collector.findings)
        expected = {
            "MAS-NET-007",      # ATS arbitrary loads (Info.plist)
            "MAS-BIN-008",      # dev provisioning get-task-allow
            "MAS-STO-005",      # credentials in UserDefaults/plist
            "MAS-CRED-008",     # plist credential key
            "MAS-PRI-003",      # token printed with print()
        }
        missing = expected - set(hit)
        self.assertEqual(missing, set(), f"expected rules missing (got {sorted(hit)})")


class TestRuleMetadata(TempBase):
    def test_rules_well_formed(self) -> None:
        for module in (m01, m04, m05):
            for name in dir(module):
                rule = getattr(module, name)
                if hasattr(rule, "rule_id") and hasattr(rule, "owasp"):
                    self.assertTrue(rule.rule_id.startswith("MAS-"))
                    self.assertIn(rule.owasp, ORDER)
                    self.assertTrue(rule.remediation)
                    self.assertTrue(rule.title)

    def test_m04_precompile_before_use(self) -> None:
        self.assertTrue(hasattr(m04, "_RX_FILE_UNTRUSTED"))
        self.assertTrue(hasattr(m04, "_RX_SQL_CONCAT"))


if __name__ == "__main__":
    unittest.main()

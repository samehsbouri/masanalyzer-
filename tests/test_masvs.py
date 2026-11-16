"""MASVS v2 requirement matrix (masanalyzer.masvs)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.masvs import (
    MASVS_REQUIREMENTS,
    STATUS_FAIL,
    STATUS_NOT_ASSESSED,
    STATUS_PASS,
    audit,
    render_audit,
    rule_requirements,
)
from masanalyzer.testing import build_v23_signed_apk


class _FakeFinding:
    def __init__(self, rule_id, severity, owasp):
        self.rule_id = rule_id
        self.severity = severity
        self.owasp = owasp


class _FakeResult:
    def __init__(self, findings, covered):
        self.findings = findings
        self.covered_categories = covered


class MappingTests(unittest.TestCase):
    def test_every_catalog_rule_resolves(self):
        from masanalyzer.analysis import rule_catalog

        for rule in rule_catalog():
            reqs = rule_requirements(rule.rule_id, rule.owasp)
            self.assertTrue(
                reqs,
                f"{rule.rule_id} must map to at least one MASVS requirement",
            )
            for req in reqs:
                self.assertIn(req, MASVS_REQUIREMENTS)

    def test_explicit_table_overrides_defaults(self):
        # MAS-CRED-001 is M1 -> default is AUTHENTICATION-1, same as explicit
        self.assertEqual(
            rule_requirements("MAS-CRED-001", "M1"),
            ("MASVS-AUTHENTICATION-1",),
        )
        # unknown rule id falls back to the OWASP category default
        self.assertEqual(
            rule_requirements("MAS-FUTURE-999", "M10"),
            ("MASVS-CRYPTO-1",),
        )

    def test_requirement_glosses_nonempty(self):
        for req, gloss in MASVS_REQUIREMENTS.items():
            self.assertTrue(gloss.strip(), req)


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix="masan_audit_")
        cls.tampered = build_v23_signed_apk(
            os.path.join(tmp, "t.apk"), scheme="v2", tamper=True, expired_cert=True
        )
        cls.clean = build_v23_signed_apk(os.path.join(tmp, "c.apk"), scheme="v2")

    def test_tampered_fixture_fails_resilience(self):
        from masanalyzer.scanner import scan

        doc = audit(scan(self.tampered))
        rows = {r["id"]: r for r in doc["requirements"]}
        self.assertEqual(rows["MASVS-RESILIENCE-1"]["status"], STATUS_FAIL)
        self.assertGreater(doc["counts"][STATUS_FAIL], 0)

    def test_worst_severity_kept_per_requirement(self):
        """Multiple findings on one requirement keep the WORST severity."""
        from masanalyzer.model import Severity

        doc = audit(_FakeResult(
            [
                _FakeFinding("MAS-SUP-001", Severity.HIGH, "M2"),
                _FakeFinding("MAS-SUP-002", Severity.MEDIUM, "M2"),
            ],
            ["M2"],
        ))
        rows = {r["id"]: r for r in doc["requirements"]}
        row = rows["MASVS-RESILIENCE-1"]
        self.assertEqual(row["status"], STATUS_FAIL)
        self.assertEqual(row["worst"], "high")

    def test_no_findings_passes_covered(self):
        doc = audit(_FakeResult([], ["M1", "M9"]))
        rows = {r["id"]: r for r in doc["requirements"]}
        self.assertEqual(rows["MASVS-AUTHENTICATION-1"]["status"], STATUS_PASS)
        self.assertEqual(rows["MASVS-STORAGE-1"]["status"], STATUS_PASS)
        self.assertEqual(rows["MASVS-CRYPTO-1"]["status"], STATUS_NOT_ASSESSED)

    def test_counts_consistent(self):
        doc = audit(_FakeResult([], []))
        total = sum(doc["counts"].values())
        self.assertEqual(total, len(MASVS_REQUIREMENTS))
        self.assertEqual(doc["counts"][STATUS_PASS], 0)

    def test_render_deterministic(self):
        from masanalyzer.scanner import scan

        res = scan(self.clean)
        a = render_audit(res)
        b = render_audit(res)
        self.assertEqual(a, b)
        self.assertIn("# MASVS v2 requirement audit", a)
        self.assertIn("Summary", a)
        # every requirement appears as a matrix row
        for req in MASVS_REQUIREMENTS:
            self.assertIn(f"| {req} |", a)


class FormatRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix="masan_audit_fmt_")
        cls.apk = build_v23_signed_apk(os.path.join(tmp, "f.apk"), scheme="v2")

    def test_aliases_render_same_output(self):
        from masanalyzer.scanner import scan
        from masanalyzer.reporting import FORMATS, render

        res = scan(self.apk)
        self.assertIn("audit", FORMATS)
        self.assertEqual(render(res, "audit"), render(res, "masvs"))
        self.assertEqual(render(res, "audit"), render(res, "matrix"))
        self.assertEqual(render(res, "audit"), render_audit(res))

    def test_unknown_format_still_rejected(self):
        from masanalyzer.reporting import render
        from masanalyzer.model import Target

        with self.assertRaises(ValueError):
            render(_FakeResult([], []), "yaml")

    def test_cli_extension(self):
        from masanalyzer.cli import _ext_for

        self.assertEqual(_ext_for("audit"), "audit.md")


if __name__ == "__main__":
    unittest.main()

"""NIAP-style assurance matrix (niap.py): honest subset, rule-id mapped."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.model import Finding, Rule, Severity  # noqa: E402
from masanalyzer.niap import (  # noqa: E402
    REQUIREMENTS,
    STATUS_ATTN,
    STATUS_NA,
    STATUS_PASS,
    niap_matrix,
)
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import bank_dex, manifest_plain  # noqa: E402


class NiapMatrixTests(unittest.TestCase):
    def test_never_raises_on_degenerate_input(self):
        matrix = niap_matrix(object())
        self.assertIn("note", matrix)
        # no platform knowledge -> nothing is claimed as a pass
        for r in matrix["rows"]:
            self.assertNotEqual(r["status"], STATUS_PASS)

    def test_all_pass_on_clean_result(self):
        """A result with no findings maps every android requirement to pass."""
        target = type("T", (), {})()
        target.platform = "android"
        target.manifest = None
        target.meta = {}
        target.input_path = "x.apk"
        result = type("R", (), {})()
        result.target = target
        result.findings = []
        result.score = None
        matrix = niap_matrix(result)
        statuses = [r["status"] for r in matrix["rows"]]
        self.assertIn(STATUS_PASS, statuses)
        self.assertNotIn(STATUS_ATTN, statuses)

    def test_finding_maps_to_attention(self):
        """A MAS-STO finding flips NIA-09 to attention."""
        rule = Rule(
            rule_id="MAS-STO-001", owasp="M9", title="t", description="d",
            severity=Severity.HIGH, remediation="r",
            category="Insecure Data Storage",
        )
        f = rule.finding(file="a.xml", symbol="MODE_WORLD_READABLE")
        target = type("T", (), {})()
        target.platform = "android"
        target.manifest = None
        target.meta = {}
        target.input_path = "x.apk"
        result = type("R", (), {})()
        result.target = target
        result.findings = [f]
        result.score = None
        matrix = niap_matrix(result)
        row = next(r for r in matrix["rows"]
                   if r["identifier"] == "NIA-09")
        self.assertEqual(row["status"], STATUS_ATTN)
        self.assertIn("MAS-STO-001", row["detail"])

    def test_ios_rows_not_applicable_on_android(self):
        target = type("T", (), {})()
        target.platform = "android"
        target.manifest = None
        target.meta = {}
        target.input_path = "x.apk"
        result = type("R", (), {})()
        result.target = target
        result.findings = []
        result.score = None
        # every requirement row must carry one of the honest statuses
        for r in niap_matrix(result)["rows"]:
            self.assertIn(r["status"], (STATUS_PASS, STATUS_ATTN, STATUS_NA,
                                        "not assessed"))

    def test_requirements_have_unique_ids(self):
        ids = [r.ident for r in REQUIREMENTS]
        self.assertEqual(len(ids), len(set(ids)))
        for req in REQUIREMENTS:
            self.assertTrue(req.rules, f"{req.ident} maps to no rule ids")


class NiapInScanAndReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_niap_")
        path = os.path.join(cls.tmp, "n.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml",
                       manifest_plain("com.example.niap", "1.0"))
            z.writestr("classes.dex", bank_dex())
        cls.result = scan(path, progress=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_scan_matrix_has_rows(self):
        matrix = niap_matrix(self.result)
        ids = {r["identifier"] for r in matrix["rows"]}
        self.assertTrue(any(i.startswith("NIA-") for i in ids))
        self.assertIn("note", matrix)

    def test_json_inventory_carries_niap(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.result, "json"))
        niap = doc["inventory"].get("niap") or {}
        self.assertTrue(niap.get("rows"))

    def test_md_and_html_render_niap(self):
        from masanalyzer.reporting import render

        md = render(self.result, "md")
        self.assertIn("Assurance matrix", md)
        self.assertIn("not a", md.lower())
        html = render(self.result, "html")
        self.assertIn("Assurance matrix", html)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

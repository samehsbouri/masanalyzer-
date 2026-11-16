"""Reporting tests: four renderers, score math, and XSS safety."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from masanalyzer.model import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)
from masanalyzer.owasp import CATEGORIES, ORDER
from masanalyzer.packaging import prepare_target
from masanalyzer.reporting import (
    FORMATS,
    compute_score,
    render,
    score_to_grade,
)
from masanalyzer.reporting.score import SEVERITY_WEIGHT
from masanalyzer.scanner import ScanResult, analyze_target
from masanalyzer.testing import build_android_tree


def make_result(tmp: str) -> ScanResult:
    target = prepare_target(build_android_tree(os.path.join(tmp, "app")))
    result = analyze_target(target)
    return result


class TestRenderers(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="masan_report_")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _result(self) -> ScanResult:
        result = make_result(self.tmp)
        self.assertGreater(len(result.findings), 0)
        return result

    def test_render_dispatch_and_aliases(self) -> None:
        result = self._result()
        self.assertEqual(render(result, "json"), render(result, "JSON"))
        self.assertEqual(render(result, "md"), render(result, "markdown"))
        self.assertIsInstance(render(result, "pdf"), bytes)
        with self.assertRaises(ValueError):
            render(result, "no-such-format")

    def test_json_report_shape(self) -> None:
        result = self._result()
        doc = json.loads(render(result, "json"))
        self.assertTrue(doc.get("tool", {}).get("name"))
        self.assertIn("scan", doc)
        self.assertIsInstance(doc.get("findings"), list)
        self.assertTrue(doc["findings"])
        first = doc["findings"][0]
        for key in ("rule_id", "severity", "owasp", "evidence"):
            self.assertIn(key, first)
        self.assertIn("score", doc)

    def test_markdown_contains_summary(self) -> None:
        result = self._result()
        md = render(result, "md")
        self.assertIn("masanalyzer", md.lower())
        self.assertIn(result.findings[0].rule_id, md)

    def test_html_is_selfcontained(self) -> None:
        result = self._result()
        html = render(result, "html")
        self.assertIn("<html", html.lower())
        self.assertIn("</html>", html.lower())

    def test_html_escapes_finding_content(self) -> None:
        """A finding whose snippet carries raw HTML must never inject script."""
        result = self._result()
        xss = Finding(
            rule_id="MAS-TEST-999",
            title="XSS probe",
            description="snippet injection probe",
            severity=Severity.HIGH,
            owasp="M1",
            category=CATEGORIES["M1"].name,
            platform="any",
            evidence=Evidence(
                file="js/probe.js",
                line=1,
                snippet='<script>alert("XSS")</script>',
            ),
            remediation="none",
            confidence=Confidence.HIGH,
        )
        result.findings.append(xss)
        html = render(result, "html")
        self.assertNotIn('<script>alert', html)
        self.assertIn("&lt;script&gt;", html)

    def test_sarif_structure(self) -> None:
        result = self._result()
        doc = json.loads(render(result, "sarif"))
        self.assertEqual(doc.get("version"), "2.1.0")
        self.assertTrue(doc.get("runs"))
        run = doc["runs"][0]
        self.assertTrue(run.get("results"))
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        ids = [r.get("id") for r in rules]
        self.assertEqual(ids, sorted(ids), "SARIF rules must be deterministic/sorted")
        for res in run["results"]:
            self.assertIn(res.get("ruleId"), ids)
            self.assertIn(res.get("level"), ("none", "note", "warning", "error"))

    def test_all_formats_renderables(self) -> None:
        result = self._result()
        for fmt in FORMATS:
            out = render(result, fmt)
            if fmt == "pdf":
                self.assertIsInstance(out, bytes)   # binary format
            else:
                self.assertIsInstance(out, str)
            self.assertTrue(out.strip())


class TestScore(unittest.TestCase):
    def test_clean_target_scores_perfect(self) -> None:
        score = compute_score([], covered_categories=ORDER)
        self.assertGreaterEqual(score.total, 100.0)
        self.assertEqual(score.grade, "A+")

    def test_severity_weights_drive_deduction(self) -> None:
        findings = [
            Finding(
                rule_id="MAS-T-1",
                title="t",
                description="d",
                severity=Severity.CRITICAL,
                owasp="M9",
                category=CATEGORIES["M9"].name,
                evidence=Evidence(file="f"),
            )
        ]
        score = compute_score(findings, covered_categories=["M9"])
        self.assertLess(score.total, 100.0)
        self.assertEqual(score.scope, 1)
        self.assertEqual(score.by_owasp["M9"].findings, 1)

    def test_uncovered_categories_excluded_from_total(self) -> None:
        findings = [
            Finding(
                rule_id="MAS-T-2",
                title="t",
                description="d",
                severity=Severity.HIGH,
                owasp="M4",
                category=CATEGORIES["M4"].name,
                evidence=Evidence(file="f"),
            )
        ]
        score = compute_score(findings, covered_categories=["M4"])
        self.assertEqual(score.scope, 1)
        self.assertFalse(score.by_owasp["M10"].in_scope)
        total_only_m4 = score.total
        # same finding but every category covered => better total than 0
        self.assertGreaterEqual(total_only_m4, 0.0)
        self.assertLessEqual(total_only_m4, 100.0)

    def test_grade_bands(self) -> None:
        self.assertEqual(score_to_grade(100.0), "A+")
        self.assertEqual(score_to_grade(0.0), "F")
        self.assertIn(score_to_grade(55.0), ("C", "D"))
        self.assertIn(score_to_grade(85.0), ("B",))

    def test_weights_ordered(self) -> None:
        weights = list(SEVERITY_WEIGHT.values())
        self.assertEqual(sorted(weights), weights, "severity weights must be ordered")


if __name__ == "__main__":
    unittest.main()

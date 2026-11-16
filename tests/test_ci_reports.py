"""CI renderers: JUnit XML + GitLab Code Quality (masanalyzer.reporting)."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.testing import build_dex, manifest_axml


def _apk(tmp: str) -> str:
    """Fixture APK producing at least one medium+ and one low finding."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(
            "AndroidManifest.xml",
            manifest_axml("com.example.testapp", "1.0"),
        )
        z.writestr("classes.dex", build_dex(strings=(
            b"Lcom/example/testapp/MainActivity;",
            b"http://api.testapp.com/v1/login",   # cleartext -> MAS-NET-005
        )))
    path = os.path.join(tmp, "ci.apk")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


class CiReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_ci_")
        from masanalyzer.scanner import scan
        from masanalyzer.reporting import render

        cls.res = scan(_apk(cls.tmp))
        cls.junit = render(cls.res, "junit")
        cls.gitlab = json.loads(render(cls.res, "gitlab"))
        cls.sev_by_rule = {}
        for f in cls.res.findings:
            cls.sev_by_rule.setdefault(f.rule_id, str(f.severity))

    def test_junit_is_well_formed_xml(self):
        root = ET.fromstring(self.junit)
        self.assertEqual(root.tag, "testsuites")
        suites = root.findall("testsuite")
        self.assertEqual(len(suites), 1)

    def test_junit_counts_match_findings(self):
        root = ET.fromstring(self.junit)
        suite = root.find("testsuite")
        cases = suite.findall("testcase")
        self.assertEqual(len(cases), len(self.res.findings))
        self.assertEqual(
            int(suite.get("failures")),
            sum(1 for s in self.sev_by_rule.values()
                if s in ("medium", "high", "critical")),
        )
        self.assertEqual(int(root.get("tests")), len(self.res.findings))

    def test_junit_failing_and_skipped_split(self):
        root = ET.fromstring(self.junit)
        suite = root.find("testsuite")
        rule_of = {}
        for case in suite.findall("testcase"):
            rule_of[case.get("classname")] = case
        has_failure = False
        for rule_id, case in rule_of.items():
            sev = self.sev_by_rule.get(rule_id)
            if sev in ("medium", "high", "critical"):
                self.assertIsNotNone(
                    case.find("failure"),
                    f"{rule_id} ({sev}) must carry <failure>",
                )
                has_failure = True
            else:
                self.assertIsNotNone(
                    case.find("skipped"),
                    f"{rule_id} ({sev}) must be <skipped>",
                )
        self.assertTrue(has_failure, "fixture should include a failing finding")

    def test_junit_properties_carry_scan_context(self):
        root = ET.fromstring(self.junit)
        props = {
            p.get("name"): p.get("value")
            for p in root.find("testsuite").find("properties")
        }
        self.assertEqual(props["tool"], "masanalyzer")
        self.assertTrue(props["tool_version"])
        self.assertTrue(props["target"])
        self.assertTrue(props["grade"])

    def test_junit_deterministic(self):
        from masanalyzer.reporting import render

        self.assertEqual(self.junit, render(self.res, "junit"))
        self.assertEqual(render(self.res, "xunit"), self.junit)  # alias

    def test_gitlab_schema(self):
        self.assertIsInstance(self.gitlab, list)
        self.assertGreater(len(self.gitlab), 0)
        for issue in self.gitlab:
            for key in ("description", "check_name", "fingerprint",
                        "severity", "location"):
                self.assertIn(key, issue)
            self.assertIn(issue["severity"],
                          ("info", "minor", "major", "critical", "blocker",
                           "unknown"))
            self.assertIn("path", issue["location"])
            self.assertIn("lines", issue["location"])
            self.assertIn("begin", issue["location"]["lines"])

    def test_gitlab_severity_mapping(self):
        expected = {"info": "info", "low": "minor", "medium": "major",
                    "high": "critical", "critical": "blocker"}
        for issue in self.gitlab:
            sev = self.sev_by_rule[issue["check_name"]] \
                if issue["check_name"] in self.sev_by_rule else None
            if sev:
                self.assertEqual(issue["severity"], expected[sev])

    def test_gitlab_fingerprints_stable_and_unique_per_finding(self):
        from masanalyzer.reporting import render

        fps = [i["fingerprint"] for i in self.gitlab]
        self.assertEqual(fps, [i["fingerprint"] for i in
                               json.loads(render(self.res, "gitlab"))])
        self.assertEqual(len(fps), len(set(fps)))
        self.assertTrue(all(len(fp) == 64 for fp in fps))

    def test_registration(self):
        from masanalyzer.reporting import FORMATS, _ALIASES, _RENDERERS

        self.assertIn("junit", FORMATS)
        self.assertIn("gitlab", FORMATS)
        self.assertEqual(_ALIASES["xunit"], "junit")
        self.assertEqual(_ALIASES["codequality"], "gitlab")
        from masanalyzer.reporting import render_junit, render_gitlab
        self.assertIs(_RENDERERS["junit"], render_junit)
        self.assertIs(_RENDERERS["gitlab"], render_gitlab)

    def test_cli_writes_ci_files(self):
        from masanalyzer.cli import main

        tmp = tempfile.mkdtemp(prefix="masan_ci_cli_")
        out = os.path.join(tmp, "out")
        rc = main([_apk(tmp), "-o", out, "--format", "junit,gitlab", "-q"])
        self.assertEqual(rc, 0)
        jpath = os.path.join(out, "report.junit.xml")
        gpath = os.path.join(out, "report.codequality.json")
        self.assertTrue(os.path.exists(jpath), jpath)
        self.assertTrue(os.path.exists(gpath), gpath)
        ET.fromstring(open(jpath, encoding="utf-8").read())
        self.assertIsInstance(json.load(open(gpath, encoding="utf-8")), list)


if __name__ == "__main__":
    unittest.main()

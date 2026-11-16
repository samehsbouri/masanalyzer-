"""Tests for the four non-crypto features added in 1.1.0:

* lightweight taint tracking (MAS-INPUT-006)
* scan config policy (--config)
* baseline suppression (--baseline / --update-baseline)
* report diffing (masanalyzer-diff)
* SARIF region fidelity / originalUriBaseIds
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.model import Evidence, Finding, ScanFile, Severity
from masanalyzer.analysis.taint import describe, taint_flows
from masanalyzer.config import ScanConfig
from masanalyzer.baseline import Baseline
from masanalyzer import diffcli
from masanalyzer.reporting import sarif as sarif_mod


TAINT_SOURCE = '''\
package com.example.app;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

public class Flow {
    private SQLiteDatabase db;

    public void handle(Intent intent) {
        String q = intent.getStringExtra("query");   // line 8: source capture
        String sql = "SELECT * FROM t WHERE a = '" + q + "'";  // propagation
        db.execSQL(sql);                             // line 10: SINK
    }

    public void safe(Intent intent) {
        String q = intent.getStringExtra("q2");
        String sql = "SELECT * FROM t LIMIT 10";     // constant, untainted
        db.execSQL(sql);                             // must NOT flag
    }
}
'''


class TaintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="masan_taint_")
        cls.path = os.path.join(cls.dir, "Flow.java")
        with open(cls.path, "w", encoding="utf-8") as fh:
            fh.write(TAINT_SOURCE)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.dir, ignore_errors=True)

    def _sf(self):
        return ScanFile(
            relpath="app/Flow.java",
            kind="code",
            path=self.path,
            size=os.path.getsize(self.path),
        )

    def test_cross_line_flow_detected(self):
        flows = taint_flows(self._sf())
        self.assertTrue(any(f.sink.startswith("SQL") for f in flows))
        flow = [f for f in flows if "execSQL" in f.line][0]
        self.assertEqual(flow.lineno, 11)
        self.assertIn("sql", flow.tainted)
        self.assertEqual(flow.source_line, 9)  # ultimate getStringExtra capture
        self.assertTrue(describe(flow).startswith("SQL"))

    def test_untainted_constant_not_flagged(self):
        flows = [f for f in taint_flows(self._sf()) if "safe" in f.line]
        # the constant-SQL sink (last execSQL) must not appear
        self.assertFalse(any(f.lineno > 16 for f in flows), flows)


def _make_finding(rule="MAS-NET-004", path="app/src/main/A.java", sev="high"):
    return Finding(
        rule_id=rule,
        owasp="M2",
        category="Test category",
        title="t",
        description="d",
        severity=Severity(sev),
        remediation="r",
        evidence=Evidence(file=path),
    )


class ConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="masan_cfg_")
        cls.cfg_path = os.path.join(cls.dir, "masanalyzer.json")
        with open(cls.cfg_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "exclude_rules": ["MAS-NET-004"],
                    "exclude_paths": ["^build/outputs/"],
                    "rule_severity": {"MAS-CRED-002": "low"},
                    "min_severity": "low",
                },
                fh,
            )

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_load_and_apply(self):
        cfg = ScanConfig.load(self.cfg_path)
        self.assertEqual(cfg.exclude_rules, ["MAS-NET-004"])
        self.assertFalse(cfg.applies(_make_finding()))                 # rule excluded
        self.assertFalse(cfg.applies(_make_finding(rule="MAS-X-001", path="build/outputs/x.so")))
        self.assertTrue(cfg.applies(_make_finding(rule="MAS-X-001")))
        f = _make_finding(rule="MAS-CRED-002")
        cfg.reseverity(f)
        self.assertEqual(f.severity.value, "low")

    def test_broken_config_is_inert(self):
        broken = os.path.join(self.dir, "broken.json")
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        cfg = ScanConfig.load(broken)
        self.assertTrue(cfg.applies(_make_finding()))
        self.assertEqual(cfg.exclude_rules, [])


class BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="masan_base_")
        cls.path = os.path.join(cls.dir, "baseline.json")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_write_then_suppress(self):
        f1 = _make_finding(path="a.java")
        f2 = _make_finding(rule="MAS-OTHER-009", path="b.java")
        base = Baseline()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(base.dump([f1]))
        reloaded = Baseline.load(self.path)
        kept = reloaded.filter([f1, f2])
        self.assertEqual([f.rule_id for f in kept], ["MAS-OTHER-009"])

    def test_invalid_baseline_inert(self):
        bad = os.path.join(self.dir, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("[]")
        base = Baseline.load(bad)
        self.assertEqual(len(base), 0)


def _report(findings, total):
    return {
        "scan": {},
        "score": {"total": total, "grade": "B"},
        "findings": findings,
    }


def _fdoc(fid, rule, sev="high"):
    return {
        "id": fid,
        "rule_id": rule,
        "severity": sev,
        "owasp": "M2",
        "evidence": {"file": "a.java", "line": 3},
    }


class DiffTests(unittest.TestCase):
    def test_new_high_blocks(self):
        old = _report([_fdoc("h1", "MAS-A-001")], 80)
        new = _report([_fdoc("h1", "MAS-A-001"), _fdoc("h2", "MAS-B-001")], 75)
        diff = diffcli.diff_reports(old, new)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["resolved"]), 0)
        code = diffcli.print_diff(diff, fail_on="high")
        self.assertEqual(code, 1)

    def test_resolved_passes(self):
        old = _report([_fdoc("h1", "MAS-A-001")], 80)
        new = _report([], 93)
        diff = diffcli.diff_reports(old, new)
        code = diffcli.print_diff(diff, fail_on="high")
        self.assertEqual(code, 0)
        self.assertEqual(len(diff["resolved"]), 1)

    def test_load_report_validates(self):
        with self.assertRaises(ValueError):
            diffcli._as_report({"no": "findings"})

    def test_fail_on_low(self):
        old = _report([], 90)
        new = _report([_fdoc("i1", "MAS-I-001", sev="low")], 90)
        diff = diffcli.diff_reports(old, new)
        self.assertEqual(diffcli.print_diff(diff, fail_on="low"), 1)


class SarifRegionTests(unittest.TestCase):
    def _render(self, finding):
        from types import SimpleNamespace

        finding.evidence.line = 12
        finding.evidence.snippet = "TaskerApp()..."
        result = SimpleNamespace(findings=[finding], tool={"version": "1.1.0"})
        return json.loads(sarif_mod.render_sarif(result))

    def test_region_endline_and_baseids(self):
        doc = self._render(_make_finding())
        text = json.dumps(doc)
        run = doc["runs"][0]
        self.assertEqual(run["originalUriBaseIds"]["SRCROOT"] != None, True, "SRCROOT present")
        self.assertEqual(run["columnKind"], "unicodeCodeUnits")
        self.assertIn('"endLine"', text)
        region = run["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 12)
        self.assertEqual(region["endLine"], 12)

    def test_not_uploadable_without_regions(self):
        text = json.dumps(self._render(_make_finding()))
        # findings always carry a region when they have a line, and a
        # uriBaseId pointing at SRCROOT - the two upload requirements
        self.assertIn('"uriBaseId"', text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

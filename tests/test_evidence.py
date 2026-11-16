"""Report hygiene contract: no duplicate findings anywhere, and every
finding carries - and every renderer prints - the exact matched code or
the detection basis ("how did you find it")."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.model import FindingCollector  # noqa: E402
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import (  # noqa: E402
    build_android_tree,
    build_apk,
    build_ipa,
    build_signed_apk,
)


class ReportHygiene(unittest.TestCase):
    """One scan, every renderer, hard evidence-quality assertions."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_evidence_")
        cls.tree = build_android_tree(os.path.join(cls.tmp, "tree"))
        cls.apk = build_apk(os.path.join(cls.tmp, "app.apk"))
        cls.ipa = build_ipa(os.path.join(cls.tmp, "app.ipa"))
        cls.tampered = build_signed_apk(
            os.path.join(cls.tmp, "tampered.apk"), tamper=True
        )
        cls.results = [scan(p) for p in
                       (cls.tree, cls.apk, cls.ipa, cls.tampered)]
        # markdown/html render one finding per block, so a duplicate
        # identity would show up twice - assert at the JSON layer first
        import json

        from masanalyzer.reporting import render

        cls.reports = [dict(
            json_doc=json.loads(render(r, "json")),
            md=render(r, "md"),
            html=render(r, "html"),
            junit=render(r, "junit"),
        ) for r in cls.results]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- no duplication ----------------------------------------------------
    def test_no_duplicate_identities_in_report(self):
        for rep in self.reports:
            ids = [f["id"] for f in rep["json_doc"]["findings"]]
            self.assertEqual(len(ids), len(set(ids)),
                             "identical finding identity rendered twice")

    def test_collector_dedupes_same_finding(self):
        from masanalyzer.model import Finding, Severity

        collector = FindingCollector()
        f = Finding(
            rule_id="MAS-X-001", title="t", description="d",
            severity=Severity.LOW, owasp="M1", category="c",
        )
        self.assertIsNotNone(collector.add(f))
        self.assertIsNone(collector.add(f), "second identical add is a dup")
        self.assertEqual(len(collector.findings), 1)

    def test_markdown_top_list_is_capped_not_a_duplicate(self):
        for rep in self.reports:
            total = len(rep["json_doc"]["findings"])
            md = rep["md"]
            if total <= 10:
                continue
            top = md.split("## Top findings", 1)[-1].split(
                "Full evidence", 1)[0]
            numbered = [l for l in top.splitlines() if l[:3] in
                        {f"{i}." for i in range(1, 100)}]
            self.assertLessEqual(
                len(numbered), 10,
                "top-findings list must stay a top-10, not a re-render "
                "of every detailed block")

    def test_junit_testcase_names_unique(self):
        import re

        for rep in self.reports:
            names = re.findall(r'<testcase name="([^"]+)"', rep["junit"])
            self.assertEqual(len(names), len(set(names)),
                             "junit testcase names must be unique")

    # -- evidence present + rendered ----------------------------------------
    def test_every_finding_carries_detection_basis(self):
        for rep in self.reports:
            for f in rep["json_doc"]["findings"]:
                ev = f.get("evidence", {})
                basis = [
                    ev.get("snippet"), ev.get("symbol"),
                    ev.get("offset"), ev.get("note"),
                ]
                self.assertTrue(
                    any(b for b in basis),
                    f"{f['rule_id']} has no snippet/symbol/offset/note - "
                    f"report cannot say how it was found: {ev}",
                )

    def test_markdown_prints_evidence_for_every_finding(self):
        for rep in self.reports:
            md = rep["md"]
            for f in rep["json_doc"]["findings"]:
                loc = f["evidence"]
                self.assertIn(
                    loc.get("file", ""), md,
                    f"{f['rule_id']}: file must appear in markdown")
                snippet = loc.get("snippet")
                if snippet:
                    self.assertIn(
                        snippet.splitlines()[0].strip()[:60],
                        md.replace("`", ""),
                        f"{f['rule_id']}: exact code must be printed")
                if loc.get("symbol"):
                    self.assertIn(
                        loc["symbol"], md,
                        f"{f['rule_id']}: matched component must be printed")
                if loc.get("note"):
                    self.assertIn(
                        loc["note"], md,
                        f"{f['rule_id']}: detection note must be printed")

    def test_html_prints_symbol_snippet_and_note(self):
        for rep in self.reports:
            html = (rep["html"]
                    .replace("&quot;", '"')
                    .replace("&#x27;", "'")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">"))
            for f in rep["json_doc"]["findings"]:
                ev = f.get("evidence", {})
                if ev.get("symbol"):
                    self.assertIn(
                        ev["symbol"], html,
                        f"{f['rule_id']}: matched component missing in HTML")
                if ev.get("snippet"):
                    self.assertIn(
                        ev["snippet"].strip()[:40],
                        html.replace("&quot;", '"'),
                        f"{f['rule_id']}: exact code missing in HTML")
                if ev.get("note"):
                    self.assertIn(
                        ev["note"], html,
                        f"{f['rule_id']}: detection note missing in HTML")

    def test_tampered_apk_names_the_broken_entry(self):
        rep = self.reports[3]
        sup8 = [f for f in rep["json_doc"]["findings"]
                if f["rule_id"] == "MAS-SUP-008"]
        self.assertTrue(sup8)
        ev = sup8[0]["evidence"]
        self.assertTrue(ev.get("symbol"), "must name the tampered entry")
        self.assertIn("digest mismatch", ev.get("note", ""))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

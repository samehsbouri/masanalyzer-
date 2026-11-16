"""masanalyzer's differentiators, locked in as contract tests:

1. assurance tiers - every finding is graded by its verification method
   (verified / structural / heuristic) and the tier travels into every
   report format;
2. attack-surface synthesis - manifest entry points cross-referenced with
   the findings attached to each component, embedded in the reports.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer import assurance  # noqa: E402
from masanalyzer.packaging import prepare_target  # noqa: E402
from masanalyzer.reporting import render  # noqa: E402
from masanalyzer.scanner import analyze_target, scan  # noqa: E402
from masanalyzer.testing import (  # noqa: E402
    build_android_tree,
    build_signed_apk,
    manifest_plain,
)

TIERS = {"verified", "structural", "heuristic"}


class AssuranceTiers(unittest.TestCase):
    """Every finding is graded; verified/structural/heuristic are honest."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_unique_")
        tree = build_android_tree(os.path.join(cls.tmp, "tree"))
        cls.tree_result = scan(tree)
        cls.bad_apk = build_signed_apk(
            os.path.join(cls.tmp, "bad.apk"), tamper=True)
        cls.tampered_result = scan(cls.bad_apk)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _find(self, result, rule_id):
        return [f for f in result.findings if f.rule_id == rule_id]

    def test_every_finding_is_graded(self):
        for f in self.tree_result.findings + self.tampered_result.findings:
            self.assertIn(
                f.assurance, TIERS,
                f"{f.rule_id} must carry an assurance tier")

    def test_signature_verification_is_verified(self):
        hits = self._find(self.tampered_result, "MAS-SUP-008")
        self.assertTrue(hits, "tampered fixture must raise MAS-SUP-008")
        self.assertEqual(hits[0].assurance, "verified")

    def test_manifest_flag_is_structural(self):
        hits = self._find(self.tree_result, "MAS-BIN-001")
        self.assertTrue(hits, "fixture manifest is debuggable")
        self.assertEqual(hits[0].assurance, "structural")

    def test_pattern_match_is_heuristic(self):
        hits = self._find(self.tree_result, "MAS-CRED-002")
        self.assertTrue(hits, "fixture carries an api-key literal")
        self.assertEqual(hits[0].assurance, "heuristic")

    def test_unknown_rule_defaults_to_heuristic(self):
        self.assertEqual(assurance.tier_for("MAS-FAKE-999"), "heuristic")

    def test_annotate_stamps_everything(self):
        n = assurance.annotate(self.tree_result.findings)
        self.assertEqual(n, len(self.tree_result.findings))

    def test_json_summary_counts_tiers(self):
        doc = json.loads(render(self.tree_result, "json"))
        by_assurance = doc["summary"].get("by_assurance")
        self.assertIsInstance(by_assurance, dict)
        self.assertEqual(sum(by_assurance.values()), len(doc["findings"]))
        for f in doc["findings"]:
            self.assertIn(f.get("assurance"), TIERS)

    def test_markdown_carries_assurance_badge(self):
        md = render(self.tampered_result, "md")
        self.assertIn("Assurance: verified", md)

    def test_html_carries_assurance_chip(self):
        html = render(self.tampered_result, "html")
        self.assertIn("assurance:", html)
        self.assertIn("verified", html)

    def test_csv_has_assurance_column(self):
        import csv as _csv
        import io as _io

        from masanalyzer.reporting.csv_report import COLUMNS

        self.assertIn("assurance", COLUMNS)
        rows = list(_csv.reader(_io.StringIO(render(self.tree_result, "csv"))))
        self.assertEqual(rows[0], COLUMNS)
        # every data row has the same arity as the header
        for row in rows[1:]:
            self.assertEqual(len(row), len(COLUMNS))


class AttackSurface(unittest.TestCase):
    """Entry points parsed from the manifest, cross-referenced w/ findings."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_surface_")
        cls.result = scan(build_android_tree(os.path.join(cls.tmp, "tree")))
        surface = cls.result.target.meta.get("attack_surface") or {}
        cls.surface = surface
        cls.by_name = {
            e["component"]: e for e in surface.get("entry_points", [])
        }

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_surface_built(self):
        self.assertTrue(self.surface, "surface must be synthesized")

    def test_exported_components_listed(self):
        # fixture manifest exports LoginActivity + CredentialsProvider
        self.assertIn("com.example.insecurebank.LoginActivity", self.by_name)
        self.assertIn(
            "com.example.insecurebank.CredentialsProvider", self.by_name)
        kinds = {n: e["kind"] for n, e in self.by_name.items()}
        self.assertEqual(kinds["com.example.insecurebank.CredentialsProvider"],
                         "provider")

    def test_findings_attached_by_component(self):
        prov = self.by_name["com.example.insecurebank.CredentialsProvider"]
        self.assertGreaterEqual(prov["finding_count"], 1)
        identities = set(prov["findings"])
        attached = {f.identity: f for f in self.result.findings}
        rules = {attached[i].rule_id for i in identities if i in attached}
        self.assertIn("MAS-AUTH-001", rules,
                      "exported provider finding must attach to its door")

    def test_worst_severity_reflects_attached_findings(self):
        prov = self.by_name["com.example.insecurebank.CredentialsProvider"]
        self.assertEqual(prov["worst_severity"], "high")  # MAS-AUTH-001
        act = self.by_name["com.example.insecurebank.LoginActivity"]
        self.assertEqual(act["worst_severity"], "medium")  # MAS-AUTH-002

    def test_summary_counts(self):
        s = self.surface["summary"]
        self.assertEqual(s["external_entry_points"], len(self.by_name))
        self.assertEqual(
            s["surface_findings"],
            sum(e["finding_count"] for e in self.by_name.values()))
        self.assertGreaterEqual(s["unprotected_entry_points"], 2)

    def test_reports_embed_the_surface(self):
        doc = json.loads(render(self.result, "json"))
        self.assertIn("attack_surface", doc["inventory"])
        self.assertEqual(
            len(doc["inventory"]["attack_surface"]["entry_points"]),
            len(self.by_name))
        md = render(self.result, "md")
        self.assertIn("## Attack surface", md)
        self.assertIn("CredentialsProvider", md)
        html = render(self.result, "html")
        self.assertIn("Attack surface", html)


class DeepLinkSurface(unittest.TestCase):
    """Browsable deep links and permission guards reach the surface."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_dl_")
        base = os.path.join(cls.tmp, "app")
        man_dir = os.path.join(base, "app", "src", "main")
        os.makedirs(man_dir, exist_ok=True)
        body = (
            '    <activity android:name=".OpenActivity" '
            'android:exported="true">\n'
            '      <intent-filter>\n'
            '        <action android:name="android.intent.action.VIEW"/>\n'
            '        <category android:name='
            '"android.intent.category.DEFAULT"/>\n'
            '        <category android:name='
            '"android.intent.category.BROWSABLE"/>\n'
            '        <data android:scheme="myapp" android:host="sec.example" '
            'android:pathPrefix="/open"/>\n'
            '      </intent-filter>\n'
            '    </activity>\n'
            '    <activity android:name=".GuardedActivity" '
            'android:exported="true" '
            'android:permission="com.example.CUSTOM"/>\n'
        )
        with open(os.path.join(man_dir, "AndroidManifest.xml"), "wb") as fh:
            fh.write(manifest_plain(body=body))
        target = prepare_target(base)
        cls.result = analyze_target(target)
        cls.surface = target.meta.get("attack_surface") or {}
        cls.by_name = {
            e["component"]: e for e in cls.surface.get("entry_points", [])
        }

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_browsable_link_parsed(self):
        entry = self.by_name.get("com.example.insecurebank.OpenActivity")
        self.assertIsNotNone(entry)
        links = entry["browsable_links"]
        self.assertTrue(links, "browsable deep link must be listed")
        self.assertEqual(links[0]["scheme"], "myapp")
        self.assertEqual(links[0]["host"], "sec.example")
        self.assertEqual(links[0]["path_prefix"], "/open")

    def test_browsable_host_in_summary(self):
        s = self.surface["summary"]
        self.assertIn("sec.example", s["browsable_hosts"])
        self.assertGreaterEqual(s["browsable_deep_links"], 1)

    def test_permission_guard_recorded(self):
        entry = self.by_name.get("com.example.insecurebank.GuardedActivity")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["permission"], "com.example.CUSTOM")

    def test_deep_link_finding_attached(self):
        entry = self.by_name.get("com.example.insecurebank.OpenActivity")
        identities = set(entry["findings"])
        attached = {f.identity: f for f in self.result.findings}
        rules = {attached[i].rule_id for i in identities if i in attached}
        self.assertIn("MAS-AUTH-006", rules,
                      "browsable deep-link finding must attach to its door")

    def test_fix_first_why_explains_the_door(self):
        queue = {
            e["component"]: e for e in self.surface["summary"]["fix_first"]
        }
        open_why = queue["com.example.insecurebank.OpenActivity"]["why"]
        self.assertIn("no permission guard", open_why)
        self.assertTrue(
            any(w.startswith("1 browsable deep link") for w in open_why),
            open_why)
        guarded_why = queue["com.example.insecurebank.GuardedActivity"]["why"]
        self.assertNotIn("no permission guard", guarded_why)


class FixFirstQueue(unittest.TestCase):
    """The exposure-ranked remediation order (surface.summary.fix_first)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_fixfirst_")
        cls.result = scan(build_android_tree(os.path.join(cls.tmp, "tree")))
        cls.surface = cls.result.target.meta.get("attack_surface") or {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _entry(self, name):
        return {e["component"]: e for e in self.surface["entry_points"]}[name]

    def test_queue_present_and_ranked(self):
        queue = self.surface["summary"]["fix_first"]
        self.assertTrue(queue, "fix-first queue must be synthesized")
        scores = [e["score"] for e in queue]
        self.assertEqual(scores, sorted(scores, reverse=True),
                         "queue must be ordered worst-exposure first")
        self.assertEqual(
            {e["component"] for e in queue},
            {e["component"] for e in self.surface["entry_points"]},
            "every door must be queued exactly once")

    def test_score_matches_transparent_formula(self):
        by_id = {f.identity: f for f in self.result.findings}
        rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        for e in self.surface["entry_points"]:
            verified = sum(
                1 for i in e["findings"]
                if i in by_id and by_id[i].assurance == "verified")
            expected = (
                rank.get(e["worst_severity"], 0)
                + 2 * verified
                + (1 if not e["permission"] else 0)
                + min(len(e["browsable_links"]), 3)
            )
            self.assertEqual(e["fix_score"], expected,
                             f"score for {e['component']}")
            why = e["fix_why"]
            self.assertIn(f"worst: {e['worst_severity']}", why)
            if verified:
                self.assertIn(f"{verified} verified finding", why)

    def test_worst_door_ranks_first_with_rationale(self):
        prov = self._entry("com.example.insecurebank.CredentialsProvider")
        queue = self.surface["summary"]["fix_first"]
        top = queue[0]
        self.assertEqual(top["component"], prov["component"])
        self.assertIn("worst: high", top["why"])

    def test_renderers_carry_the_queue(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.result, "json"))
        self.assertIn(
            "fix_first",
            doc["inventory"]["attack_surface"]["summary"])
        md = render(self.result, "md")
        self.assertIn("### Fix first", md)
        self.assertIn("CredentialsProvider", md)
        html = render(self.result, "html")
        self.assertIn("Fix first", html)

    def test_score_is_deterministic(self):
        first = self.surface["summary"]["fix_first"]
        again = scan(
            build_android_tree(os.path.join(self.tmp, "tree2"))
        ).target.meta["attack_surface"]["summary"]["fix_first"]
        self.assertEqual(first, again)


class FixFirstFormula(unittest.TestCase):
    """Unit checks on the scoring helper (verified facts weigh double)."""

    @staticmethod
    def _fid(i, assurance):
        class _F:
            pass

        f = _F()
        f.identity = i
        f.assurance = assurance
        return f

    def test_verified_facts_weigh_double(self):
        from masanalyzer.surface import _fix_first

        entry = {
            "worst_severity": "medium",
            "findings": ["a", "b"],
            "permission": "com.example.GUARD",
            "browsable_links": [],
        }
        by_id = {
            "a": self._fid("a", "verified"),
            "b": self._fid("b", "heuristic"),
        }
        score, why = _fix_first(entry, by_id)
        self.assertEqual(score, 3 + 2 * 1)
        self.assertIn("1 verified finding", why)
        self.assertNotIn("no permission guard", why)
        self.assertIn("worst: medium", why)

    def test_unguarded_plus_links_cap(self):
        from masanalyzer.surface import _fix_first

        entry = {
            "worst_severity": "",
            "findings": [],
            "permission": "",
            "browsable_links": [{}, {}, {}, {}],   # 4 links -> capped at 3
        }
        score, why = _fix_first(entry, {})
        self.assertEqual(score, 1 + 3)
        self.assertIn("no permission guard", why)
        self.assertIn("4 browsable deep links", why)
        self.assertNotIn("worst:", why)


class WebViewSurface(unittest.TestCase):
    """JS-bridge files are enumerated as part of the surface."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_wv_")
        tree = build_android_tree(os.path.join(cls.tmp, "tree"))
        java_dir = os.path.join(
            tree, "app", "src", "main", "java", "com", "example", "insecurebank")
        os.makedirs(java_dir, exist_ok=True)
        with open(os.path.join(java_dir, "Bridge.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example.insecurebank;\n"
                "import android.webkit.WebSettings;\n"
                "public class Bridge {\n"
                "  void cfg(WebSettings s) {\n"
                "    s.setJavaScriptEnabled(true);\n"
                "  }\n"
                "}\n")
        cls.result = scan(tree)
        surface = cls.result.target.meta.get("attack_surface") or {}
        cls.summary = surface.get("summary") or {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_webview_file_listed(self):
        files = self.summary.get("webview_integration_files") or []
        self.assertTrue(
            any(f.endswith("Bridge.java") for f in files),
            f"Bridge.java must be listed, got {files}")

    def test_webview_rule_still_fires(self):
        rules = {f.rule_id for f in self.result.findings}
        self.assertIn("MAS-MIS-005", rules)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

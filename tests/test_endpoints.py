"""Endpoint/URL inventory (masanalyzer.endpoints) + M5 inventory rules."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.endpoints import (
    build_inventory,
    harvest_strings,
    host_is_trivial,
)
from masanalyzer.model import Target
from masanalyzer.testing import build_dex, manifest_axml


def _target_with_pool(package: str = "com.examplecorp-team.app") -> Target:
    t = Target(input_path="synthetic", platform="android", work_dir=".", name="x")
    t.package = package
    t.string_pool.extend([
        ("classes.dex", "https://api.examplecorp-team.com/v1/login"),
        ("classes.dex", "http://10.0.2.2:8080/health"),        # emulator loopback-ish
        ("classes.dex", "http://127.0.0.1/debug"),
        ("classes.dex", "https://analytics.google-analytics.com/collect"),
        ("classes.dex", "https://sync.examplecorp-team.com/sync"),
        ("resources.arsc", "https://vendor.appsflyer.com/install"),
        ("assets/db.sqlite", "10.7.3.9"),
        ("string_pool", "nothing relevant in this string"),
    ])
    return t


class ClassifyTests(unittest.TestCase):
    """Classification happens on hosts discovered by harvest: use URL forms."""

    def _cls(self, raw, package="com.examplecorp-team.app"):
        t = Target(input_path="s", platform="android", work_dir=".", name="x")
        t.package = package
        t.string_pool.append(("x", raw))
        inv = build_inventory(t)
        return inv["rows"][0]["classification"] if inv["rows"] else ""

    def test_public_host(self):
        self.assertEqual(self._cls("https://api.somecorp.io/x"), "public")

    def test_first_party_guess_matches_package_token(self):
        self.assertEqual(
            self._cls("https://api.examplecorp-team.com/x"), "first_party"
        )

    def test_tracker_suffix(self):
        self.assertEqual(
            self._cls("https://analytics.google-analytics.com/collect"), "tracker"
        )
        self.assertEqual(self._cls("https://sub.appsflyer.com/install"), "tracker")

    def test_private_and_local(self):
        self.assertEqual(self._cls("192.168.1.10"), "private")
        self.assertEqual(self._cls("10.0.2.2"), "private")
        self.assertEqual(self._cls("http://localhost/debug"), "local")
        self.assertEqual(self._cls("https://db.corp.internal/x"), "local")


def _target_only(host: str) -> Target:
    t = Target(input_path="s", platform="android", work_dir=".", name="x")
    t.package = "com.examplecorp-team.app"
    t.string_pool.append(("x", host))
    return t


class BuilderTests(unittest.TestCase):
    def test_inventory_structure_and_counts(self):
        target = _target_with_pool()
        inv = build_inventory(target)
        self.assertEqual(inv["total"], len(inv["rows"]))
        self.assertEqual(inv["rows"][0]["classification"], "tracker")
        # counts must add up
        self.assertEqual(
            inv["counts"]["tracker"]
            + inv["counts"]["private"]
            + inv["counts"]["local"]
            + inv["counts"]["first_party"]
            + inv["counts"]["public"],
            inv["total"],
        )
        self.assertEqual(inv["counts"]["cleartext"], 2)
        # rows are JSON-ready dicts
        for row in inv["rows"]:
            for key in ("host", "kind", "scheme", "classification",
                        "cleartext", "sources", "occurrences"):
                self.assertIn(key, row)

    def test_cleartext_flag_and_port(self):
        target = _target_with_pool()
        inv = build_inventory(target)
        by_host = {r["host"]: r for r in inv["rows"]}
        self.assertTrue(by_host["10.0.2.2"]["cleartext"])
        self.assertEqual(by_host["10.0.2.2"]["port"], 8080)
        self.assertFalse(by_host["api.examplecorp-team.com"]["cleartext"])

    def test_trivial_hosts_dropped(self):
        target = _target_with_pool()
        target.string_pool.append(
            ("classes.dex", "http://schemas.android.com/apk/res/android")
        )
        target.string_pool.append(("classes.dex", "https://www.w3.org/2000/svg"))
        inv = build_inventory(target)
        hosts = {r["host"] for r in inv["rows"]}
        self.assertNotIn("schemas.android.com", hosts)
        self.assertNotIn("www.w3.org", hosts)

    def test_rfc2606_example_tld_urls_counted(self):
        """URLs on the reserved ``example`` TLD must not be filtered away."""
        target = _target_with_pool()
        target.string_pool.append(
            ("assets/config.properties", "alt=http://mirror.insecurebank.example")
        )
        inv = build_inventory(target)
        hosts = {r["host"] for r in inv["rows"]}
        self.assertIn("mirror.insecurebank.example", hosts)
        row = next(r for r in inv["rows"]
                   if r["host"] == "mirror.insecurebank.example")
        self.assertTrue(row["cleartext"])

    def test_dedup_and_occurrence_count(self):
        t = _target_only("https://host.examplecorp-team.com/path1")
        t.string_pool.extend([
            ("a.dex", "https://host.examplecorp-team.com/path2"),
            ("b.dex", "https://host.examplecorp-team.com/path3"),
        ])
        inv = build_inventory(t)
        self.assertEqual(len(inv["rows"]), 1)
        self.assertGreaterEqual(inv["rows"][0]["occurrences"], 3)
        self.assertIn("a.dex", inv["rows"][0]["sources"])


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_ep_")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("AndroidManifest.xml", manifest_axml("com.example.testapp", "1.0"))
            z.writestr("classes.dex", build_dex(strings=(
                b"https://api.testapp.com/v1/login?x=1",
                b"http://10.7.3.9:8080/health",
                b"https://analytics.google-analytics.com/collect",
            )))
        cls.apk = os.path.join(cls.tmp, "urls.apk")
        with open(cls.apk, "wb") as fh:
            fh.write(buf.getvalue())
        from masanalyzer.scanner import scan

        cls.res = scan(cls.apk)

    def test_inventory_in_scan_meta(self):
        inv = self.res.target.meta.get("endpoints")
        self.assertIsNotNone(inv)
        cls_ = {r["host"]: r["classification"] for r in inv["rows"]}
        self.assertEqual(cls_["analytics.google-analytics.com"], "tracker")
        self.assertEqual(cls_["10.7.3.9"], "private")
        self.assertEqual(cls_["api.testapp.com"], "first_party")

    def test_inventory_rules_fire(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("MAS-NET-008", ids)      # tracker endpoint
        self.assertIn("MAS-NET-009", ids)      # private endpoint
        notes = [f.evidence.symbol for f in self.res.findings
                 if f.rule_id == "MAS-NET-009"]
        self.assertIn("10.7.3.9", notes)

    def test_json_report_includes_inventory(self):
        from masanalyzer.reporting import render
        import json as j

        doc = j.loads(render(self.res, "json"))
        self.assertIn("inventory", doc)
        ep = doc["inventory"]["endpoints"]
        self.assertGreater(ep["total"], 0)
        self.assertIn("counts", ep)

    def test_rule_count_grew(self):
        from masanalyzer.analysis import rule_catalog

        ids = {r.rule_id for r in rule_catalog()}
        self.assertIn("MAS-NET-008", ids)
        self.assertIn("MAS-NET-009", ids)


if __name__ == "__main__":
    unittest.main()

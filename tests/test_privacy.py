"""Excess-access privacy matrix (analysis.privacy) + m06/m08 rules."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.manifest import Manifest
from masanalyzer.model import Target
from masanalyzer.testing import build_dex, manifest_plain


def _manifest(*perms: str, special: tuple = ()) -> Manifest:
    return Manifest(
        package="com.example.testapp",
        uses_permissions=[
            "android.permission.INTERNET",
            *perms,
            *special,
        ],
    )


def _target(*dex_strings: bytes) -> Target:
    import types as _t
    from masanalyzer.android.dex import parse_dex

    t = Target(input_path="synthetic", platform="android", work_dir=".", name="x")
    t.manifest = _manifest(
        "android.permission.CAMERA",
        "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO",   # never corroborated below
    )
    strings = list(dex_strings)
    # every L...; descriptor becomes a class type so dex.classes carries it
    idx = tuple(
        i for i, s in enumerate(strings)
        if s.startswith(b"L") and s.endswith(b";")
    )
    blob = build_dex(
        strings=strings, types=idx, classes=tuple(range(len(idx)))
    )
    t.meta["dex"] = [{
        "classes": list(parse_dex(blob).classes),
        "methods": [],
    }]
    t.string_pool.extend(("classes.dex", s.decode()) for s in strings)
    return t


class MatrixTests(unittest.TestCase):
    def test_corroborated_vs_excess(self):
        from masanalyzer.analysis.privacy import build_privacy_matrix

        t = _target(
            b"Lcom/example/testapp/MainActivity;",
            b"Landroid/hardware/Camera;",        # camera API in dex
            b"content://sms/inbox",              # sms reach in a string
        )
        matrix = build_privacy_matrix(t)
        rows = {r["permission"]: r for r in matrix["rows"]}
        self.assertTrue(rows["android.permission.CAMERA"]["corroborated"])
        self.assertEqual(
            rows["android.permission.CAMERA"]["observed"][0]["surface"],
            "dex-classes",
        )
        self.assertTrue(rows["android.permission.SEND_SMS"]["corroborated"])
        self.assertIn(
            "string-pool",
            rows["android.permission.SEND_SMS"]["observed"][0]["surface"],
        )
        self.assertTrue(rows["android.permission.RECORD_AUDIO"]["excess"])
        self.assertFalse(matrix["rows"][0]["special"])
        # INTERNET is not dangerous: no row for it
        self.assertNotIn("android.permission.INTERNET", rows)
        # counts summarize the split
        self.assertEqual(matrix["counts"]["excess"], 1)
        self.assertEqual(matrix["counts"]["corroborated"], 2)

    def test_special_access_flagged(self):
        from masanalyzer.analysis.privacy import build_privacy_matrix

        t = Target(input_path="synthetic", platform="android", work_dir=".",
                   name="x")
        t.manifest = _manifest(
            "android.permission.REQUEST_INSTALL_PACKAGES",
            special=("android.permission.SYSTEM_ALERT_WINDOW",),
        )
        matrix = build_privacy_matrix(t)
        self.assertTrue(all(r["excess"] for r in matrix["rows"]))
        self.assertTrue(all(r["special"] for r in matrix["rows"]))
        self.assertEqual(matrix["counts"]["special"], 2)

    def test_no_manifest_no_matrix(self):
        from masanalyzer.analysis.privacy import build_privacy_matrix

        t = Target(input_path="synthetic", platform="android", work_dir=".",
                   name="x")
        self.assertEqual(build_privacy_matrix(t), {})


class FindingTests(unittest.TestCase):
    def _result(self, t: Target, rule_modules=(("m06", 1),)):
        from masanalyzer.scanner import analyze_target

        return analyze_target(t)

    def test_excess_sensitive_rule_fires(self):
        from masanalyzer.analysis.privacy import build_privacy_matrix

        t = _target(
            b"Lcom/example/testapp/MainActivity;",
            b"Landroid/hardware/Camera;",
        )
        build_privacy_matrix(t)
        res = self._result(t)
        excess = [f for f in res.findings if f.rule_id == "MAS-PRI-007"]
        self.assertEqual(
            {f.evidence.symbol for f in excess},
            {"android.permission.RECORD_AUDIO",
             "android.permission.SEND_SMS"},   # no sms marker in the fixture
        )
        self.assertEqual(excess[0].severity.value, "medium")
        # corroborated camera never lands in an excess finding
        self.assertFalse(
            any("CAMERA" in (f.evidence.symbol or "")
                for f in res.findings
                if f.rule_id.startswith("MAS-PRI-00"))
        )

    def test_excess_low_band_rule(self):
        from masanalyzer.analysis.privacy import build_privacy_matrix

        t = _target(b"Lcom/example/testapp/MainActivity;")
        t.manifest = _manifest(
            "android.permission.READ_MEDIA_IMAGES",   # non-sensitive bucket
        )
        build_privacy_matrix(t)
        res = self._result(t)
        low = [f for f in res.findings if f.rule_id == "MAS-PRI-008"]
        self.assertEqual(
            {f.evidence.symbol for f in low},
            {"android.permission.READ_MEDIA_IMAGES"},
        )
        self.assertEqual(low[0].severity.value, "low")

    def test_special_access_misconfig_rule(self):
        t = Target(input_path="synthetic", platform="android", work_dir=".",
                   name="x")
        t.manifest = _manifest(
            special=("android.permission.MANAGE_EXTERNAL_STORAGE",
                     "android.permission.WRITE_SETTINGS"),
        )
        res = self._result(t)
        mis = [f for f in res.findings if f.rule_id == "MAS-MIS-007"]
        self.assertEqual(
            {f.evidence.symbol for f in mis},
            {"android.permission.MANAGE_EXTERNAL_STORAGE",
             "android.permission.WRITE_SETTINGS"},
        )

    def test_no_matrix_no_privacy_rules(self):
        res = self._result(_target(b"Lcom/example/testapp/MainActivity;"))
        self.assertFalse(
            any(f.rule_id.startswith("MAS-PRI-00")
                for f in res.findings)
        )


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from masanalyzer.scanner import scan

        cls.tmp = tempfile.mkdtemp(prefix="masan_privacy_")
        app = os.path.join(cls.tmp, "app")
        os.makedirs(app)
        with open(
            os.path.join(app, "AndroidManifest.xml"), "wb"
        ) as fh:
            fh.write(manifest_plain(
                "com.example.testapp", "1.0", min_sdk=21, target_sdk=30,
                uses_permissions=(
                    "android.permission.INTERNET",
                    "android.permission.CAMERA",
                    "android.permission.SEND_SMS",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                ),
            ))
        with open(os.path.join(app, "classes.dex"), "wb") as fh:
            fh.write(build_dex(strings=(
                b"Lcom/example/testapp/MainActivity;",
                b"content://sms/inbox",   # SEND_SMS corroborated
            )))
        cls.res = scan(app)

    def test_matrix_in_scan_meta(self):
        counts = self.res.target.meta["privacy_matrix"]["counts"]
        self.assertEqual(counts["dangerous"], 3)     # camera + sms + install
        self.assertEqual(counts["corroborated"], 1)  # sms
        self.assertEqual(counts["excess"], 2)        # camera + install

    def test_m06_and_m08_findings(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("MAS-PRI-007", ids)   # camera unused (sensitive band)
        self.assertIn("MAS-PRI-008", ids)   # REQUEST_INSTALL_PACKAGES (low)
        camera = [
            f for f in self.res.findings
            if f.rule_id == "MAS-PRI-007"
            and "CAMERA" in (f.evidence.symbol or "")
        ]
        self.assertEqual(len(camera), 1)
        install = [
            f for f in self.res.findings
            if f.rule_id == "MAS-MIS-007"
            and "REQUEST_INSTALL" in (f.evidence.symbol or "")
        ]
        self.assertEqual(len(install), 1)

    def test_json_report_privacy_inventory(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.res, "json"))
        priv = doc["inventory"]["privacy"]
        self.assertEqual(priv["dangerous"], 3)
        self.assertEqual(priv["excess"], 2)
        names = {r["permission"] for r in priv["rows"]}
        self.assertIn("android.permission.SEND_SMS", names)


if __name__ == "__main__":
    unittest.main()

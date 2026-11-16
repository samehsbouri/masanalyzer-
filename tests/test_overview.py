"""Feature: at-a-glance overview facts (masanalyzer.overview).

The MobSF-style front panel — file hashes, app identity, signature
schemes/certificate, permission protection levels, component counts —
surfaced in report.json (inventory.overview), the HTML/Markdown reports
and the dashboard overview page.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.overview import build_overview  # noqa: E402
from masanalyzer.reporting import render  # noqa: E402
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import bank_dex, build_ipa, manifest_plain  # noqa: E402


def _apk(tmp: str, name: str = "ov.apk") -> tuple:
    path = os.path.join(tmp, name)
    man = manifest_plain(
        "com.example.overview", "3.1.4", min_sdk=24, target_sdk=34,
        body=(
            '    <activity android:name=".MainActivity" '
            'android:exported="true">\n'
            '      <intent-filter>\n'
            '        <action android:name="android.intent.action.MAIN"/>\n'
            '        <category android:name='
            '"android.intent.category.LAUNCHER"/>\n'
            '      </intent-filter>\n'
            '    </activity>\n'
            '    <service android:name=".SyncService" '
            'android:exported="false"/>\n'
            '    <uses-permission android:name='
            '"android.permission.INTERNET"/>\n'
            '    <uses-permission android:name='
            '"android.permission.ACCESS_FINE_LOCATION"/>\n'
            '    <uses-permission android:name='
            '"android.permission.READ_PROFILE"/>\n'
        ),
    )
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", man)
        z.writestr("classes.dex", bank_dex())
    return path


class OverviewFacts(unittest.TestCase):
    """build_overview extracts parsed facts only."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_")
        cls.path = _apk(cls.tmp)
        cls.result = scan(cls.path, progress=lambda *a: None)
        cls.ov = build_overview(cls.result)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_file_hashes_match_content(self):
        f = self.ov["file"]
        blob = open(self.path, "rb").read()
        self.assertEqual(f["name"], "ov.apk")
        self.assertEqual(f["size_bytes"], len(blob))
        self.assertEqual(f["md5"], hashlib.md5(blob).hexdigest())
        self.assertEqual(f["sha1"], hashlib.sha1(blob).hexdigest())
        self.assertEqual(f["sha256"], hashlib.sha256(blob).hexdigest())

    def test_app_identity(self):
        app = self.ov["app"]
        self.assertEqual(app["package"], "com.example.overview")
        self.assertEqual(app["version_name"], "3.1.4")
        self.assertEqual(app["min_sdk"], 24)
        self.assertEqual(app["target_sdk"], 34)
        self.assertEqual(
            app["main_activity"], "com.example.overview.MainActivity")
        comps = app["components"]
        self.assertEqual(comps["activities"], 1)
        self.assertEqual(comps["services"], 1)
        self.assertEqual(comps["total"], 2)
        self.assertEqual(comps["exported"], 1)
        self.assertIn("1 activity", comps["text"])
        self.assertIn("1 service", comps["text"])

    def test_permission_protection_levels(self):
        levels = {p["name"]: p["protection_level"]
                  for p in self.ov["permissions"]}
        self.assertEqual(levels["android.permission.INTERNET"], "normal")
        self.assertEqual(
            levels["android.permission.ACCESS_FINE_LOCATION"], "dangerous")

    def test_permission_descriptions_bundled_reference(self):
        """Known permissions get the bundled reference wording; unknown
        ones stay without a description (nothing invented)."""
        rows = {p["name"]: p for p in self.ov["permissions"]}
        self.assertIn("network", rows["android.permission.INTERNET"]
                      .get("description", ""))
        self.assertNotIn("description", rows.get(
            "android.permission.READ_PROFILE", {}))

    def test_unsigned_signature_facts(self):
        sig = self.ov["signature"]
        self.assertFalse(sig["signed"])
        self.assertFalse(sig["schemes"]["v1"]["present"])

    def test_score_and_findings_and_surface(self):
        self.assertIn("grade", self.ov["score"])
        self.assertIn("by_severity", self.ov["findings"])
        self.assertIn("fix_first", self.ov["surface"])

    def test_never_raises_on_degenerate_input(self):
        self.assertEqual(build_overview(object()), {})


class ResourceLabelResolution(unittest.TestCase):
    """@res/0x... app labels resolve through resources.arsc."""

    @classmethod
    def setUpClass(cls):
        import shutil

        from masanalyzer.android.resources import resource_strings
        from masanalyzer.testing import build_arsc

        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_label_")
        cls.arsc = build_arsc([
            (0x7F14006B, "PES 2013 Moderno"),
            (0x7F14006C, "Second String"),
        ])
        cls.ids = resource_strings(cls.arsc)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_ids_map_to_strings(self):
        self.assertEqual(self.ids.get(0x7F14006B), "PES 2013 Moderno")
        self.assertEqual(self.ids.get(0x7F14006C), "Second String")

    def test_apk_label_resolved_end_to_end(self):
        from masanalyzer.overview import build_overview
        from masanalyzer.scanner import scan
        from masanalyzer.testing import bank_dex, manifest_plain

        path = os.path.join(self.tmp, "labeled.apk")
        man = manifest_plain(
            "com.example.labeled", "1.0", min_sdk=21, target_sdk=30,
            body=('    <activity android:name=".Main" '
                  'android:exported="true"/>\n'),
        )
        man = man.replace(
            b"<application ",
            b'<application android:label="@res/0x7f14006b" ')
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", man)
            z.writestr("classes.dex", bank_dex())
            z.writestr("resources.arsc", self.arsc)
        result = scan(path, progress=lambda *a: None)
        ov = build_overview(result)
        self.assertEqual(ov["app"].get("app_name"), "PES 2013 Moderno")

    def test_resolver_tolerates_garbage(self):
        from masanalyzer.android.resources import resource_strings

        self.assertEqual(resource_strings(b"not an arsc"), {})
        self.assertEqual(resource_strings(b""), {})


class OverviewSignedApk(unittest.TestCase):
    """Signature facts for a genuinely signed fixture (real cert)."""

    @classmethod
    def setUpClass(cls):
        import shutil

        from masanalyzer.testing import build_signed_apk

        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_sig_")
        apk = build_signed_apk(os.path.join(cls.tmp, "signed.apk"))
        cls.result = scan(apk, progress=lambda *a: None)
        cls.ov = build_overview(cls.result)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_v1_present_and_signed(self):
        sig = self.ov["signature"]
        self.assertTrue(sig["signed"])
        self.assertTrue(sig["schemes"]["v1"]["present"])
        self.assertFalse(sig["schemes"]["v2"]["present"])
        cert = sig["certificates"][0]
        self.assertEqual(
            cert["subject"], "masanalyzer Test Signer")
        self.assertTrue(cert["self_signed"])
        self.assertEqual(cert["key_algorithm"], "rsa")
        self.assertEqual(cert["serial"], "2a")
        self.assertTrue(cert["sha256"])

    def test_certificate_fingerprints_and_algorithms(self):
        """Cert DER content hashes + signature/hash algorithm names."""
        cert = self.ov["signature"]["certificates"][0]
        self.assertEqual(len(cert["md5"]), 32)
        self.assertEqual(len(cert["sha1"]), 40)
        self.assertEqual(len(cert["sha512"]), 128)
        self.assertEqual(
            cert["signature_algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(cert["hash_algorithm"], "sha256")


class OverviewIosTolerance(unittest.TestCase):
    """iOS bundles keep the file facts; Android-only sections stay absent."""

    @classmethod
    def setUpClass(cls):
        import shutil

        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_ios_")
        ipa = build_ipa(os.path.join(cls.tmp, "app.ipa"))
        cls.result = scan(ipa, progress=lambda *a: None)
        cls.ov = build_overview(cls.result)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_file_facts_present_without_manifest_sections(self):
        self.assertIn("sha256", self.ov.get("file") or {})
        self.assertNotIn("app", self.ov)
        self.assertNotIn("signature", self.ov)
        self.assertNotIn("permissions", self.ov)


class OverviewInReports(unittest.TestCase):
    """The overview rides every human/machine report format."""

    @classmethod
    def setUpClass(cls):
        import shutil

        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_rep_")
        cls.result = scan(_apk(cls.tmp), progress=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_json_inventory_overview(self):
        doc = json.loads(render(self.result, "json"))
        ov = doc["inventory"]["overview"]
        self.assertIn("sha256", ov["file"])
        self.assertEqual(ov["app"]["package"], "com.example.overview")
        self.assertIn("permissions", ov)

    def test_markdown_overview_table(self):
        md = render(self.result, "md")
        self.assertIn("## Overview", md)
        self.assertIn("Package name", md)
        self.assertIn("Main activity", md)

    def test_html_overview_grid(self):
        html = render(self.result, "html")
        self.assertIn("<h2>Overview</h2>", html)
        self.assertIn("File information", html)
        self.assertIn("App information", html)
        self.assertIn("Permissions", html)


class OverviewMaxSdk(unittest.TestCase):
    """uses-sdk maxSdkVersion is surfaced when present."""

    def test_max_sdk_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="masan_ov_maxsdk_")
        try:
            path = os.path.join(tmp, "maxsdk.apk")
            man = manifest_plain(
                "com.example.maxsdk", "1.0", min_sdk=21, target_sdk=30,
            )
            man = man.replace(
                b'targetSdkVersion="30"',
                b'targetSdkVersion="30" android:maxSdkVersion="33"')
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("AndroidManifest.xml", man)
                z.writestr("classes.dex", bank_dex())
            result = scan(path, progress=lambda *a: None)
            ov = build_overview(result)
            self.assertEqual(ov["app"].get("max_sdk"), 33)
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


class OverviewTrackers(unittest.TestCase):
    """Tracker endpoints observed are counted on the overview (honest
    wording, no invented denominator)."""

    @classmethod
    def setUpClass(cls):
        import shutil

        from masanalyzer.testing import build_dex

        cls.tmp = tempfile.mkdtemp(prefix="masan_ov_tracker_")
        path = os.path.join(cls.tmp, "trk.apk")
        man = manifest_plain("com.example.trackerapp", "1.0")
        dex = build_dex(
            strings=[
                b"Lcom/example/trackerapp/MainActivity;",
                b"com/example/trackerapp/MainActivity",
                b"https://app.adjust.com/event",
                b"https://api.insecurebank.example:8443/v2/login",
            ],
        )
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", man)
            z.writestr("classes.dex", dex)
        cls.result = scan(path, progress=lambda *a: None)
        cls.ov = build_overview(cls.result)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_tracker_count_end_to_end(self):
        counts = (self.result.target.meta["endpoints"]["counts"])
        self.assertGreaterEqual(counts["tracker"], 1)
        self.assertEqual(self.ov["trackers"]["count"], counts["tracker"])
        self.assertIn("observed", self.ov["trackers"]["note"])
        self.assertNotIn("/432", str(self.ov["trackers"]))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

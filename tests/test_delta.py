"""Release-gate delta gate (masanalyzer.deltacli)."""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.deltacli import (
    bundle_deltas,
    fail_reasons,
)
from masanalyzer.diffcli import diff_reports

MODULE = "masanalyzer.deltacli"


def _report_old() -> dict:
    return {
        "scan": {"target": {"name": "a.apk"}},
        "score": {"total": 80.0},
        "findings": [
            {
                "id": "f1", "rule_id": "MAS-NET-005", "title": "cleartext",
                "severity": "medium", "owasp": "M5",
                "evidence": {"file": "classes.dex", "line": 3},
            },
        ],
        "inventory": {
            "bundle": {
                "version": "1.0.0",
                "size_bytes": 1000000,
                "permissions": [
                    "android.permission.INTERNET",
                    "android.permission.POST_NOTIFICATIONS",
                ],
                "signers": ["abc123cafebabe"],
            },
            "endpoints": {
                "rows": [
                    {"host": "api.example.com", "classification": "first_party"},
                ],
            },
        },
    }


def _report_new() -> dict:
    base = _report_old()
    base["findings"].append({
        "id": "f2", "rule_id": "MAS-MIS-003", "title": "signature perm",
        "severity": "low", "owasp": "M8",
        "evidence": {"file": "AndroidManifest.xml"},
    })
    bundle = base["inventory"]["bundle"]
    bundle.update({
        "version": "1.1.0",
        "size_bytes": 1200000,
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
    })
    base["inventory"]["endpoints"]["rows"] = [
        {"host": "api.example.com", "classification": "public"},
        {"host": "tracker.ads.example.net", "classification": "tracker"},
    ]
    return base


class BundleDeltaTests(unittest.TestCase):
    def test_version_size_permissions(self):
        d = bundle_deltas(_report_old(), _report_new())
        self.assertEqual(d["version"], ("1.0.0", "1.1.0"))
        self.assertEqual(d["size"]["delta"], 200000)
        self.assertEqual(
            d["permissions"]["added"],
            ["android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA"],
        )
        self.assertEqual(d["permissions"]["removed"], [])

    def test_signer_change_detected(self):
        old, new = _report_old(), _report_new()
        new["inventory"]["bundle"]["signers"] = ["ffffffff00000"]
        d = bundle_deltas(old, new)
        self.assertTrue(d["signers"]["changed"])
        self.assertEqual(d["signers"]["removed"], ["abc123cafebabe"])
        self.assertEqual(d["signers"]["added"], ["ffffffff00000"])

    def test_signer_stable_no_change(self):
        d = bundle_deltas(_report_old(), _report_new())
        self.assertFalse(d["signers"]["changed"])

    def test_endpoints_added_removed_reclassified(self):
        d = bundle_deltas(_report_old(), _report_new())["endpoints"]
        self.assertEqual(d["added"], ["tracker.ads.example.net"])
        self.assertEqual(d["removed"], [])
        self.assertEqual(
            d["reclassified"],
            ["api.example.com"],   # first_party -> public
        )

    def test_reports_without_bundle_sections_tolerated(self):
        d = bundle_deltas({"findings": []}, {"findings": []})
        self.assertEqual(d["endpoints"], {"added": [], "removed": [],
                                          "reclassified": []})
        self.assertNotIn("size", d)


class FailGateTests(unittest.TestCase):
    def test_findings_gate(self):
        diff = diff_reports(_report_old(), _report_new())
        reasons = fail_reasons(
            bundle_deltas(_report_old(), _report_new()), diff,
            fail_on="high", gate_permissions=False, gate_signers=False,
        )
        self.assertEqual(reasons, [])   # only a low finding was added

        reasons = fail_reasons(
            bundle_deltas(_report_old(), _report_new()), diff,
            fail_on="low", gate_permissions=False, gate_signers=False,
        )
        self.assertEqual(len(reasons), 1)
        self.assertIn("new finding(s)", reasons[0])

    def test_permission_gate(self):
        diff = diff_reports(_report_old(), _report_new())
        reasons = fail_reasons(
            bundle_deltas(_report_old(), _report_new()), diff,
            fail_on="critical", gate_permissions=True, gate_signers=False,
        )
        self.assertEqual(len(reasons), 1)
        self.assertIn("permission(s) added", reasons[0])
        self.assertIn("CAMERA", reasons[0])

    def test_signer_gate(self):
        old, new = _report_old(), _report_new()
        new["inventory"]["bundle"]["signers"] = ["deadbeefdeadbeef"]
        diff = diff_reports(old, new)
        reasons = fail_reasons(
            bundle_deltas(old, new), diff,
            fail_on="critical", gate_permissions=False, gate_signers=True,
        )
        self.assertEqual(len(reasons), 1)
        self.assertIn("signing identity", reasons[0])


def _with_surface(doc: dict, entry_points: list) -> dict:
    doc.setdefault("inventory", {})["attack_surface"] = {
        "summary": {},
        "entry_points": entry_points,
    }
    return doc


class SurfaceDeltaTests(unittest.TestCase):
    """The gate watches the attack surface, not just severity counts."""

    OLD = [
        {
            "component": "com.example.app.MainActivity", "kind": "activity",
            "permission": "", "browsable_links": [],
        },
        {
            "component": "com.example.app.GuardedActivity",
            "kind": "activity",
            "permission": "com.example.CUSTOM",
            "browsable_links": [
                {"scheme": "myapp", "host": "old.example",
                 "path_prefix": "/v1"},
            ],
        },
    ]

    NEW = [
        {
            "component": "com.example.app.MainActivity", "kind": "activity",
            "permission": "", "browsable_links": [],
        },
        {
            "component": "com.example.app.GuardedActivity",
            "kind": "activity",
            "permission": "com.example.CUSTOM",
            "browsable_links": [
                {"scheme": "myapp", "host": "old.example",
                 "path_prefix": "/v1"},
                {"scheme": "myapp", "host": "new.example",
                 "path_prefix": "/v2"},
            ],
        },
        {
            "component": "com.example.app.OpenActivity", "kind": "activity",
            "permission": "", "browsable_links": [],
        },
    ]

    def test_unguarded_door_and_links_detected(self):
        d = bundle_deltas(
            _with_surface(_report_old(), self.OLD),
            _with_surface(_report_new(), self.NEW),
        )["surface"]
        self.assertEqual(
            d["unguarded_added"], ["com.example.app.OpenActivity"])
        self.assertEqual(d["removed"], [])
        self.assertEqual(
            d["deep_links_added"], ["myapp|new.example|/v2"])
        self.assertEqual(d["deep_links_removed"], [])

    def test_surface_shrink_is_not_a_regression(self):
        d = bundle_deltas(
            _with_surface(_report_old(), self.NEW),
            _with_surface(_report_new(), self.OLD),
        )["surface"]
        self.assertEqual(d["unguarded_added"], [])
        self.assertEqual(d["deep_links_added"], [])
        self.assertEqual(
            d["removed"], ["com.example.app.OpenActivity"])

    def test_reports_without_surface_tolerated(self):
        d = bundle_deltas({"findings": []}, {"findings": []})["surface"]
        self.assertFalse(d["comparable"])
        reasons = fail_reasons(
            d, diff_reports(_report_old(), _report_new()),
            fail_on="critical", gate_permissions=False,
            gate_signers=False, gate_surface=True,
        )
        self.assertEqual(reasons, [])

    def test_gate_fires_on_unguarded_and_links(self):
        deltas = bundle_deltas(
            _with_surface(_report_old(), self.OLD),
            _with_surface(_report_new(), self.NEW),
        )
        diff = diff_reports(_report_old(), _report_new())
        reasons = fail_reasons(
            deltas, diff, fail_on="critical", gate_permissions=False,
            gate_signers=False, gate_surface=True,
        )
        self.assertEqual(len(reasons), 2)
        self.assertIn("unguarded entry point(s) added", reasons[0])
        self.assertIn("OpenActivity", reasons[0])
        self.assertIn("deep link(s) added", reasons[1])
        self.assertIn("myapp://new.example/v2", reasons[1])

    def test_gate_silent_when_surface_stable(self):
        deltas = bundle_deltas(
            _with_surface(_report_old(), self.OLD),
            _with_surface(_report_new(), self.OLD),
        )
        diff = diff_reports(_report_old(), _report_new())
        reasons = fail_reasons(
            deltas, diff, fail_on="critical", gate_permissions=False,
            gate_signers=False, gate_surface=True,
        )
        self.assertEqual(reasons, [])


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import contextlib
        from masanalyzer.cli import main as cli_main
        from masanalyzer.scanner import scan

        def build(tmp: str, perms: tuple) -> str:
            app = os.path.join(tmp, "app_" + str(len(perms)))
            os.makedirs(app)
            with open(os.path.join(app, "AndroidManifest.xml"), "wb") as fh:
                fh.write(_manifest_bytes(perms))
            with open(os.path.join(app, "classes.dex"), "wb") as fh:
                fh.write(b"d" * 1000)   # plain payload, no valid dex
            res = scan(app)
            from masanalyzer.reporting import render

            path = os.path.join(tmp, f"report_{len(perms)}.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render(res, "json"))
            return path

        cls.tmp = tempfile.mkdtemp(prefix="masan_delta_")
        cls.old_report = build(
            cls.tmp, ("android.permission.INTERNET",),
        )
        cls.new_report = build(
            cls.tmp,
            ("android.permission.INTERNET", "android.permission.CAMERA"),
        )

    def test_cli_pass(self):
        from masanalyzer.deltacli import main

        rc = main([self.old_report, self.new_report])
        self.assertEqual(rc, 0)

    def test_cli_permission_gate_blocks(self):
        from masanalyzer.deltacli import main

        rc = main([self.old_report, self.new_report, "--gate-permissions"])
        self.assertEqual(rc, 1)

    def test_findings_gate_blocks_on_high(self):
        # both trees hit the unsigned-app identity rules; the NEW report must
        # only add low/medium bands here, so fail-on critical passes
        from masanalyzer.deltacli import main

        rc = main([self.old_report, self.new_report, "--fail-on", "critical"])
        self.assertEqual(rc, 0)

    def test_cli_bad_file(self):
        from masanalyzer.deltacli import main

        rc = main([self.old_report, os.path.join(self.tmp, "missing.json")])
        self.assertEqual(rc, 2)


class SurfaceGateE2E(unittest.TestCase):
    """A new unguarded browsable door in the manifest blocks the release."""

    @classmethod
    def setUpClass(cls):
        from masanalyzer.scanner import scan
        from masanalyzer.testing import manifest_plain

        def build(tmp: str, body: str, tag: str) -> str:
            app = os.path.join(tmp, "app_" + tag)
            os.makedirs(app)
            with open(os.path.join(app, "AndroidManifest.xml"), "wb") as fh:
                fh.write(manifest_plain(
                    "com.example.testapp", "1.0", min_sdk=21,
                    target_sdk=30, body=body))
            with open(os.path.join(app, "classes.dex"), "wb") as fh:
                fh.write(b"d" * 1000)
            res = scan(app)
            from masanalyzer.reporting import render

            path = os.path.join(tmp, f"report_{tag}.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(render(res, "json"))
            return path

        cls.tmp = tempfile.mkdtemp(prefix="masan_surf_gate_")
        cls.old_report = build(cls.tmp, "", "old")
        cls.new_report = build(
            cls.tmp,
            '    <activity android:name=".OpenActivity" '
            'android:exported="true">\n'
            '      <intent-filter>\n'
            '        <action android:name="android.intent.action.VIEW"/>\n'
            '        <category android:name='
            '"android.intent.category.DEFAULT"/>\n'
            '        <category android:name='
            '"android.intent.category.BROWSABLE"/>\n'
            '        <data android:scheme="myapp" android:host="gate.example"'
            ' android:pathPrefix="/open"/>\n'
            '      </intent-filter>\n'
            '    </activity>\n',
            "new",
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_surface_delta_detects_new_door(self):
        from masanalyzer.deltacli import bundle_deltas

        d = bundle_deltas(
            json.load(open(self.old_report, encoding="utf-8")),
            json.load(open(self.new_report, encoding="utf-8")),
        )["surface"]
        self.assertEqual(
            d["unguarded_added"],
            ["com.example.testapp.OpenActivity"])
        self.assertEqual(
            d["deep_links_added"], ["myapp|gate.example|/open"])

    def test_gate_blocks(self):
        from masanalyzer.deltacli import main

        rc = main([self.old_report, self.new_report, "--gate-surface",
                   "--fail-on", "critical"])
        self.assertEqual(rc, 1)

    def test_no_gate_passes(self):
        from masanalyzer.deltacli import main

        rc = main([self.old_report, self.new_report,
                   "--fail-on", "critical"])
        self.assertEqual(rc, 0)


def _manifest_bytes(perms: tuple) -> bytes:
    from masanalyzer.testing import manifest_plain

    return manifest_plain(
        "com.example.testapp", "1.0", min_sdk=21, target_sdk=30,
        uses_permissions=perms,
    )


if __name__ == "__main__":
    unittest.main()

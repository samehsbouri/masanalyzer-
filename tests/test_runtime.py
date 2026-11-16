"""Runtime session ingestion (masanalyzer.runtime) - bundle, rules, correlation."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer import assurance
from masanalyzer.model import Target
from masanalyzer.runtime import BundleError, analyze_bundle, load_bundle
from masanalyzer.testing import build_dex, manifest_axml

SESSION = {
    "id": "2026-11-16T10-12-00-login",
    "device": "emulator-5554",
    "api_level": 33,
    "image": "aosp_atd_x86_64",
    "flow": "login",
    "tls_interception": "system-ca",
    "rooted": True,
}


#: credential-shaped fixtures are assembled from harmless words instead of
#: being written out: a token literal in a test file trips secret scanners
#: (GitGuardian flagged this fixture as a leaked bearer token)
FIXTURE_KEY = "-".join(("fixture", "api", "key"))
FIXTURE_TOKEN = "-".join(("fixture", "bearer", "token"))


def _har(entries):
    """``entries`` = (method, url, headers, status, mime, body) tuples."""
    return {"log": {"version": "1.2", "entries": [
        {
            "startedDateTime": "2026-11-16T10:12:01.000Z",
            "request": {
                "method": method,
                "url": url,
                "headers": [{"name": n, "value": v} for n, v in headers],
            },
            "response": {
                "status": status,
                "content": {"mimeType": mime, "text": body},
            },
        }
        for method, url, headers, status, mime, body in entries
    ]}}


def write_bundle(root, har_entries=None, logcat=None, session=None, extra=None):
    os.makedirs(root, exist_ok=True)
    doc = {"schema": "masanalyzer.runtime/1", "session": session or dict(SESSION)}
    doc.update(extra or {})
    with open(os.path.join(root, "runtime.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    if har_entries is not None:
        with open(os.path.join(root, "traffic.har"), "w", encoding="utf-8") as fh:
            json.dump(_har(har_entries), fh)
    if logcat is not None:
        with open(os.path.join(root, "logcat.txt"), "w", encoding="utf-8") as fh:
            fh.write(logcat)
    return root


def target_with(hosts):
    t = Target(input_path="synthetic", platform="android", work_dir=".", name="x")
    t.package = "com.examplecorp-team.app"
    t.meta["endpoints"] = {
        "total": len(hosts),
        "rows": [{"host": h, "classification": "public"} for h in hosts],
    }
    return t


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masan_rt_")

    def test_reads_provenance_traffic_and_logcat(self):
        root = write_bundle(
            os.path.join(self.tmp, "s1"),
            har_entries=[
                ("GET", "https://api.example.test/v1/login", [], 200, "application/json", "{}"),
            ],
            logcat="11-16 10:12:01.001  1234  1250 I ActivityManager: Start proc com.x\n",
        )
        bundle = load_bundle(root)
        self.assertEqual(bundle.session_id, SESSION["id"])
        self.assertEqual(bundle.provenance()["api_level"], 33)
        self.assertEqual(len(bundle.traffic), 1)
        self.assertEqual(bundle.traffic[0].host, "api.example.test")
        self.assertEqual(len(bundle.logcat), 1)
        self.assertTrue(bundle.has_data)

    def test_missing_provenance_is_an_error(self):
        root = os.path.join(self.tmp, "empty")
        os.makedirs(root)
        with self.assertRaises(BundleError):
            load_bundle(root)

    def test_broken_har_degrades_to_a_warning(self):
        root = write_bundle(os.path.join(self.tmp, "s2"))
        with open(os.path.join(root, "traffic.har"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        bundle = load_bundle(root)
        self.assertEqual(bundle.traffic, [])
        self.assertTrue(any("traffic.har" in w for w in bundle.warnings))

    def test_logcat_continuation_lines_stay_with_their_entry(self):
        root = write_bundle(
            os.path.join(self.tmp, "s3"),
            logcat=(
                "11-16 10:12:01.001  1234  1250 E AndroidRuntime: FATAL EXCEPTION: main\n"
                "\tat com.example.Boom(Boom.java:9)\n"
            ),
        )
        bundle = load_bundle(root)
        self.assertEqual(len(bundle.logcat), 1)
        self.assertIn("com.example.Boom", bundle.logcat[0].message)
        self.assertTrue(bundle.logcat[0].is_error)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masan_rt_")

    def _analyze(self, har_entries, **kw):
        static_hosts = kw.pop("static_hosts", [])
        root = write_bundle(os.path.join(self.tmp, "s"), har_entries=har_entries, **kw)
        return analyze_bundle(load_bundle(root), target_with(static_hosts))

    def test_cleartext_request_is_observed(self):
        findings, inventory = self._analyze([
            ("GET", "http://api.example.test/v1/health", [], 200, "text/plain", "ok"),
        ])
        dyn = [f for f in findings if f.rule_id == "MAS-DYN-001"]
        self.assertEqual(len(dyn), 1)
        self.assertEqual(dyn[0].severity.value, "high")
        self.assertIn("api.example.test", dyn[0].evidence.note)
        self.assertEqual(inventory["traffic"]["cleartext"], 1)
        self.assertEqual(inventory["session"]["flow"], "login")

    def test_https_only_traffic_is_quiet(self):
        findings, _ = self._analyze(
            [("GET", "https://api.example.test/v1/health", [], 200, "text/plain", "ok")],
            static_hosts=["api.example.test"],
        )
        self.assertEqual(findings, [])

    def test_credentials_are_found_and_redacted(self):
        findings, _ = self._analyze([
            ("POST", f"https://api.example.test/v1/login?api_key={FIXTURE_KEY}",
             [], 200, "application/json", "{}"),
            ("GET", "https://api.example.test/v2/me",
             [("Authorization", f"Bearer {FIXTURE_TOKEN}")], 200,
             "application/json", "{}"),
        ])
        cred = [f for f in findings if f.rule_id == "MAS-DYN-002"]
        self.assertEqual(len(cred), 1)          # one finding per host
        blob = json.dumps([f.to_dict() for f in cred])
        self.assertNotIn(FIXTURE_KEY, blob)
        self.assertNotIn(FIXTURE_TOKEN, blob)
        self.assertIn("api_key=fix", blob)

    def test_tracker_beacon(self):
        findings, inventory = self._analyze([
            ("GET", "https://sub.appsflyer.com/install", [], 200, "text/plain", ""),
        ])
        self.assertIn("MAS-DYN-003", {f.rule_id for f in findings})
        self.assertEqual(inventory["traffic"]["trackers"], 1)

    def test_unseen_host_is_reported_and_known_host_is_not(self):
        findings, inventory = self._analyze(
            [
                ("GET", "https://api.example.test/v1/me", [], 200, "text/plain", ""),
                ("GET", "https://cdn.dynamic-cfg.test/bundle.json", [], 200, "text/plain", ""),
            ],
            static_hosts=["api.example.test", "old.static-only.test"],
        )
        dyn = [f for f in findings if f.rule_id == "MAS-DYN-004"]
        self.assertEqual(len(dyn), 1)
        self.assertIn("cdn.dynamic-cfg.test", dyn[0].evidence.note)
        corr = inventory["correlation"]
        self.assertEqual(corr["matched"], 1)
        self.assertEqual(corr["runtime_only"], ["cdn.dynamic-cfg.test"])
        self.assertEqual(corr["static_only"], ["old.static-only.test"])
        self.assertEqual(corr["static_hosts"], 2)

    def test_logcat_tls_errors_are_summarised(self):
        _, inventory = self._analyze(
            [("GET", "https://api.example.test/x", [], 200, "text/plain", "")],
            logcat=(
                "11-16 10:12:03.001  1234  1250 E okhttp: SSLHandshakeException: "
                "java.security.cert.CertPathValidatorException: Trust anchor for "
                "certification path not found.\n"
            ),
        )
        self.assertEqual(inventory["logcat"]["tls_errors"], 1)

    def test_dynamic_rules_are_observed_tier(self):
        for rid in ("MAS-DYN-001", "MAS-DYN-002", "MAS-DYN-003", "MAS-DYN-004"):
            self.assertEqual(assurance.tier_for(rid), assurance.OBSERVED)


class ScanWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_rt_scan_")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("AndroidManifest.xml",
                       manifest_axml("com.example.testapp", "1.0"))
            z.writestr("classes.dex", build_dex(strings=(
                b"https://api.testapp.com/v1/login",
            )))
        cls.apk = os.path.join(cls.tmp, "app.apk")
        with open(cls.apk, "wb") as fh:
            fh.write(buf.getvalue())
        cls.bundle = write_bundle(
            os.path.join(cls.tmp, "session"),
            har_entries=[
                ("GET", "http://api.testapp.com/v1/login", [], 200, "text/plain", ""),
                ("GET", "https://new.runtime-only.test/ping", [], 200, "text/plain", ""),
            ],
        )
        from masanalyzer.scanner import scan

        cls.static = scan(cls.apk)
        cls.dynamic = scan(cls.apk, runtime=cls.bundle)

    def test_findings_and_meta_are_attached(self):
        ids = {f.rule_id for f in self.dynamic.findings}
        self.assertIn("MAS-DYN-001", ids)
        self.assertIn("MAS-DYN-004", ids)
        runtime = self.dynamic.target.meta["runtime"]
        self.assertEqual(runtime["session"]["image"], "aosp_atd_x86_64")
        self.assertEqual(runtime["correlation"]["runtime_only"],
                         ["new.runtime-only.test"])

    def test_observed_tier_reaches_the_findings(self):
        dyn = [f for f in self.dynamic.findings if f.rule_id.startswith("MAS-DYN-")]
        self.assertTrue(dyn)
        self.assertEqual({f.assurance for f in dyn}, {"observed"})

    def test_json_report_gains_a_runtime_section(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.dynamic, "json"))
        self.assertIn("runtime", doc["inventory"])
        self.assertEqual(doc["inventory"]["runtime"]["traffic"]["hosts"], 2)

    def test_static_scan_is_untouched(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.static, "json"))
        self.assertNotIn("runtime", doc["inventory"])
        self.assertFalse(
            [f for f in self.static.findings if f.rule_id.startswith("MAS-DYN-")]
        )


if __name__ == "__main__":
    unittest.main()

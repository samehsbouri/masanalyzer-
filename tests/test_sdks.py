"""Embedded SDK fingerprinting + version-aware SCA (masanalyzer.sdks)."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.model import Target
from masanalyzer.sdks import (
    SDK_SIGNATURES,
    VULNERABLE_SDKS,
    add_vulnerable_rule,
    detect_sdks,
    vulnerable_version_check,
)
from masanalyzer.testing import build_dex, manifest_axml


def _target(*dexes: bytes) -> Target:
    """A synthetic android target whose meta carries the fixture DEXes."""
    import types as _t

    t = Target(input_path="synthetic", platform="android", work_dir=".", name="x")
    t.meta["dex_files"] = []
    for blob in dexes:
        dex = _t.SimpleNamespace()
        dex.iter_strings = _strings_iter(blob)
        t.meta["dex_files"].append(dex)
    return t


def _strings_iter(blob: bytes):
    from masanalyzer.android.dex import parse_dex

    return parse_dex(blob).iter_strings


class DetectionTests(unittest.TestCase):
    def test_descriptor_signature_detected(self):
        dex = build_dex(strings=(
            b"Lcom/appsflyer/AppsFlyerLibCore;",
            b"Lcom/example/app/MainActivity;",
            b"Lokhttp3/OkHttpClient;",
        ))
        t = _target(dex)
        hits = detect_sdks(t)
        ids = {h["id"] for h in hits}
        self.assertIn("appsflyer", ids)
        self.assertIn("okhttp", ids)
        self.assertNotIn("adjust", ids)
        # evidence carries the actual descriptor string
        af = next(h for h in hits if h["id"] == "appsflyer")
        self.assertEqual(af["evidence"][0], "Lcom/appsflyer/AppsFlyerLibCore;")
        self.assertEqual(af["sources"], ["dex-descriptors"])
        # meta is written for downstream consumers
        self.assertIs(t.meta["sdks"], hits)
        self.assertGreater(t.meta["sdks_stats"]["dex_strings_scanned"], 0)

    def test_eol_sdk_detected(self):
        dex = build_dex(strings=(
            b"Lorg/apache/http/message/BasicHeader;",
        ))
        hits = detect_sdks(_target(dex))
        self.assertEqual([h["id"] for h in hits], ["apache-http"])

    def test_version_extracted_from_string(self):
        dex = build_dex(strings=(
            b"Lokhttp3/internal/platform/Platform;",
            b"okhttp/3.12.1",
        ))
        hits = detect_sdks(_target(dex))
        okhttp = next(h for h in hits if h["id"] == "okhttp")
        self.assertEqual(okhttp["version"], "3.12.1")

    def test_no_hits_clean_target(self):
        dex = build_dex(strings=(
            b"Lcom/example/app/MainActivity;",
            b"just a plain string",
        ))
        t = _target(dex)
        hits = detect_sdks(t)
        self.assertEqual(hits, [])
        self.assertEqual(t.meta["sdks_stats"]["detected"], 0)

    def test_version_string_alone_is_not_enough(self):
        """A version literal without any descriptor/prefix does not invent a hit."""
        dex = build_dex(strings=(b"okhttp/3.12.1",))
        hits = detect_sdks(_target(dex))
        self.assertEqual(hits, [])

    def test_signature_db_shape(self):
        for sig in SDK_SIGNATURES:
            self.assertTrue(sig["id"] and sig["vendor"] and sig["category"])
            self.assertTrue(sig["prefixes"], sig["id"])


class VulnerableVersionTests(unittest.TestCase):
    def test_okhttp_pre_313_flags(self):
        hit = {"id": "okhttp", "version": "3.12.0"}
        reason = vulnerable_version_check(hit)
        self.assertIsNotNone(reason)
        self.assertIn("TLS 1.0", reason)

    def test_okhttp_modern_clean(self):
        self.assertIsNone(vulnerable_version_check({"id": "okhttp", "version": "4.9.0"}))
        self.assertIsNone(vulnerable_version_check({"id": "okhttp", "version": "3.13.0"}))

    def test_unknown_sdk_no_reason(self):
        self.assertIsNone(vulnerable_version_check({"id": "glide", "version": "2.0.0"}))
        self.assertIsNone(vulnerable_version_check({"id": "glide", "version": None}))

    def test_garbage_version_is_not_fatal(self):
        self.assertIsNone(
            vulnerable_version_check({"id": "okhttp", "version": "not-a-version"})
        )

    def test_runtime_rule_extension(self):
        try:
            add_vulnerable_rule("glide", "4.0.0", "glide < 4 is policy-restricted here")
            self.assertEqual(
                vulnerable_version_check({"id": "glide", "version": "3.12.0"}),
                "glide < 4 is policy-restricted here",
            )
            self.assertIsNone(
                vulnerable_version_check({"id": "glide", "version": "4.1.2"})
            )
        finally:
            VULNERABLE_SDKS.pop("glide", None)

    def test_version_tuple_parsing(self):
        from masanalyzer.sdks import _version_tuple

        self.assertEqual(_version_tuple("3.12.1"), (3, 12, 1))
        self.assertEqual(_version_tuple("5.5.1"), (5, 5, 1))
        self.assertEqual(_version_tuple("2.11"), (2, 11))


class EndToEndTests(unittest.TestCase):
    """apk fixture -> scan() wires sdks into meta, rules, reports."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_sdk_")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr(
                "AndroidManifest.xml",
                manifest_axml("com.example.testapp", "1.0"),
            )
            z.writestr("classes.dex", build_dex(strings=(
                b"Lcom/example/testapp/MainActivity;",
                b"Lokhttp3/OkHttpClient;",
                b"okhttp/3.12.0",
                b"Lorg/apache/http/message/BasicHeader;",
                b"Lcom/mopub/mobileads/MoPubView;",
            )))
        cls.apk = os.path.join(cls.tmp, "sdks.apk")
        with open(cls.apk, "wb") as fh:
            fh.write(buf.getvalue())
        from masanalyzer.scanner import scan

        cls.res = scan(cls.apk)

    def test_sdks_in_scan_meta(self):
        hits = self.res.target.meta.get("sdks")
        self.assertIsNotNone(hits)
        by_id = {h["id"]: h for h in hits}
        self.assertIn("okhttp", by_id)
        self.assertEqual(by_id["okhttp"]["version"], "3.12.0")
        self.assertIn("apache-http", by_id)
        self.assertIn("mopub", by_id)

    def test_sca_rules_fire(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("MAS-SCA-001", ids)   # okhttp 3.12.0 < 3.13.0
        self.assertIn("MAS-SCA-002", ids)   # apache-http + mopub EOL
        notes = [f.evidence.note for f in self.res.findings
                 if f.rule_id == "MAS-SCA-001"]
        self.assertTrue(any("okhttp 3.12.0" in (n or "") for n in notes), notes)

    def test_json_report_inventory_sdks(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.res, "json"))
        sdks = doc["inventory"]["sdks"]
        self.assertGreater(sdks["total"], 0)
        ids = {c["id"] for c in sdks["components"]}
        self.assertIn("okhttp", ids)

    def test_sbom_has_sdk_components(self):
        from masanalyzer.reporting import render

        cdx = json.loads(render(self.res, "sbom"))
        names = {c["name"] for c in cdx["components"]}
        self.assertIn("okhttp", names)
        okhttp = next(c for c in cdx["components"] if c["name"] == "okhttp")
        self.assertEqual(okhttp["type"], "framework")
        self.assertEqual(okhttp.get("version"), "3.12.0")
        self.assertTrue(any(p["name"] == "masanalyzer:vendor"
                            for p in okhttp["properties"]))


if __name__ == "__main__":
    unittest.main()

"""End-to-end tests for real v1 (JAR) APK signature verification."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android import apk as apk_mod
from masanalyzer.android import apkverify
from masanalyzer.testing import build_signed_apk


class V1VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_apkverify_")
        cls.good = build_signed_apk(
            os.path.join(cls.tmp, "good.apk"), package="com.example.good"
        )
        cls.bad = build_signed_apk(
            os.path.join(cls.tmp, "bad.apk"), package="com.example.bad", tamper=True
        )

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _verify(self, path):
        with zipfile.ZipFile(path) as zf:
            return apkverify.verify_v1_signature(zf)

    def test_valid_apk_verifies(self):
        result, sf_name = self._verify(self.good)
        self.assertIsNotNone(result)
        self.assertTrue(result.verified, result.describe())
        self.assertGreaterEqual(result.covered_entries, 3)
        self.assertEqual(sf_name.lower(), "meta-inf/cert.sf")
        self.assertEqual(result.reasons, [])

    def test_tampered_dex_fails(self):
        result, _ = self._verify(self.bad)
        self.assertIsNotNone(result)
        self.assertFalse(result.verified)
        self.assertTrue(
            any("digest mismatch" in r for r in result.reasons), result.describe()
        )

    def test_load_apk_reports_state(self):
        info = apk_mod.load_apk(self.good)
        self.assertTrue(info.v1_verified, info.warnings)
        self.assertGreaterEqual(info.v1_covered_entries, 3)

        bad_info = apk_mod.load_apk(self.bad)
        self.assertFalse(bad_info.v1_verified)
        self.assertTrue(bad_info.v1_reasons)

    def test_unsigned_apk_has_no_state(self):
        # build a plain unsigned container through the existing fixture path
        from masanalyzer.testing import build_apk

        plain = os.path.join(self.tmp, "plain.apk")
        build_apk(plain)
        info = apk_mod.load_apk(plain)
        self.assertIsNone(info.v1_verified)

    def test_manifest_tamper_fails(self):
        # rewrite the manifest content inside the good apk -> SF digest break
        import base64
        import hashlib

        out = os.path.join(self.tmp, "mf_tamper.apk")
        with zipfile.ZipFile(self.good) as zin, zipfile.ZipFile(
            out, "w"
        ) as zout:
            for name in zin.namelist():
                data = zin.read(name)
                if name.lower() == "androidmanifest.xml":
                    data = data[:-1] + bytes([data[-1] ^ 0x40])
                zout.writestr(name, data)
        result, _ = self._verify(out)
        self.assertFalse(result.verified)
        joined = " | ".join(result.reasons)
        self.assertTrue(
            "manifest" in joined or "digest" in joined, joined
        )

    def test_missing_coverage_fails(self):
        # add an extra file that the signed manifest does not know about
        out = os.path.join(self.tmp, "extra.apk")
        with zipfile.ZipFile(self.good) as zin, zipfile.ZipFile(
            out, "w"
        ) as zout:
            for name in zin.namelist():
                zout.writestr(name, zin.read(name))
            zout.writestr("smuggled.bin", b"evil payload")
        result, _ = self._verify(out)
        self.assertFalse(result.verified)
        self.assertTrue(
            any("not covered" in r for r in result.reasons), result.describe()
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Acceptance test: full scan pipeline on real signed/tampered APK fixtures."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.scanner import scan
from masanalyzer.testing import build_signed_apk


class SignedApkScans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_scanapk_")
        cls.good = build_signed_apk(os.path.join(cls.tmp, "good.apk"))
        cls.bad = build_signed_apk(os.path.join(cls.tmp, "bad.apk"), tamper=True)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_good_apk_no_sup008(self):
        result = scan(self.good)
        rules = {f.rule_id for f in result.findings}
        self.assertNotIn("MAS-SUP-008", rules)
        apk = result.target.meta.get("apk")
        self.assertTrue(apk.v1_verified)

    def test_tampered_apk_raises_critical(self):
        result = scan(self.bad)
        hits = [f for f in result.findings if f.rule_id == "MAS-SUP-008"]
        self.assertTrue(hits, "expected MAS-SUP-008 on the tampered apk")
        self.assertEqual(hits[0].severity.value, "critical")
        self.assertIn("digest mismatch", hits[0].evidence.note or hits[0].description)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

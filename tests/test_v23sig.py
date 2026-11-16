"""Tests for APK signature scheme v2/v3 verification (apksigv2) + rules."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android import apk as apk_mod
from masanalyzer.android import apksigv2
from masanalyzer.model import Target
from masanalyzer.testing import build_v23_signed_apk


class V2V3VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_v23_")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _load(tmp_base, scheme, tamper):
        path = os.path.join(
            tmp_base, f"{scheme}{'_bad' if tamper else ''}.apk"
        )
        build_v23_signed_apk(path, scheme=scheme, tamper=tamper)
        return path

    def test_clean_v2_verifies(self):
        path = self._load(self.tmp, "v2", tamper=False)
        data = open(path, "rb").read()
        block = apksigv2.find_signing_block(data)
        self.assertIsNotNone(block)
        self.assertIsNotNone(apksigv2.APK_SIG_BLOCK_MAGIC)
        res = apksigv2.verify_v2(data, block)
        self.assertTrue(res.verified, res.reasons)
        self.assertEqual(res.signer_count, 1)
        self.assertEqual(res.digest_algorithm, "sha256")

    def test_clean_v3_verifies(self):
        path = self._load(self.tmp, "v3", tamper=False)
        data = open(path, "rb").read()
        block = apksigv2.find_signing_block(data)
        res = apksigv2.verify_v3(data, block)
        self.assertTrue(res.verified, res.reasons)
        self.assertEqual(res.signer_count, 1)
        # min/max SDK round-trip
        self.assertEqual(block.entries.get(apksigv2.V3_BLOCK_ID) is not None, True)

    def test_tampered_v2_fails_on_content_digest(self):
        path = self._load(self.tmp, "v2", tamper=True)
        data = open(path, "rb").read()
        block = apksigv2.find_signing_block(data)
        res = apksigv2.verify_v2(data, block)
        self.assertFalse(res.verified)
        self.assertFalse(res.layout_ok is False)  # layout itself is intact
        self.assertTrue(
            any("does NOT match the signed digest" in r for r in res.reasons),
            res.reasons,
        )

    def test_tampered_v3_fails_on_content_digest(self):
        path = self._load(self.tmp, "v3", tamper=True)
        data = open(path, "rb").read()
        block = apksigv2.find_signing_block(data)
        res = apksigv2.verify_v3(data, block)
        self.assertFalse(res.verified)
        self.assertTrue(
            any("does NOT match the signed digest" in r for r in res.reasons),
            res.reasons,
        )

    def test_forged_signature_fails(self):
        """Rewrite the signed data inside signedData - signature must break."""
        path = self._load(self.tmp, "v2", tamper=False)
        blob = bytearray(open(path, "rb").read())
        block = apksigv2.find_signing_block(bytes(blob))
        payload = block.entries[apksigv2.V2_BLOCK_ID]
        off = blob.find(payload)
        # flip one byte inside the certificates (digests stay valid)
        idx = off + 4                                     # signer record start
        blob[idx + 40] ^= 0xFF
        data2 = bytes(blob)
        block2 = apksigv2.find_signing_block(data2)
        res = apksigv2.verify_v2(data2, block2)
        self.assertFalse(res.verified)

    def test_load_apk_reports_verification(self):
        for scheme in ("v2", "v3"):
            clean = self._load(self.tmp, scheme, tamper=False)
            bad = self._load(self.tmp, scheme, tamper=True)
            info_c, info_b = apk_mod.load_apk(clean), apk_mod.load_apk(bad)
            key = f"{scheme}_verified"
            self.assertIs(True, getattr(info_c, key))
            self.assertIs(False, getattr(info_b, key))
            self.assertEqual(info_c.zip_layout_anomalies, [])


class RuleIntegrationTests(unittest.TestCase):
    """m02 rules must fire on verifications from load_apk meta."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_v23rules_")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_v2_broken_rule_fires(self):
        from masanalyzer.analysis import m02

        path = os.path.join(self.tmp, "tamper_v2rule.apk")
        build_v23_signed_apk(path, scheme="v2", tamper=True)
        info = apk_mod.load_apk(path)
        target = Target(input_path=path, platform="android", work_dir=self.tmp, name="tamper.apk")
        target.meta["apk"] = info
        ids = {f.rule_id for f in m02.analyze(target)}
        self.assertIn("MAS-SUP-010", ids)

    def test_rollback_banner_rule(self):
        from masanalyzer.analysis import m02

        # banner absent (fixtures carry no v1 signature) -> None -> no rule;
        # the rule drives the pair: simulate by monkey flag
        rule = m02.R_ROLLBACK
        self.assertEqual(rule.rule_id, "MAS-SUP-012")
        self.assertEqual(rule.title.find("banner") >= 0, True)

    def test_catalog_includes_new_rules(self):
        from masanalyzer.analysis import rule_catalog

        ids = {r.rule_id for r in rule_catalog()}
        self.assertTrue(
            {"MAS-SUP-009", "MAS-SUP-010", "MAS-SUP-011", "MAS-SUP-012"} <= ids
        )


class ZipLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_ziplay_")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _apk(self, name):
        path = os.path.join(self.tmp, name)
        apk_mod.build_signed_apk(path)
        return apk_mod.load_apk(path)

    def test_normal_apk_has_no_anomalies(self):
        from masanalyzer.testing import build_signed_apk

        path = os.path.join(self.tmp, "plain.apk")
        build_signed_apk(path)
        info = apk_mod.load_apk(path)
        self.assertEqual(info.zip_layout_anomalies, [])

    def test_mispointed_central_directory_is_detected(self):
        from masanalyzer.testing import build_signed_apk

        import struct

        path = os.path.join(self.tmp, "janus.apk")
        build_signed_apk(path)
        blob = bytearray(open(path, "rb").read())
        eocd = blob.rfind(b"PK\x05\x06")
        (cd_off,) = struct.unpack_from("<I", blob, eocd + 16)
        # first CD entry's local header offset field = cd_off + 42
        (local,) = struct.unpack_from("<I", blob, cd_off + 42)
        struct.pack_into("<I", blob, cd_off + 42, 1)   # points at junk
        anom = apk_mod._zip_layout_anomalies(bytes(blob), eocd)
        self.assertTrue(anom, "layout detector must flag mispointed entries")


if __name__ == "__main__":
    unittest.main()

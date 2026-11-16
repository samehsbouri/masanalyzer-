"""Identity gate (--verify-identity) + signing-certificate quality rules."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import datetime as _dt

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.pkcs7 import parse_certificate
from masanalyzer.testing import (
    build_signed_apk,
    build_v23_signed_apk,
    cert_der_for_rsa,
    rsa_keypair,
)


class ParseCertificateTests(unittest.TestCase):
    def setUp(self):
        self.key = rsa_keypair()
        self.cert = cert_der_for_rsa(self.key)
        self.info = parse_certificate(self.cert)

    def test_subject_and_issuer(self):
        self.assertEqual(self.info.subject, "masanalyzer Test Signer")
        self.assertTrue(self.info.self_signed)

    def test_validity_window(self):
        # UTCTime '26' -> 2026, '34' -> 2034
        self.assertEqual(self.info.not_before.date(), _dt.date(2026, 1, 1))
        self.assertEqual(self.info.not_after.date(), _dt.date(2034, 1, 1))

    def test_key_info(self):
        self.assertEqual(self.info.key_algorithm, "rsa")
        self.assertGreaterEqual(self.info.key_bits, 1023)
        self.assertEqual(self.info.serial_hex, "2a")


class FingerprintExtractionTests(unittest.TestCase):
    """load_apk must surface the leaf-cert fingerprint for all schemes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_identity_")
        cls.expected = hashlib.sha256(cert_der_for_rsa(rsa_keypair())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_fingerprints_same_cert_across_schemes(self):
        for tag, path in (
            ("v1", build_signed_apk(os.path.join(self.tmp, "s1.apk"))),
            ("v2", build_v23_signed_apk(os.path.join(self.tmp, "s2.apk"), scheme="v2")),
            ("v3", build_v23_signed_apk(os.path.join(self.tmp, "s3.apk"), scheme="v3")),
        ):
            from masanalyzer.android.apk import load_apk

            info = load_apk(path)
            self.assertEqual(
                info.signer_fingerprints, [self.expected],
                f"{tag}: fingerprint must match the fixture cert",
            )

    def test_expired_fixture_surfaces_dates(self):
        from masanalyzer.android.apk import load_apk

        path = self._build("v2", expire=True)
        info = load_apk(path)
        ci = info.v2.cert_info
        self.assertEqual(ci["not_after"], "2020-03-01T00:00:00")

    @staticmethod
    def _build(scheme, expire):
        return build_v23_signed_apk(
            os.path.join(tempfile.mkdtemp(prefix="masan_id2_"), "a.apk"),
            scheme=scheme,
            expired_cert=expire,
        )


class CertQualityRuleTests(unittest.TestCase):
    """MAS-SUP-013 (expired/expiring) + MAS-SUP-014 (weak key)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_quality_")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _rule_ids(ci):
        from masanalyzer.analysis import m02
        from masanalyzer.android.apk import ApkInfo, ApkSigner
        from masanalyzer.model import Target

        apk = ApkInfo(path="x.apk", name="x.apk")
        apk.v2 = ApkSigner(
            scheme="v2", names=["signer"], blob=b"",
            cert_sha256="a" * 64, cert_info=ci,
        )
        target = Target(
            input_path="x.apk", platform="android", work_dir=".", name="x.apk"
        )
        target.meta["apk"] = apk
        return {f.rule_id for f in m02.analyze(target)}

    def test_expired_fires(self):
        ids = self._rule_ids(
            {"not_after": "2020-03-01T00:00:00", "subject": "S",
             "key_algorithm": "rsa", "key_bits": 3072}
        )
        self.assertIn("MAS-SUP-013", ids)
        self.assertNotIn("MAS-SUP-014", ids)

    def test_soon_expiring_fires(self):
        soon = (_dt.datetime.now() + _dt.timedelta(days=30)).isoformat()
        ids = self._rule_ids(
            {"not_after": soon, "subject": "S",
             "key_algorithm": "rsa", "key_bits": 3072}
        )
        self.assertIn("MAS-SUP-013", ids)

    def test_healthy_cert_silent(self):
        far = (_dt.datetime.now() + _dt.timedelta(days=400)).isoformat()
        ids = self._rule_ids(
            {"not_after": far, "subject": "S",
             "key_algorithm": "rsa", "key_bits": 3072}
        )
        self.assertNotIn("MAS-SUP-013", ids)
        self.assertNotIn("MAS-SUP-014", ids)

    def test_weak_key_fires(self):
        ids = self._rule_ids(
            {"not_after": (_dt.datetime.now() + _dt.timedelta(days=400)).isoformat(),
             "subject": "S", "key_algorithm": "rsa", "key_bits": 1023}
        )
        self.assertIn("MAS-SUP-014", ids)

    def test_missing_cert_info_silent(self):
        # cert_info absent (unrecoverable) -> no crash, no fake findings
        ids = self._rule_ids(None)
        self.assertNotIn("MAS-SUP-013", ids)
        self.assertNotIn("MAS-SUP-014", ids)

    def test_end_to_end_fixture_rules(self):
        from masanalyzer.scanner import scan

        apk = build_v23_signed_apk(
            os.path.join(self.tmp, "expired2.apk"), scheme="v2", expired_cert=True
        )
        ids = {f.rule_id for f in scan(apk).findings}
        self.assertIn("MAS-SUP-013", ids)
        self.assertIn("MAS-SUP-014", ids)


class VerifyIdentityCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_verifyid_")
        cls.apk = build_signed_apk(os.path.join(cls.tmp, "app.apk"))

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_match_returns_zero(self):
        from masanalyzer.cli import main

        rc = main([
            self.apk, "--format", "json", "-q",
            "-o", os.path.join(self.tmp, "out_ok"),
            "--verify-identity", self._pretty(self._fp()),
        ])
        self.assertEqual(rc, 0)

    def test_mismatch_returns_one(self):
        from masanalyzer.cli import main

        rc = main([
            self.apk, "--format", "json", "-q",
            "-o", os.path.join(self.tmp, "out_bad"),
            "--verify-identity", "ab" * 32,
        ])
        self.assertEqual(rc, 1)

    def _fp(self):
        return hashlib.sha256(cert_der_for_rsa(rsa_keypair())).hexdigest()

    @staticmethod
    def _pretty(fp: str) -> str:
        return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


if __name__ == "__main__":
    unittest.main()

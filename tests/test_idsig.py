"""APK v4 ``.idsig`` sidecar parsing + MAS-SUP-015."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.apksigv4 import (
    IdsigError,
    cross_check,
    find_idsig_path,
    parse_idsig,
)
from masanalyzer.testing import (
    build_idsig,
    build_v23_signed_apk,
    cert_der_for_rsa,
    rsa_keypair,
)


class ParseIdsigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masan_idsig_")
        self.cert = cert_der_for_rsa(rsa_keypair())
        self.fp = hashlib.sha256(self.cert).hexdigest()
        self.path = build_idsig(
            os.path.join(self.tmp, "app.apk.idsig"), self.cert, apk_size=123456
        )

    def test_header_parsed(self):
        info = parse_idsig(self.path, apk_size=123456)
        self.assertEqual(info.version, 1)
        self.assertEqual(info.chunk_size, 4096)
        self.assertEqual(info.cert_sha256, self.fp)
        self.assertTrue(info.tree_shape_ok)

    def test_bad_magic_rejected(self):
        bad = os.path.join(self.tmp, "broken.idsig")
        with open(bad, "wb") as fh:
            fh.write(b"NOPE!" + b"\x00" * 80)
        with self.assertRaises(IdsigError):
            parse_idsig(bad)

    def test_tree_shape_mismatch_flagged(self):
        # sidecar generated for a tiny apk but scanned against a huge one
        path = build_idsig(
            os.path.join(self.tmp, "bigger.apk.idsig"), self.cert, apk_size=1024
        )
        info = parse_idsig(path, apk_size=99_999_999)
        self.assertFalse(info.tree_shape_ok)

    def test_sidecar_lookup(self):
        self.assertEqual(find_idsig_path(self.path[:-6] + ".apk"), self.path)
        self.assertIsNone(find_idsig_path(os.path.join(self.tmp, "none.apk")))

    def test_cross_check_match_and_mismatch(self):
        info = parse_idsig(self.path, apk_size=123456)
        self.assertTrue(cross_check(info, [self.fp]).signer_match)
        self.assertFalse(cross_check(info, ["ff" * 32]).signer_match)
        self.assertIsNone(cross_check(info, []).signer_match)


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_idsig_rule_")

    def _scan_with_sidecar(self, sidecar_cert, apk_size=64_000):
        key = rsa_keypair()
        cert = cert_der_for_rsa(key)
        apk = build_v23_signed_apk(os.path.join(self.tmp, "app.apk"))
        build_idsig(
            apk + ".idsig", sidecar_cert, apk_size=os.path.getsize(apk)
        )
        from masanalyzer.scanner import scan

        return scan(apk)

    def test_matching_sidecar_is_silent(self):
        key = rsa_keypair()
        res = self._scan_with_sidecar(self._sidecar_cert())
        ids = {f.rule_id for f in res.findings}
        self.assertNotIn("MAS-SUP-015", ids)
        idsig = res.target.meta["idsig"]
        self.assertTrue(idsig["signer_match"])

    def test_mismatched_sidecar_fires(self):
        from masanalyzer.testing import cert_der_for_rsa as _c, rsa_keypair as _r

        other = _c(_r(seed=777))
        res = self._scan_with_sidecar(other)
        ids = {f.rule_id for f in res.findings}
        self.assertIn("MAS-SUP-015", ids)
        hits = [f for f in res.findings if f.rule_id == "MAS-SUP-015"]
        self.assertIn("does not match", hits[0].evidence.note)

    def _sidecar_cert(self):
        return cert_der_for_rsa(rsa_keypair())

    def test_rule_catalog_grew(self):
        from masanalyzer.analysis import rule_catalog

        self.assertIn(
            "MAS-SUP-015", {r.rule_id for r in rule_catalog()}
        )


class EndToEndScanSidecar(unittest.TestCase):
    def test_scan_apk_with_sidecar_meta(self):
        tmp = tempfile.mkdtemp(prefix="masan_idsig_e2e_")
        cert = cert_der_for_rsa(rsa_keypair())
        fp = hashlib.sha256(cert).hexdigest()
        apk = build_v23_signed_apk(os.path.join(tmp, "an_app.apk"))
        build_idsig(apk + ".idsig", cert, apk_size=os.path.getsize(apk))
        from masanalyzer.scanner import scan

        res = scan(apk)
        meta = res.target.meta.get("idsig") or {}
        self.assertEqual(meta.get("cert_sha256"), fp)
        self.assertIs(meta.get("signer_match"), True)


if __name__ == "__main__":
    unittest.main()

"""IOC / threat-intel mode (masanalyzer.iocs, --intel)."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.iocs import (
    IntelBundle,
    classify_token,
    load_intel,
    parse_intel_file,
)
from masanalyzer.testing import build_dex, manifest_axml

IOC_FILE = """\
# generated test intel
evil-c2.testexample.net
https://phish.testexample.net/payload
198.51.100.77
# digest of assets/evil.bin computed at build time
3a6bc9e4c7adec7ae5d4a92dd4a3a5b6c93fb3d33ba2c40ef5f3e4b0bcef1100
not-an-indicator!!
127.0.0.1
"""


def _apk(tmp: str) -> str:
    """Fixture APK with every indicator class represented."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(
            "AndroidManifest.xml",
            manifest_axml("com.example.testapp", "1.0"),
        )
        z.writestr("classes.dex", build_dex(strings=(
            b"Lcom/example/testapp/MainActivity;",
            b"https://api.testapp.com/v1/login?x=1",
            b"evil-c2.testexample.net",
        )))
        z.writestr("assets/config.json", '"callback": "198.51.100.77"')
        # content of this file hashes to the sha256 token in IOC_FILE
        z.writestr("assets/evil.bin", b"\x00\x01confirm-intel-content\x00")
    path = os.path.join(tmp, "iocs.apk")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


def _evil_bin_digest(parser: str = "sha256"):
    import hashlib

    return hashlib.sha256(b"\x00\x01confirm-intel-content\x00").hexdigest()


class ParseTests(unittest.TestCase):
    def _write(self, text: str) -> str:
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "iocs.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_parse_buckets_and_errors(self):
        by_type, errors = parse_intel_file(self._write(IOC_FILE))
        self.assertIn("evil-c2.testexample.net", by_type["domain"])
        self.assertIn("phish.testexample.net", by_type["domain"])
        self.assertEqual(by_type["ip"], ["198.51.100.77", "127.0.0.1"])
        self.assertEqual(len(by_type["hash"]), 1)
        self.assertTrue(any("not-an-indicator" in e for e in errors))

    def test_prefix_form(self):
        # 58 'a' + 'beefbe' = a valid 64-hex sha256 token after the prefix
        _, errors = parse_intel_file(
            self._write("host:42.3.9.1\nsha256:beefbe" + "a" * 58 + "\n")
        )
        self.assertEqual(errors, [])

    def test_classify_token_table(self):
        self.assertEqual(classify_token("10.0.0.1"), "ip")
        self.assertEqual(classify_token("192.168.99.300"), None)  # bad range
        self.assertEqual(classify_token("example.exampleapp.io"), "domain")
        self.assertEqual(classify_token("https://example.exampleapp.io/x"), "domain")
        self.assertEqual(classify_token("a" * 64), "hash")
        self.assertEqual(classify_token("A" * 40), "hash")
        self.assertEqual(classify_token("a" * 33), None)
        self.assertEqual(classify_token("-not-really-.c"), None)


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_intel_")
        cls.apk = _apk(cls.tmp)
        cls.bundle = load_intel(_write_intel(cls.tmp, IOC_FILE.replace(
            "3a6bc9e4c7adec7ae5d4a92dd4a3a5b6c93fb3d33ba2c40ef5f3e4b0bcef1100",
            _evil_bin_digest(),
        )))
        from masanalyzer.scanner import scan

        cls.res = scan(cls.apk, intel=cls.bundle)

    def test_network_hits(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("CUSTOM-IOC-NETWORK-INDICATOR", ids)
        symbols = {f.evidence.symbol for f in self.res.findings
                   if f.rule_id == "CUSTOM-IOC-NETWORK-INDICATOR"}
        self.assertTrue(any("evil-c2.testexample.net" in s for s in symbols), symbols)
        self.assertTrue(any("198.51.100.77" in s for s in symbols), symbols)

    def test_digest_hit(self):
        hits = [f for f in self.res.findings
                if f.rule_id == "CUSTOM-IOC-DIGEST"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].evidence.file, "assets/evil.bin")
        self.assertIn("sha256", hits[0].evidence.note)

    def test_intel_tag_present(self):
        for f in self.res.findings:
            if f.rule_id.startswith("CUSTOM-IOC"):
                self.assertIn("intel", f.tags)

    def test_inactive_intel_no_findings(self):
        bundle = IntelBundle({"domain": [], "ip": [], "hash": []}, [])
        self.assertFalse(bundle.active)
        from masanalyzer.scanner import scan

        res2 = scan(self.apk, intel=bundle)
        self.assertFalse(
            any(f.rule_id.startswith("CUSTOM-IOC") for f in res2.findings)
        )


def _write_intel(tmp: str, text: str) -> str:
    path = os.path.join(tmp, "intel.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class CliTests(unittest.TestCase):
    def test_cli_intel_scan(self):
        from masanalyzer.cli import main

        tmp = tempfile.mkdtemp(prefix="masan_intel_cli_")
        apk = _apk(tmp)
        intel_path = os.path.join(tmp, "intel.txt")
        with open(intel_path, "w", encoding="utf-8") as fh:
            fh.write(IOC_FILE.replace(
                "3a6bc9e4c7adec7ae5d4a92dd4a3a5b6c93fb3d33ba2c40ef5f3e4b0bcef1100",
                _evil_bin_digest(),
            ))
        out = os.path.join(tmp, "out")
        rc = main([apk, "-o", out, "--format", "json", "-q", "--intel", intel_path])
        self.assertEqual(rc, 0)
        doc = json.load(open(os.path.join(out, "report.json"), encoding="utf-8"))
        rids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("CUSTOM-IOC-NETWORK-INDICATOR", rids)
        self.assertIn("CUSTOM-IOC-DIGEST", rids)


if __name__ == "__main__":
    unittest.main()

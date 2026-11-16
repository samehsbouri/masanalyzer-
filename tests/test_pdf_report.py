"""PDF report (reporting.pdf_report): deterministic stdlib-only writer."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.reporting import FORMATS, render  # noqa: E402
from masanalyzer.reporting.pdf_report import render_pdf  # noqa: E402
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import bank_dex, manifest_plain  # noqa: E402


def _apk(tmp: str) -> str:
    path = os.path.join(tmp, "pdf.apk")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml",
                   manifest_plain("com.example.pdf", "1.0"))
        z.writestr("classes.dex", bank_dex())
    return path


class PdfFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_pdf_")
        cls.result = scan(_apk(cls.tmp), progress=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_registered_as_a_format(self):
        self.assertIn("pdf", FORMATS)
        # alias dispatch works
        self.assertEqual(render(self.result, "pdf"), render_pdf(self.result))

    def test_returns_pdf_bytes(self):
        pdf = render(self.result, "pdf")
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-1.4\n"))
        self.assertTrue(pdf.rstrip().endswith(b"%%EOF"))

    def test_deterministic_bytes(self):
        self.assertEqual(
            render_pdf(self.result), render_pdf(self.result))

    def test_valid_xref_offsets(self):
        import re

        pdf = render_pdf(self.result)
        xref_pos = int(re.search(rb"startxref\s+(\d+)", pdf).group(1))
        self.assertTrue(pdf[xref_pos:].startswith(b"xref"))
        table = pdf[xref_pos:pdf.index(b"trailer")].decode("latin-1")
        for line in table.splitlines():
            if line.endswith("n ") and len(line) == 20:
                off = int(line[:10])
                expect = f"{line[12:14].strip()} 0 obj".encode()
                self.assertEqual(pdf[off:off + len(expect)], expect)

    def test_content_carries_findings_and_escapes(self):
        pdf = render_pdf(self.result)
        body = pdf.decode("latin-1")
        self.assertIn("Mobile App Security Report", body)
        self.assertIn("Severity breakdown", body)
        # every finding's rule id appears, worst severity first
        rule_ids = [f.rule_id for f in self.result.findings]
        positions = [body.index(rid) for rid in rule_ids]
        self.assertEqual(positions, sorted(positions))
        # severity chips + grouped headers are drawn as colored text
        self.assertIn("CRITICAL", body)
        # parentheses inside app-controlled strings are escaped, never raw
        self.assertIn("\\(", body)
        self.assertIn("\\)", body)

    def test_non_latin1_transliterated(self):
        """Hostile unicode cannot break the byte layout."""

        class FakeTarget:
            platform = "android"
            input_path = "x.apk"
            package = "com.example.badge-\u2713\u274c"
            name = ""
            files = []
            manifest = None
            meta = {}

        result = type("R", (), {})()
        result.target = FakeTarget()
        result.findings = []
        result.score = None
        result.tool = {"name": "masanalyzer", "version": "1"}
        result.finished = "2026-01-01"
        result.analyzers_run = 1
        result.analyzers_failed = []
        result.duration_s = 0.1
        pdf = render_pdf(result)
        self.assertTrue(pdf.startswith(b"%PDF-1.4\n"))
        self.assertIn(b"badge-??", pdf)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

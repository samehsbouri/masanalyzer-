"""CSV renderer + serve/watch ergonomics (masanalyzer.watchserver)."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import csv as _csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _apk():
    tmp = tempfile.mkdtemp(prefix="masan_csv_")
    from masanalyzer.scanner import scan
    from masanalyzer.testing import build_signed_apk

    return scan(build_signed_apk(os.path.join(tmp, "a.apk")))


class CsvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = _apk()

    def test_registered(self):
        from masanalyzer.reporting import FORMATS, render

        self.assertIn("csv", FORMATS)
        text = render(self.res, "csv")
        rows = list(_csv.reader(io.StringIO(text)))
        header = rows[0]
        self.assertIn("rule_id", header)
        self.assertIn("severity", header)
        # one data row per finding
        self.assertEqual(len(rows) - 1, len(self.res.findings))

    def test_columns_align(self):
        from masanalyzer.reporting import render

        text = render(self.res, "csv")
        rows = list(_csv.reader(io.StringIO(text)))
        width = len(rows[0])
        for r in rows:
            self.assertEqual(len(r), width)

    def test_extension(self):
        from masanalyzer.cli import _ext_for

        self.assertEqual(_ext_for("csv"), "csv")


class ServeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_serve_")
        res = _apk()
        from masanalyzer.reporting import render

        with open(os.path.join(cls.tmp, "report.html"), "w", encoding="utf-8") as fh:
            fh.write(render(res, "html"))

    def test_http_get_serves_report(self):
        from masanalyzer.watchserver import serve_reports

        server = serve_reports(self.tmp, port=0)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            import urllib.request
            import urllib.error

            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/report.html", timeout=5
                ) as resp:
                    body = resp.read().decode("utf-8", "replace")
                    self.assertIn("<", body)
            except urllib.error.URLError:
                self.skipTest("localhost loopback unavailable")
        finally:
            server.shutdown()
            server.server_close()
            t.join(2)


class WatchTests(unittest.TestCase):
    def test_watch_reruns_loop(self):
        tmp = tempfile.mkdtemp(prefix="masan_watch_")
        from masanalyzer.testing import build_signed_apk

        apk = build_signed_apk(os.path.join(tmp, "w.apk"))
        out = os.path.join(tmp, "out")

        from masanalyzer import watchserver

        seen = []
        rc = watchserver.watch(
            apk,
            out,
            interval=0.5,
            formats=["json"],
            max_iterations=2,
            on_change=seen.append,
        )
        self.assertEqual(rc, 2)
        self.assertEqual(len(seen), 2)
        report = os.path.join(out, "report.json")
        self.assertTrue(os.path.isfile(report))


if __name__ == "__main__":
    unittest.main()

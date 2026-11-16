"""Callsite-receipts table (the decompiled-code equivalent) in reports.

The receipts are exercised for extraction in test_callsites.py; here we
verify they reach the HTML / Markdown / JSON reports.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.reporting import render  # noqa: E402
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import build_dex, manifest_plain  # noqa: E402

URL = "https://api.example.com/v1/secret"

_STRINGS = [
    b"Lcom/example/receipts/Main;",      # 0 -> type 0 (owner)
    b"Landroid/webkit/WebView;",         # 1 -> type 1 (callee class)
    b"doLoad",                           # 2 (owner method name)
    b"loadUrl",                          # 3 (callee method name)
    URL.encode(),                        # 4 (the URL constant)
]


def _webview_dex() -> bytes:
    """One method: const-string URL -> invoke WebView#loadUrl -> receipt."""
    return build_dex(
        _STRINGS,
        types=[0, 1],
        classes=[0],
        methods=[(0, 2), (1, 3)],
        code={
            # const-string v0, URL ; invoke WebView#loadUrl ; return
            0: ((0 << 8 | 0x1A), 4, ((1 & 0xF) << 12) | 0x6E, 1, 0, 0x0011),
        },
    )


class ReceiptsInReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_receipts_")
        path = os.path.join(cls.tmp, "rc.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml",
                       manifest_plain("com.example.receipts", "1.0"))
            z.writestr("classes.dex", _webview_dex())
        cls.result = scan(path, progress=lambda *a: None)
        cls.receipts = cls.result.target.meta.get("callsites") or []

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_fixture_produced_a_receipt(self):
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.receipts[0]["url"], URL)
        self.assertEqual(self.receipts[0]["method"],
                         "com.example.receipts.Main#doLoad")

    def test_md_has_receipts_table(self):
        md = render(self.result, "md")
        self.assertIn("Network callsite receipts", md)
        self.assertIn(URL, md)
        self.assertIn("com.example.receipts.Main#doLoad", md)
        self.assertIn("Landroid/webkit/WebView;#loadUrl", md)

    def test_html_has_receipts_table(self):
        html = render(self.result, "html")
        self.assertIn("Network callsite receipts", html)
        self.assertIn(URL, html)

    def test_json_inventory_callsites(self):
        doc = json.loads(render(self.result, "json"))
        inv = doc["inventory"].get("callsites") or {}
        self.assertEqual(inv.get("total"), 1)
        self.assertEqual(inv["rows"][0]["url"], URL)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

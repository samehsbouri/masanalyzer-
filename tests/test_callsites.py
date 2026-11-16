"""DEX callsite receipts (Feature 5): build_dex bytecode fixtures, walker
behaviour, packaging wiring and the endpoint ``called_from`` attachment."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.dex import parse_dex  # noqa: E402
from masanalyzer.testing import build_apk, build_dex  # noqa: E402

URL = "https://api.insecurebank.example:8443/v2/login"

# fixture string table: 0/1 type descriptors, 2/3 names, 4 the URL constant
CS_STRINGS = (
    b"Lcom/example/insecurebank/LoginActivity;",
    b"Landroid/webkit/WebView;",
    b"doLogin",
    b"loadUrl",
    URL.encode(),
)


def _invoke35(method_idx: int, *regs: int) -> tuple:
    """invoke-virtual {regs...}, method@idx (op 0x6E, format 35c)."""
    count = len(regs)
    pack = 0
    for i, reg in enumerate(regs[:4]):
        pack |= (reg & 0xF) << (i * 4)
    hi = 0
    if count >= 5:
        hi = (regs[4] & 0xF) << 8     # G nibble rides in unit 0
    return ((count & 0xF) << 12) | hi | 0x6E, method_idx & 0xFFFF, pack


def _invoke3rc(method_idx: int, first: int, count: int) -> tuple:
    """invoke-virtual-range (op 0x74, format 3rc)."""
    return (count & 0xFF) << 8 | 0x74, method_idx & 0xFFFF, first & 0xFFFF


def _const_string(reg: int, string_idx: int) -> tuple:
    """const-string vX, string@idx (op 0x1A, opcode in the low byte)."""
    return (reg & 0xFF) << 8 | 0x1A, string_idx & 0xFFFF


def _move_object(dst: int, src: int) -> tuple:
    """move-object vA, vB (op 0x07, format 12x)."""
    return ((src & 0xF) << 12 | (dst & 0xF) << 8 | 0x07,)


RETURN_OBJECT = (0x0011,)   # return-object, format 11x


def _webview_dex() -> bytes:
    """One method: const-string URL -> invoke WebView#loadUrl -> receipt."""
    code = {
        0: _const_string(0, 4) + _invoke35(1, 0) + RETURN_OBJECT,
    }
    return build_dex(
        CS_STRINGS,
        types=[0, 1],
        classes=[0],
        methods=[(0, 2), (1, 3)],
        code=code,
    )


class WalkerReceipts(unittest.TestCase):
    """Receipt extraction on synthetic code fixtures."""

    def test_receipt_fields_35c(self):
        dex = parse_dex(_webview_dex())
        dex.analyze_callsites()
        self.assertEqual(len(dex.callsites), 1)
        rec = dex.callsites[0]
        self.assertEqual(
            rec["method"], "com.example.insecurebank.LoginActivity#doLogin"
        )
        self.assertEqual(rec["url"], URL)
        self.assertEqual(rec["callee"], "Landroid/webkit/WebView;#loadUrl")
        self.assertGreater(rec["offset"], 0)
        self.assertEqual(dex.callsite_stats["derailed"], 0)
        self.assertGreater(dex.callsite_stats["aligned"], 0)

    def test_analyze_callsites_idempotent(self):
        dex = parse_dex(_webview_dex())
        dex.analyze_callsites()
        first = list(dex.callsites)
        dex.analyze_callsites()
        self.assertEqual(dex.callsites, first)

    def test_receipt_3rc_range_invoke(self):
        # const-string v4, URL; invoke-virtual-range {v4}, WebView#loadUrl
        code = {
            0: _const_string(4, 4) + _invoke3rc(1, 4, 1) + RETURN_OBJECT,
        }
        raw = build_dex(
            CS_STRINGS,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code=code,
        )
        dex = parse_dex(raw)
        dex.analyze_callsites()
        self.assertTrue(dex.callsites, "3rc invoke must pair the URL register")
        self.assertEqual(dex.callsites[0]["url"], URL)

    def test_move_object_propagation(self):
        # const-string v3, URL; move-object v5, v3; invoke-virtual {v5}
        code = {
            0: _const_string(3, 4) + _move_object(5, 3)
               + _invoke35(1, 5) + RETURN_OBJECT,
        }
        raw = build_dex(
            CS_STRINGS,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code=code,
        )
        dex = parse_dex(raw)
        dex.analyze_callsites()
        self.assertTrue(dex.callsites, "move-object must carry the URL along")
        self.assertEqual(dex.callsites[0]["url"], URL)

    def test_same_owner_url_callee_deduped(self):
        # two identical invokes -> one receipt for the (owner,url,callee) key
        code = {
            0: _const_string(0, 4) + _invoke35(1, 0)
               + _invoke35(1, 0) + RETURN_OBJECT,
        }
        raw = build_dex(
            CS_STRINGS,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code=code,
        )
        dex = parse_dex(raw)
        dex.analyze_callsites()
        self.assertEqual(len(dex.callsites), 1)

    def test_no_receipt_without_url(self):
        # const-string holding a non-URL token, still hitting loadUrl
        code = {
            0: _const_string(0, 3) + _invoke35(1, 0) + RETURN_OBJECT,
        }
        raw = build_dex(
            CS_STRINGS,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code=code,
        )
        dex = parse_dex(raw)
        dex.analyze_callsites()
        self.assertEqual(dex.callsites, [])

    def test_abstract_method_without_code_ok(self):
        # owner has no code_off entry -> walked as abstract, no crash
        raw = build_dex(
            CS_STRINGS,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code={1: RETURN_OBJECT},      # only the callee carries code
        )
        dex = parse_dex(raw)
        dex.analyze_callsites()
        self.assertEqual(dex.callsites, [])
        self.assertEqual(dex.callsite_stats["derailed"], 0)

    def test_limit_caps_receipts(self):
        # owner method with 2 receipts + limit=1 trims the second
        other = "https://stage.insecurebank.example/api"
        strings = list(CS_STRINGS)
        strings.append(other.encode())          # string idx 5
        code = {
            0: _const_string(0, 4) + _invoke35(1, 0)
               + _const_string(1, 5) + _invoke35(1, 1) + RETURN_OBJECT,
        }
        raw = build_dex(
            strings,
            types=[0, 1],
            classes=[0],
            methods=[(0, 2), (1, 3)],
            code=code,
        )
        dex = parse_dex(raw)
        self.assertEqual(len(dex.callsites), 0)     # not yet analyzed
        dex.analyze_callsites(limit=1)
        self.assertEqual(len(dex.callsites), 1)


class PackagingWiring(unittest.TestCase):
    """Full-scan pipeline: receipts land in meta + endpoint rows."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_callsites_")
        cls.apk = build_apk(
            os.path.join(cls.tmp, "app.apk"), dex=_webview_dex()
        )
        from masanalyzer.scanner import scan

        cls.result = scan(cls.apk)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_target_meta_receipts(self):
        receipts = self.result.target.meta.get("callsites") or []
        self.assertEqual(len(receipts), 1)
        rec = receipts[0]
        self.assertEqual(rec["dex"], "classes.dex")
        self.assertEqual(rec["url"], URL)
        self.assertIn("#loadUrl", rec["callee"])

    def test_target_meta_stats(self):
        stats = self.result.target.meta.get("callsite_stats") or {}
        dex_stats = stats.get("classes.dex") or {}
        self.assertGreaterEqual(dex_stats.get("methods", 0), 1)
        self.assertEqual(dex_stats.get("derailed", 0), 0)

    def test_endpoint_row_has_called_from(self):
        from masanalyzer.endpoints import build_inventory

        inv = build_inventory(self.result.target)
        host_rows = [
            r for r in inv["rows"] if r.get("host") == "api.insecurebank.example"
        ]
        self.assertTrue(host_rows, "URL constant must surface as an endpoint")
        callers = host_rows[0].get("called_from")
        self.assertTrue(callers, "receipt must attach calling methods")
        self.assertTrue(
            any("#doLogin" in c for c in callers), f"got {callers}"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

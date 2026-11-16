"""Behaviour analysis (behaviour.py) + the general invoke walker.

Quark-style rule IDs (BEH-xxx) with exact Android API matchers,
attributed to declaring methods via dex.DexFile.collect_api_calls.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.dex import parse_dex  # noqa: E402
from masanalyzer.behaviour import (  # noqa: E402
    BEHAVIOURS,
    behaviour_meta,
    match_callee,
)
from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import build_dex, manifest_plain  # noqa: E402


def _invoke35(method_idx: int, *regs: int) -> tuple:
    count = len(regs)
    pack = 0
    for i, reg in enumerate(regs[:4]):
        pack |= (reg & 0xF) << (i * 4)
    hi = 0
    if count >= 5:
        hi = (regs[4] & 0xF) << 8
    return ((count & 0xF) << 12) | hi | 0x6E, method_idx & 0xFFFF, pack


RETURN_OBJECT = (0x0011,)


def _runtime_dex() -> bytes:
    """App#doRun invokes Runtime#exec (BEH-001)."""
    return build_dex(
        strings=[
            b"Ljava/lang/Runtime;",      # 0 -> type 0
            b"exec",                     # 1
            b"Lcom/example/beh/App;",    # 2 -> type 1
            b"doRun",                    # 3
        ],
        types=[0, 2],
        classes=[1],
        methods=[(0, 1), (1, 3)],
        code={1: _invoke35(0, 0) + RETURN_OBJECT},
    )


def _benign_dex() -> bytes:
    """App#run invokes String#length - matches no behaviour rule."""
    return build_dex(
        strings=[
            b"Ljava/lang/String;",       # 0 -> type 0
            b"length",                   # 1
            b"Lcom/example/ben/App;",    # 2 -> type 1
            b"run",                      # 3
        ],
        types=[0, 2],
        classes=[1],
        methods=[(0, 1), (1, 3)],
        code={1: _invoke35(0, 0) + RETURN_OBJECT},
    )


class MatcherTests(unittest.TestCase):
    def test_runtime_exec_matches_beh_001(self):
        self.assertIn("BEH-001", match_callee("Ljava/lang/Runtime;#exec"))

    def test_star_matcher(self):
        self.assertIn("BEH-002",
                      match_callee("Ldalvik/system/DexClassLoader;#<init>"))

    def test_dollar_class(self):
        self.assertIn("BEH-014", match_callee(
            "Landroid/content/SharedPreferences$Editor;#putString"))

    def test_unknown_matches_nothing(self):
        self.assertEqual(match_callee("Ljava/lang/String;#length"), ())

    def test_malformed_matches_nothing(self):
        self.assertEqual(match_callee("no-hash-in-here"), ())
        self.assertEqual(match_callee(""), ())

    def test_all_rules_have_unique_ids(self):
        ids = [r.rule_id for r in BEHAVIOURS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(ids == sorted(ids))


class CollectApiCallsTests(unittest.TestCase):
    def test_receipt_attributed_to_declaring_method(self):
        dex = parse_dex(_runtime_dex())
        dex.relpath = "classes.dex"
        dex.collect_api_calls()
        self.assertEqual(len(dex.api_receipts), 1)
        rec = dex.api_receipts[0]
        self.assertEqual(rec["method"], "com.example.beh.App#doRun")
        self.assertEqual(rec["callee"], "Ljava/lang/Runtime;#exec")
        self.assertIn("offset", rec)
        self.assertEqual(dex.api_stats["derailed"], 0)
        self.assertEqual(dex.api_stats["invokes"], 1)
        self.assertEqual(dex.api_stats["aligned"], 1)

    def test_idempotent(self):
        dex = parse_dex(_runtime_dex())
        dex.relpath = "classes.dex"
        dex.collect_api_calls()
        first = list(dex.api_receipts)
        dex.collect_api_calls()
        self.assertEqual(dex.api_receipts, first)

    def test_match_filter_collects_nothing_for_benign(self):
        dex = parse_dex(_benign_dex())
        dex.relpath = "classes.dex"
        dex.collect_api_calls(match=lambda c: bool(match_callee(c)))
        self.assertEqual(dex.api_receipts, [])
        self.assertEqual(dex.api_stats["invokes"], 1)

    def test_match_none_collects_every_invoke(self):
        dex = parse_dex(_benign_dex())
        dex.relpath = "classes.dex"
        dex.collect_api_calls(match=None)
        self.assertEqual(len(dex.api_receipts), 1)
        self.assertEqual(dex.api_receipts[0]["callee"],
                         "Ljava/lang/String;#length")


class BehaviourMetaTests(unittest.TestCase):
    def test_meta_shape(self):
        dex = parse_dex(_runtime_dex())
        dex.relpath = "classes.dex"
        meta = behaviour_meta([dex])
        self.assertIn("BEH-001", {b["id"] for b in meta["behaviours"]})
        entry = meta["behaviours"][0]
        self.assertEqual(entry["receipts"], 1)
        self.assertEqual(entry["methods"], ["com.example.beh.App#doRun"])
        self.assertEqual(meta["total_receipts"], 1)
        self.assertEqual(meta["rows"][0]["dex"], "classes.dex")

    def test_unknown_api_not_claimed(self):
        dex = parse_dex(_benign_dex())
        dex.relpath = "classes.dex"
        self.assertEqual(behaviour_meta([dex]), {})

    def test_no_dex(self):
        self.assertEqual(behaviour_meta([]), {})


class BehaviourInScan(unittest.TestCase):
    """The behaviour layer rides the full packaging pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_behaviour_")
        path = os.path.join(cls.tmp, "beh.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml",
                       manifest_plain("com.example.beh", "1.0"))
            z.writestr("classes.dex", _runtime_dex())
        cls.result = scan(path, progress=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_meta_behaviour_present(self):
        meta = self.result.target.meta.get("behaviour") or {}
        ids = {b["id"] for b in meta.get("behaviours", [])}
        self.assertIn("BEH-001", ids)
        row = meta["rows"][0]
        self.assertEqual(row["method"], "com.example.beh.App#doRun")
        self.assertEqual(row["callee"], "Ljava/lang/Runtime;#exec")

    def test_json_report_carries_behaviour(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.result, "json"))
        inv = doc["inventory"].get("behaviour") or {}
        ids = {b["id"] for b in inv.get("behaviours", [])}
        self.assertIn("BEH-001", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

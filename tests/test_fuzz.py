"""Fuzz corpus: corrupted bundles must never crash the scanner.

The architectural promise is that every parser is defensive: a truncated,
byte-flipped, or randomly corrupted bundle is scanned to completion and
produces a result (possibly with no findings) - never an uncaught exception
and never an analyzer failure entry.
"""

from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.scanner import scan
from masanalyzer.testing import build_apk, build_ipa, build_v23_signed_apk


def _corpus(base: str) -> list:
    """Deterministic corrupt variants of valid fixtures."""
    rng = random.Random(20260101)
    out = []

    valid = {}
    valid["apk"] = build_apk(os.path.join(base, "valid.apk"))
    valid["apk23"] = build_v23_signed_apk(os.path.join(base, "valid_v23.apk"), scheme="v2")
    valid["ipa"] = build_ipa(os.path.join(base, "valid.ipa"))

    for tag, path in valid.items():
        blob = open(path, "rb").read()
        # truncations at fractions of the file
        for frac in (0.02, 0.25, 0.5, 0.9):
            p = os.path.join(base, f"trunc_{tag}_{int(frac * 100)}.apk")
            n = max(1, int(len(blob) * frac))
            with open(p, "wb") as fh:
                fh.write(blob[:n])
            out.append(p)
        # byte-flips at deterministic pseudo-random positions
        for i in range(4):
            p = os.path.join(base, f"flip_{tag}_{i}.apk")
            corrupt = bytearray(blob)
            for _ in range(8):
                pos = rng.randrange(len(corrupt))
                corrupt[pos] ^= rng.randrange(1, 256)
            with open(p, "wb") as fh:
                fh.write(bytes(corrupt))
            out.append(p)
        # garbage suffix appended (hostile trailing data)
        p = os.path.join(base, f"tail_{tag}.apk")
        with open(p, "wb") as fh:
            fh.write(blob + os.urandom(4096))
        out.append(p)
        # empty and minimal files
        for name in (f"empty_{tag}",):
            p = os.path.join(base, f"{name}.bin")
            open(p, "wb").close()
            out.append(p)
    return out


class FuzzCorpusTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_fuzz_")
        cls.artifacts = _corpus(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_variant_completes(self):
        failures = []
        for path in self.artifacts:
            try:
                result = scan(path, keep_work_dir=False)
                self.assertEqual(result.analyzers_failed, [])
            except Exception as exc:                     # noqa: BLE001
                failures.append(f"{os.path.basename(path)}: {exc!r}")

        self.assertEqual(
            failures, [], "corrupted inputs must not abort the scan"
        )

    def test_corruption_never_crashes_apk_module(self):
        """Direct hit on the signing block locator and ZIP layout walker."""
        from masanalyzer.android import apk as apk_mod

        for path in self.artifacts:
            try:
                blob = open(path, "rb").read()
                apk_mod._zip_layout_anomalies(blob, blob.rfind(b"PK\x05\x06"))
                apk_mod.load_apk_unsafe(blob) if hasattr(
                    apk_mod, "load_apk_unsafe"
                ) else None
            except Exception as exc:                     # noqa: BLE001
                self.fail(f"{os.path.basename(path)} helpers raised: {exc!r}")


if __name__ == "__main__":
    unittest.main()

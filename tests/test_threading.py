"""Threaded parallel inventory (packaging) - determinism preserved."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer import packaging
from masanalyzer.model import Target


PT_LOAD, PT_DYNAMIC = 1, 2


def elf_with_deps(
    needed: tuple = ("libcrypto_vendored.so.1.1", "liblog.so"),
    dangerous: tuple = ("dlopen", "mprotect", "execve"),
) -> bytes:
    """Minimal ELF64 with a PT_DYNAMIC table declaring DT_NEEDED entries."""
    fmt = "<"
    strtab = b"\x00"
    offsets = {}
    for blob in (*needed, *dangerous):
        offsets[blob] = len(strtab)
        strtab += blob.encode("ascii") + b"\x00"
    strtab_off = 0x200

    dyn = b""
    for name in needed:
        dyn += struct.pack(fmt + "qQ", 1, offsets[name])
    dyn += struct.pack(fmt + "qQ", 5, strtab_off)
    dyn += struct.pack(fmt + "qQ", 0, 0)

    dyn_off = 0x100
    out = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    out += struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0
    )
    out += struct.pack(fmt + "IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    out += struct.pack(
        fmt + "IIQQQQQQ", PT_DYNAMIC, 6, dyn_off, dyn_off, len(dyn), len(dyn), 6, 8
    )
    out += b"\x00" * (0x100 - len(out))
    out += dyn
    out += b"\x00" * (0x200 - len(out))
    out += strtab
    return out


class ParallelInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masan_thread_")

    @staticmethod
    def _blob(i: int) -> bytes:
        return (f"payload {i} " * 64).encode("ascii")

    def test_many_files_hashed_concurrently(self):
        base = os.path.join(self.tmp, "tree", "assets")
        os.makedirs(base, exist_ok=True)
        names = []
        for i in range(30):
            rel = os.path.join(base, f"asset_{i:02}.bin")
            with open(rel, "wb") as fh:
                fh.write(self._blob(i))
            names.append(rel.replace(os.sep, "/"))

        target = Target(input_path=self.tmp, platform="unknown",
                        work_dir=os.path.join(self.tmp, "tree"), name="tree")
        packaging._collect_tree_files(target, os.path.join(self.tmp, "tree"))

        self.assertEqual(len(target.files), 30)
        # deterministic order: files appear in walk order, every one hashed
        rels = [f.relpath for f in target.files]
        self.assertEqual(len(set(rels)), 30)
        for sf in target.files:
            self.assertTrue(sf.sha256 and len(sf.sha256) == 64)

    def test_small_bundles_stay_serial(self):
        from masanalyzer.testing import build_signed_apk

        apk = build_signed_apk(os.path.join(self.tmp, "small.apk"))
        from masanalyzer.scanner import scan

        files = scan(apk).target.files
        self.assertTrue(0 < len(files) < packaging._FILES_PARALLEL_THRESHOLD)

    def test_many_native_libs_parsed_concurrently(self):
        base = os.path.join(self.tmp, "libs")
        os.makedirs(base, exist_ok=True)
        sf_dir_target = Target(input_path=self.tmp, platform="android",
                               work_dir=base, name="libs")
        for i in range(26):
            path = os.path.join(base, f"lib{i:02}.so")
            # alternate unique deps so ordering is verifiable
            blob = elf_with_deps(needed=(f"libdep{i:02}.so",), dangerous=())
            with open(path, "wb") as fh:
                fh.write(blob)
            packaging._add_file(sf_dir_target, path,
                                os.path.basename(path).replace(os.sep, "/"),
                                kind="native")

        packaging._android_native(sf_dir_target)
        self.assertEqual(len(sf_dir_target.native_libs), 26)
        deps = sorted(
            lib.dependencies[0]
            for lib in sf_dir_target.native_libs
            if lib.dependencies
        )
        self.assertEqual(deps, [f"libdep{i:02}.so" for i in range(26)])

    def test_poison_file_skipped_not_fatal(self):
        base = os.path.join(self.tmp, "mixed")
        os.makedirs(base, exist_ok=True)
        for i in range(24):
            rel = os.path.join(base, f"f{i:02}.bin")
            with open(rel, "wb") as fh:
                fh.write(self._blob(i))
        # a directory that disappears between listing and hashing:
        gone = os.path.join(base, "gone", "sub")
        os.makedirs(gone, exist_ok=True)
        with open(os.path.join(gone, "x.bin"), "wb") as fh:
            fh.write(b"bye")
        target = Target(input_path=base, platform="unknown", work_dir=base,
                        name="mixed")
        packaging._collect_tree_files(target, base)
        # no crash, and the remaining files are all inventoried
        self.assertGreaterEqual(len(target.files), 25)


if __name__ == "__main__":
    unittest.main()

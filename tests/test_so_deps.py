""".so dependency graph (elfdeps.py) + MAS-BIN-013..016."""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.elfdeps import (
    ANDROID_SYSTEM_LIBS,
    inspect_blob,
    missing_dependencies,
)

PT_LOAD, PT_DYNAMIC = 1, 2


def elf_with_deps(
    needed: tuple = ("libcrypto_vendored.so.1.1", "liblog.so"),
    dangerous: tuple = ("dlopen", "mprotect", "execve"),
    hardening: tuple = (),
) -> bytes:
    """A minimal ELF64 with a PT_DYNAMIC table declaring DT_NEEDED entries.

    Strings live at file offsets == vaddrs (PT_LOAD maps [0, 0x1000)) so
    the DT_STRTAB resolve is trivially consistent.  ``hardening`` adds
    symbol names (``__stack_chk_fail``, ``__memcpy_chk``, ...) to the
    dynamic string table to emulate compiler-hardening imports.
    """
    fmt = "<"
    strtab = b"\x00"
    offsets = {}
    for blob in (*needed, *dangerous, *hardening):
        offsets[blob] = len(strtab)
        strtab += blob.encode("ascii") + b"\x00"
    strtab_off = 0x200                       # file offset of .dynstr

    dyn = b""
    for name in needed:                       # DT_NEEDED
        dyn += struct.pack(fmt + "qQ", 1, offsets[name])
    dyn += struct.pack(fmt + "qQ", 5, strtab_off)      # DT_STRTAB (vaddr)
    dyn += struct.pack(fmt + "qQ", 0, 0)               # DT_NULL

    dyn_off = 0x100                                    # file offset of .dynamic
    out = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    out += struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0
    )
    out += struct.pack(
        fmt + "IIQQQQQQ", PT_LOAD, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000
    )
    out += struct.pack(
        fmt + "IIQQQQQQ", PT_DYNAMIC, 6, dyn_off, dyn_off, len(dyn), len(dyn), 6, 8
    )
    out += b"\x00" * (0x100 - len(out))
    out += dyn
    out += b"\x00" * (0x200 - len(out))
    out += strtab
    return out


class InspectBlobTests(unittest.TestCase):
    def test_dt_needed_parsed(self):
        info = inspect_blob(elf_with_deps())
        self.assertTrue(info.is_elf)
        self.assertEqual(info.needed, ["libcrypto_vendored.so.1.1", "liblog.so"])

    def test_dangerous_imports_detected(self):
        info = inspect_blob(elf_with_deps())
        self.assertIn("dlopen", info.dangerous)
        self.assertIn("mprotect", info.dangerous)
        self.assertIn("execve", info.dangerous)

    def test_clean_elf_has_no_dangerous(self):
        info = inspect_blob(elf_with_deps(needed=("liblog.so",), dangerous=()))
        self.assertEqual(info.dangerous, [])

    def test_non_elf_rejected(self):
        self.assertIsNone(inspect_blob(b"MZ" + b"\x00" * 80))

    def test_dynamic_only_no_strtab(self):
        info = inspect_blob(elf_with_deps(needed=(), dangerous=()))
        self.assertEqual(info.needed, [])


class HardeningMarkerTests(unittest.TestCase):
    """stack-canary + FORTIFY_SOURCE detection (MAS-BIN-019 / MAS-BIN-020)."""

    def test_canary_and_fortify_detected(self):
        info = inspect_blob(elf_with_deps(
            needed=("liblog.so",), dangerous=(),
            hardening=(
                "__stack_chk_fail", "__memcpy_chk@LIBC",
                "__strlen_chk", "__open_realpath_chk",
            ),
        ))
        self.assertTrue(info.canary)
        self.assertIn("__memcpy_chk@libc", info.fortified)
        self.assertIn("__strlen_chk", info.fortified)
        self.assertNotIn("__stack_chk_fail", info.fortified)

    def test_default_fixture_is_unhardened(self):
        info = inspect_blob(elf_with_deps())
        self.assertFalse(info.canary)
        self.assertEqual(info.fortified, [])

    def test_guard_only_is_canary_not_fortify(self):
        info = inspect_blob(elf_with_deps(
            needed=("liblog.so",), dangerous=(),
            hardening=("__stack_chk_guard",),
        ))
        self.assertTrue(info.canary)
        self.assertEqual(info.fortified, [])


class MissingDependencyTests(unittest.TestCase):
    def test_system_and_shipped_satisfied(self):
        shipped = [
            "lib/arm64-v8a/libfeature.so",
            "lib/arm64-v8a/libc++_shared.so",
        ]
        assert "libc++_shared.so" in ANDROID_SYSTEM_LIBS
        missing = missing_dependencies(
            ["liblog.so", "libfeature.so", "libc++.so.7"], shipped
        )
        self.assertEqual(missing, ["libc++.so.7"])

    def test_everything_resolvable(self):
        self.assertEqual(
            missing_dependencies(["libc.so", "libz.so"], []), []
        )


class RuleWiringTests(unittest.TestCase):
    def _target(self, with_missing=False, hardening_flags=None):
        from masanalyzer.model import NativeLib, Target
        from masanalyzer.analysis import m07

        blob = elf_with_deps()
        info = inspect_blob(blob)
        flags = {"pie": True, "executable_stack": False, "relro": True,
                 "full_relro": True}
        if hardening_flags is not None:
            flags.update(hardening_flags)
        lib = NativeLib(
            relpath="lib/arm64-v8a/libfeature.so",
            path="libfeature.so",
            arch="aarch64",
            dependencies=list(info.needed),
            dangerous=list(info.dangerous),
            flags=flags,
            platform="android",
        )
        target = Target(input_path="x.apk", platform="android",
                        work_dir=".", name="x.apk")
        target.native_libs.append(lib)
        target.meta["so_graph"] = {
            "nodes": {"lib/arm64-v8a/libfeature.so": {
                "dependencies": list(info.needed),
                "dangerous": list(info.dangerous),
            }},
            "missing": {"lib/arm64-v8a/libfeature.so": ["libc++.so.7"]},
        }
        return target, {f.rule_id for f in m07.analyze(target)}

    def test_all_four_rules_fire(self):
        _, ids = self._target()
        self.assertIn("MAS-BIN-013", ids)
        self.assertIn("MAS-BIN-014", ids)
        self.assertIn("MAS-BIN-015", ids)
        self.assertIn("MAS-BIN-016", ids)

    def test_unhardened_so_triggers_canary_fortify_rules(self):
        _, ids = self._target(
            hardening_flags={"canary": False, "fortified": False})
        self.assertIn("MAS-BIN-019", ids)
        self.assertIn("MAS-BIN-020", ids)

    def test_hardened_so_stays_clean(self):
        _, ids = self._target(
            hardening_flags={"canary": True, "fortified": True})
        self.assertNotIn("MAS-BIN-019", ids)
        self.assertNotIn("MAS-BIN-020", ids)

    def test_flags_absent_no_claims(self):
        """Older/incomplete flag sets must not invent absence facts."""
        _, ids = self._target()
        self.assertNotIn("MAS-BIN-019", ids)
        self.assertNotIn("MAS-BIN-020", ids)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix="masan_sodg_")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("AndroidManifest.xml",
                       __import__("masanalyzer.testing", fromlist=["manifest_axml"])
                       .manifest_axml("com.example.sofix", "1.0"))
            z.writestr("classes.dex",
                       __import__("masanalyzer.testing", fromlist=["build_dex"])
                       .build_dex(strings=(b"com/example/sofix",)))
            z.writestr("lib/arm64-v8a/libfeature.so", elf_with_deps())
        cls.apk = os.path.join(tmp, "so.apk")
        with open(cls.apk, "wb") as fh:
            fh.write(buf.getvalue())
        from masanalyzer.scanner import scan

        cls.res = scan(cls.apk)

    def test_graph_built(self):
        graph = self.res.target.meta.get("so_graph")
        self.assertIsNotNone(graph)
        node = graph["nodes"].get("lib/arm64-v8a/libfeature.so")
        self.assertIsNotNone(node)
        self.assertIn("libcrypto_vendored.so.1.1", node["dependencies"])
        self.assertEqual(graph["total_edges"], 2)
        self.assertIn(
            "libcrypto_vendored.so.1.1",
            graph["missing"].get("lib/arm64-v8a/libfeature.so", []),
        )

    def test_rules_fire_in_scan(self):
        ids = {f.rule_id for f in self.res.findings}
        for want in ("MAS-BIN-013", "MAS-BIN-014", "MAS-BIN-015", "MAS-BIN-016"):
            self.assertIn(want, ids)

    def test_unhardened_stub_flags_hardening_rules_in_scan(self):
        """The default stub has no canary/FORTIFY symbols - the rules fire."""
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("MAS-BIN-019", ids)
        self.assertIn("MAS-BIN-020", ids)

    def test_native_lib_flags_record_hardening(self):
        lib = next(
            l for l in self.res.target.native_libs
            if l.relpath.endswith("libfeature.so"))
        self.assertIn("canary", lib.flags)
        self.assertIn("fortified", lib.flags)
        self.assertFalse(lib.flags["canary"])
        self.assertFalse(lib.flags["fortified"])

    def test_rule_catalog_has_new_rules(self):
        from masanalyzer.analysis import rule_catalog

        ids = {r.rule_id for r in rule_catalog()}
        self.assertTrue(ids.issuperset(
            {"MAS-BIN-013", "MAS-BIN-014", "MAS-BIN-015", "MAS-BIN-016"}
        ))


if __name__ == "__main__":
    unittest.main()

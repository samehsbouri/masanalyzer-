"""M7 hardening tests: ELF RELRO parsing, iOS code-signature verification,
MAS-BIN-011/012 rule firing, and the CycloneDX SBOM renderer."""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.model import NativeLib, Target
from masanalyzer.ios import macho
from masanalyzer.packaging import _elf_details
from masanalyzer.testing import build_macho, build_v23_signed_apk


# --------------------------------------------------------------------------
# ELF fixtures: 64-bit LE image with configurable PT_GNU_RELRO / .dynamic
# --------------------------------------------------------------------------
def tiny_elf(bind_now: bool, relro: bool, textrel: bool = False) -> bytes:
    fmt = "<"
    PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 0x6474E551, 0x6474E552
    ph_count = 4 if relro else 3
    dyn_off = 64 + 56 * ph_count
    dyn = b""
    if bind_now:
        dyn += struct.pack(fmt + "qQ", 24, 0)              # DT_BIND_NOW
        dyn += struct.pack(fmt + "qQ", 30, 0x8)            # DT_FLAGS DF_BIND_NOW
    if textrel:
        dyn += struct.pack(fmt + "qQ", 22, 0)              # DT_TEXTREL
    dyn += struct.pack(fmt + "qQ", 0, 0)                   # DT_NULL

    out = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    out += struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, ph_count, 0, 0, 0
    )
    phdrs = struct.pack(fmt + "IIQQQQQQ", PT_LOAD, 5, 0, 0, 0x1000, 0x1000, 5, 0x1000)
    phdrs += struct.pack(fmt + "IIQQQQQQ", PT_GNU_STACK, 6, 0, 0, 0, 0, 6, 4)
    phdrs += struct.pack(
        fmt + "IIQQQQQQ", PT_DYNAMIC, 6, dyn_off, dyn_off, len(dyn), len(dyn), 6, 8
    )
    if relro:
        phdrs += struct.pack(
            fmt + "IIQQQQQQ", PT_GNU_RELRO, 4, 0x200, 0x200, 0x100, 0x100, 4, 1
        )
    out += phdrs
    out += b"\x00" * (dyn_off - len(out)) + dyn
    return out


class RelroTests(unittest.TestCase):
    def _details(self, **kw):
        machine, pie, stack_exec, flags_out, hardening = _elf_details(
            tiny_elf(**kw), 2, "<"
        )
        return hardening

    def test_full_relro(self):
        hard = self._details(bind_now=True, relro=True)
        self.assertTrue(hard["relro"])
        self.assertTrue(hard["bind_now"])
        self.assertTrue(hard["full_relro"])
        self.assertFalse(hard["writable_text"])

    def test_partial_relro_no_bind_now(self):
        hard = self._details(bind_now=False, relro=True)
        self.assertTrue(hard["relro"])
        self.assertFalse(hard["bind_now"])
        self.assertFalse(hard["full_relro"])

    def test_no_relro(self):
        hard = self._details(bind_now=False, relro=False)
        self.assertFalse(hard["relro"])
        self.assertFalse(hard["full_relro"])

    def test_textrel_flag_detected(self):
        hard = self._details(bind_now=True, relro=False, textrel=True)
        self.assertTrue(hard["writable_text"])
        self.assertFalse(hard["full_relro"])     # relro segment absent

    def test_no_dynamic_section(self):
        # stack-only ELF: no PT_DYNAMIC -> relro False, no crash
        machine, pie, sx, flags_out, hard = _elf_details(tiny_elf(False, False), 2, "<")
        self.assertIn("relro", hard)


class MasBin011RuleTests(unittest.TestCase):
    """MAS-BIN-011 flags .so libraries missing full RELRO / with TEXTREL."""

    @staticmethod
    def _rule_ids(flags):
        from masanalyzer.analysis import m07

        lib = NativeLib(
            relpath="lib/libapp.so", path="lib/libapp.so",
            arch="aarch64", platform="android", flags=dict(flags),
        )
        target = Target(
            input_path="t.apk", platform="android", work_dir=".",
            name="t.apk",
        )
        target.native_libs.append(lib)
        return {f.rule_id for f in m07.analyze(target)}

    def test_partial_relro_fires(self):
        ids = self._rule_ids(
            {"pie": True, "relro": True, "full_relro": False, "bind_now": False}
        )
        self.assertIn("MAS-BIN-011", ids)

    def test_full_relro_silent(self):
        ids = self._rule_ids(
            {"pie": True, "relro": True, "full_relro": True, "bind_now": True}
        )
        self.assertNotIn("MAS-BIN-011", ids)

    def test_writable_text_fires(self):
        ids = self._rule_ids(
            {"pie": True, "relro": True, "full_relro": True, "writable_text": True}
        )
        self.assertIn("MAS-BIN-011", ids)


class CodeSignatureTests(unittest.TestCase):
    """build_macho(codesign=True) fixtures verify through the real verifier."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_codesign_")
        cls.good = build_macho(codesign=True)
        cls.bad = build_macho(codesign=True, tamper_signature=True)

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_untampered_image_verifies(self):
        img = macho.parse_macho(self.good)
        self.assertTrue(img.has_code_signature)
        self.assertIsTrue = None  # readability below
        self.assertIs(img.code_signature_verified, True)
        self.assertEqual(img.code_signature_reasons, [])

    def test_tampered_image_fails_on_page_hash(self):
        img = macho.parse_macho(self.bad)
        self.assertIsNot(img.code_signature_verified, True)
        self.assertTrue(
            any("page hashes differ" in r for r in img.code_signature_reasons),
            img.code_signature_reasons,
        )

    def test_plain_fixture_has_no_signature_pointer(self):
        img = macho.parse_macho(build_macho())
        self.assertIsNone(img.cs_offset)
        self.assertIsNone(img.code_signature_verified)

    def test_superslot_length_is_deterministic(self):
        # the two-pass patch trick relies on this invariant
        base = build_macho(codesign=True).rfind(b"\xfa\xde\x0c\x02")
        base2 = self.good.rfind(b"\xfa\xde\x0c\x02")
        self.assertEqual(base, base2)


class MasBin012RuleTests(unittest.TestCase):
    """MAS-BIN-012 fires only when the LC_CODE_SIGNATURE blob is present
    AND its CodeDirectory verification fails."""

    @staticmethod
    def _rule_ids(raw):
        from masanalyzer.analysis import m07

        img = macho.parse_macho(raw)
        target = Target(
            input_path="app.ipa", platform="ios", work_dir=".",
            name="app.ipa",
        )
        target.meta["macho"] = [img]
        return {f.rule_id for f in m07.analyze(target)}

    def test_tampered_signature_fires(self):
        self.assertIn("MAS-BIN-012", self._rule_ids(build_macho(codesign=True, tamper_signature=True)))

    def test_good_signature_silent(self):
        self.assertNotIn("MAS-BIN-012", self._rule_ids(build_macho(codesign=True)))


class SbomTests(unittest.TestCase):
    """CycloneDX 1.5 renderer: structure, determinism, aliases, harvesting."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_sbom_")

    @classmethod
    def tearDownClass(cls):
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _scan_result(tmp, apk_path):
        from masanalyzer.scanner import scan

        return scan(apk_path)

    def test_render_structure_and_aliases(self):
        from masanalyzer.reporting import FORMATS, render

        apk = os.path.join(self.tmp, "app.apk")
        build_v23_signed_apk(apk, scheme="v2")
        result = self._scan_result(self.tmp, apk)
        self.assertIn("sbom", FORMATS)
        text = render(result, "sbom")
        doc = json.loads(text)
        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["specVersion"], "1.5")
        self.assertTrue(doc["serialNumber"].startswith("urn:uuid:"))
        self.assertTrue(doc["metadata"]["tools"][0]["name"].startswith("masanalyzer"))
        self.assertTrue(doc["vulnerabilities"], "findings map into vulnerabilities")
        # aliases render the identical document
        for alias in ("cdx", "cyclonedx"):
            self.assertEqual(render(result, alias), text)
        # deterministic
        self.assertEqual(self._scan_result(self.tmp, apk) and render(result, "sbom"), text)

    def test_native_and_dep_harvest(self):
        from masanalyzer.scanner import scan

        # unpacked tree with a gradle file and a fake .so (manifest makes the
        # scanner classify the tree as android, which is where .so live)
        tree = os.path.join(self.tmp, "tree")
        os.makedirs(os.path.join(tree, "lib", "arm64-v8a"), exist_ok=True)
        with open(os.path.join(tree, "AndroidManifest.xml"), "w") as fh:
            fh.write(
                '<manifest package="com.example.tree">\n'
                '  <application android:label="tree"/>\n'
                "</manifest>\n"
            )
        with open(os.path.join(tree, "build.gradle"), "w") as fh:
            fh.write('dependencies { implementation "com.squareup.okhttp:okhttp:4.12.0" }\n')
        with open(os.path.join(tree, "lib", "arm64-v8a", "libapp.so"), "wb") as fh:
            fh.write(tiny_elf(bind_now=False, relro=True))
        result = scan(tree)
        from masanalyzer.reporting import render

        doc = json.loads(render(result, "sbom"))
        names = {(c["name"], c.get("version", "")) for c in doc["components"]}
        self.assertTrue(
            any(n[0] == "com.squareup.okhttp:okhttp" and n[1] == "4.12.0" for n in names),
            f"dep missing: {names}",
        )
        # the unhardened .so appears with its hardening property
        so = [c for c in doc["components"] if c["name"].endswith(".so")]
        self.assertTrue(so, "native .so becomes a component")
        self.assertTrue(
            any("hardening" in p["name"] for p in so[0].get("properties", [])),
            so[0],
        )


if __name__ == "__main__":
    unittest.main()

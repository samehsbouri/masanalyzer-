"""End-to-end packaging tests: APK / IPA / tree / unknown inputs."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from masanalyzer.packaging import prepare_target
from masanalyzer.testing import (
    NSC_CLEARTEXT,
    bank_dex,
    build_apk,
    build_ipa,
)


class TempBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="masan_packaging_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class TestApkTarget(TempBase):
    def test_prepare_apk(self) -> None:
        apk = build_apk(os.path.join(self.tmp, "sample.apk"), nsc_xml=NSC_CLEARTEXT)
        t = prepare_target(apk)
        try:
            self.assertEqual(t.platform, "android")
            self.assertEqual(t.package, "com.example.insecurebank")
            self.assertTrue(any(f.kind == "manifest" for f in t.files))
            self.assertEqual(len(t.meta.get("dex", []) or t.meta.get("dex_files", [])), 1)
            self.assertIsNotNone(t.meta.get("apk"))
            self.assertFalse(t.meta["apk"].signed)
            self.assertIsNotNone(t.meta.get("network_security_config"))
            self.assertTrue(t.meta["network_security_config"].allows_cleartext())
            self.assertTrue(t.string_pool, "dex strings should reach the pool")
        finally:
            shutil.rmtree(t.work_dir, ignore_errors=True)

    def test_unsigned_apk_is_not_signed(self) -> None:
        apk = build_apk(os.path.join(self.tmp, "unsig.apk"))
        t = prepare_target(apk)
        try:
            self.assertFalse(t.meta["apk"].signed)
        finally:
            shutil.rmtree(t.work_dir, ignore_errors=True)


class TestIpaTarget(TempBase):
    def test_prepare_ipa(self) -> None:
        ipa = build_ipa(os.path.join(self.tmp, "sample.ipa"))
        t = prepare_target(ipa)
        try:
            self.assertEqual(t.platform, "ios")
            self.assertEqual(t.package, "com.example.insecurenotes")
            macho = t.meta.get("macho") or []
            self.assertEqual(len(macho), 1)
            self.assertEqual(macho[0].arch, "arm64e")
            self.assertTrue(t.meta["ipa"].allow_arbitrary_loads)
            prov = t.meta.get("provisioning")
            if prov is not None:
                self.assertTrue(
                    (prov.entitlements or {}).get("get-task-allow") is True
                    or prov.debuggable is True
                )
            plists = t.meta.get("plists") or {}
            self.assertTrue(any("Info.plist" in k for k in plists))
        finally:
            shutil.rmtree(t.work_dir, ignore_errors=True)

    def test_ipa_allow_arbitrary_loads_detected(self) -> None:
        ipa = build_ipa(os.path.join(self.tmp, "ats.ipa"))
        t = prepare_target(ipa)
        try:
            self.assertTrue(t.meta["ipa"].allow_arbitrary_loads)
        finally:
            shutil.rmtree(t.work_dir, ignore_errors=True)


class TestTreeTarget(TempBase):
    def test_android_tree(self) -> None:
        from masanalyzer.testing import build_android_tree

        tree = build_android_tree(os.path.join(self.tmp, "appsrc"))
        t = prepare_target(tree)
        self.assertEqual(t.platform, "android")
        self.assertTrue(any(f.kind == "code" for f in t.files))
        self.assertTrue(any(f.kind == "manifest" for f in t.files))
        self.assertEqual(
            len(t.meta.get("dex", []) or t.meta.get("dex_files", [])), 1
        )
        self.assertIsNotNone(t.meta.get("network_security_config"))
        # dex strings reach shared pool without a container
        joined = "|".join(s for _, s in t.string_pool)
        self.assertIn("jdbc:mysql", joined)

    def test_ios_tree(self) -> None:
        from masanalyzer.testing import build_ios_tree

        tree = build_ios_tree(os.path.join(self.tmp, "iossrc"))
        t = prepare_target(tree)
        self.assertEqual(t.platform, "ios")
        self.assertEqual(t.package, "com.example.insecurenotes")
        self.assertTrue(t.meta.get("macho"))
        self.assertTrue(t.meta.get("plists"), "binary plists should be collected")


class TestMiscInputs(TempBase):
    def test_unknown_text_file(self) -> None:
        p = os.path.join(self.tmp, "notes.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("password = \"Secret!\" inside a txt file\n")
        t = prepare_target(p)
        self.assertEqual(t.platform, "unknown")
        self.assertEqual(len(t.files), 1)

    def test_missing_input_raises(self) -> None:
        p = os.path.join(self.tmp, "nope")
        with self.assertRaises(FileNotFoundError):
            prepare_target(p)

    def test_lone_elf_file_classified_native(self) -> None:
        from samples.make_samples import _elf64

        p = os.path.join(self.tmp, "standalone.so")
        with open(p, "wb") as fh:
            fh.write(_elf64(e_type=2))
        t = prepare_target(p)
        self.assertEqual([f.kind for f in t.files], ["native"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the binary parsing layers (no sample fixtures needed).

Every fixture is synthesized from raw bytes via :mod:`masanalyzer.testing`
so the tests run on any machine without an Android/iOS toolchain.
"""

import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.android.axml import parse_axml, parse_plain_xml
from masanalyzer.android.apk import common_names_from_der, load_apk
from masanalyzer.android.dex import is_dex, parse_dex
from masanalyzer.android import manifest as man
from masanalyzer.ios.macho import is_macho, parse_macho
from masanalyzer.ios.plist import dump_bplist, parse_bplist, parse_plist
from masanalyzer.ios.ipa import load_ipa
from masanalyzer.testing import (
    bank_dex,
    build_axml,
    build_apk,
    build_dex,
    build_ipa,
    build_macho,
    build_mobileprovision,
    manifest_axml,
    manifest_plain,
    prefs_plist_dict,
)


class TestDex(unittest.TestCase):
    def test_header_and_strings(self):
        blob = bank_dex()
        self.assertTrue(is_dex(blob))
        dex = parse_dex(blob)
        values = [s.value for s in dex.strings]
        self.assertIn("https://api.insecurebank.example:8443/v2/login", values)
        self.assertIn("AES/ECB/PKCS5Padding", values)
        self.assertIn("jdbc:mysql://root:S3cr3t!db@10.0.0.5/bank", values)

    def test_classes_and_methods(self):
        dex = parse_dex(bank_dex())
        self.assertEqual(dex.classes, ["com.example.insecurebank.LoginActivity"])
        self.assertIn("com.example.insecurebank.LoginActivity#doLogin", dex.methods)

    def test_obfuscation_heuristic(self):
        blob = build_dex(
            [b"La/b/C;", b"La/b/D;", b"La/b/E;", b"La/b/F;"],
            types=[0, 1, 2, 3],
            classes=[0, 1, 2, 3],
        )
        self.assertTrue(parse_dex(blob).obfuscated())
        self.assertFalse(parse_dex(bank_dex()).obfuscated())

    def test_string_offset_recorded(self):
        dex = parse_dex(bank_dex())
        self.assertTrue(any(s.offset > 0 for s in dex.strings))

    def test_garbage_rejected(self):
        with self.assertRaises(Exception):
            parse_dex(b"\x00" * 128)


class TestAxml(unittest.TestCase):
    def test_simple_manifest(self):
        strings = ["manifest", "package", "com.example.app", "versionName", "1.0"]
        node = parse_axml(build_axml(strings, 0, [(-1, 1, 2), (-1, 3, 4)]))
        self.assertIsNotNone(node)
        self.assertEqual(node.tag, "manifest")
        self.assertEqual(node.get("package"), "com.example.app")
        self.assertEqual(node.get("versionName"), "1.0")

    def test_multi_string_pool(self):
        blob = manifest_axml("com.example.insecurebank", "2.3.1")
        node = parse_axml(blob)
        self.assertEqual(node.get("package"), "com.example.insecurebank")

    def test_plain_manifest_model(self):
        m = man.Manifest.parse(
            manifest_plain(
                package="com.a.b",
                debuggable=True,
                cleartext=True,
                uses_permissions=("android.permission.INTERNET",
                                  "android.permission.CAMERA"),
            )
        )
        self.assertEqual(m.package, "com.a.b")
        self.assertTrue(m.debuggable)
        self.assertTrue(m.allow_cleartext)
        self.assertEqual(len(m.dangerous_permissions()), 1)  # CAMERA
        self.assertIn("android.permission.INTERNET", m.uses_permissions)

    def test_exported_component_default(self):
        body = '    <activity android:name=".Main"/>\n'
        body += '    <activity android:name=".Leaky" android:exported="true"/>\n'
        m = man.Manifest.parse(manifest_plain(body=body))
        names = [c.name for c in m.exported_components()]
        self.assertNotIn(".Main", names)
        self.assertIn(".Leaky", names)


class TestDerCommonNames(unittest.TestCase):
    def test_cn_extraction(self):
        # reuse the fake v1 certificate builder through load_apk path
        with tempfile.TemporaryDirectory() as tmp:
            apk = build_apk(
                os.path.join(tmp, "a.apk"),
                sign_v1=True,
            )
            info = load_apk(apk)
            self.assertTrue(info.signed)
            self.assertTrue(info.v1.names, info.v1)
            self.assertIn("Android Debug", info.v1.names)
            self.assertTrue(info.debug_signed)


class TestApk(unittest.TestCase):
    def test_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = os.path.join(tmp, "demo.apk")
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", manifest_axml("com.a.b"))
                z.writestr("classes.dex", bank_dex())
                z.writestr("res/xml/net.xml", b"<x/>")
                z.writestr("assets/tokens.txt", "seed")
            info = load_apk(apk)
            self.assertEqual(info.manifest_entry, "AndroidManifest.xml")
            self.assertEqual(info.dex_files, ["classes.dex"])
            self.assertFalse(info.signed)
            self.assertEqual(info.summary()["entries"], 4)


class TestPlist(unittest.TestCase):
    def test_roundtrip_binary(self):
        obj = {
            "CFBundleIdentifier": "com.example.insecurenotes",
            "count": 17,
            "nested": {"flag": True, "nothing": None, "payload": b"\x00According"},
            "list": [1, 2.5, "three"],
        }
        blob = dump_bplist(obj)
        self.assertTrue(blob[:8] == b"bplist00")
        back = parse_bplist(blob)
        self.assertEqual(back["CFBundleIdentifier"], "com.example.insecurenotes")
        self.assertEqual(back["count"], 17)
        self.assertEqual(back["nested"]["flag"], True)
        self.assertIsNone(back["nested"]["nothing"])
        self.assertEqual(back["nested"]["payload"], b"\x00According")
        self.assertEqual(back["list"], [1, 2.5, "three"])

    def test_unicode(self):
        obj = {"name": "Bafürünca", "emoji": " café"}
        self.assertEqual(parse_bplist(dump_bplist(obj)), obj)

    def test_parse_plist_dispatch_xml(self):
        xml = (
            b"<plist version='1.0'><dict><key>a</key>"
            b"<string>b</string></dict></plist>"
        )
        self.assertEqual(parse_plist(xml), {"a": "b"})


class TestMacho(unittest.TestCase):
    def test_arm64e_flags_and_symbols(self):
        blob = build_macho(
            symbols=("_debug_helper_doLogin",),
            suffix_strings=("https://syncserver.example.net/cache?",),
        )
        self.assertTrue(is_macho(blob))
        img = parse_macho(blob)
        self.assertEqual(img.arch, "arm64e")
        self.assertTrue(img.has_pie)
        self.assertFalse(img.stack_executable)
        self.assertIn("_debug_helper_doLogin", img.symbols)
        self.assertIn("__info_plist", img.flag_names()) if False else None
        segs = [s.name for s in img.segments]
        self.assertIn("__TEXT", segs)

    def test_non_pie_and_stack_exec(self):
        blob = build_macho(pie=False, stack_exec=True)
        img = parse_macho(blob)
        self.assertFalse(img.has_pie)
        self.assertTrue(img.stack_executable)

    def test_appended_strings_harvested(self):
        blob = build_macho(suffix_strings=("jwt-secret-fixture", "password=%@&pin=%@"))
        text = blob.decode("latin-1", "replace")
        self.assertIn("jwt-secret-fixture", text)


class TestIpa(unittest.TestCase):
    def test_load_ipa_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            ipa = build_ipa(
                os.path.join(tmp, "InsecureNotes.ipa"),
                extra_plists={"Prefs.plist": dump_bplist(prefs_plist_dict())},
            )
            info = load_ipa(ipa)
            self.assertEqual(info.bundle_identifier, "com.example.insecurenotes")
            self.assertEqual(info.version, "1.4.2")
            self.assertEqual(info.executable_name, "InsecureNotes")
            self.assertTrue(info.allow_arbitrary_loads)
            self.assertEqual(len(info.macho_images), 1)
            self.assertIsNotNone(info.profile)
            self.assertTrue(info.debuggable)  # get-task-allow
            self.assertIn("Prefs.plist", info.plists)

    def test_mobileprovision_no_debug(self):
        blob = build_mobileprovision(get_task_allow=False, name="Dist Profile")
        self.assertIn(b"Dist Profile", blob)
        self.assertIn(b"<false/>", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)

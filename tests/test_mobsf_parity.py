"""MobSF static-analysis parity: features MobSF ships that masanalyzer
was missing, locked in as regression tests (packer/protector detection,
WebView hardening trio, RSA padding, insecure deserialization, local
socket exposure, root-tooling references, Firebase endpoints).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.scanner import scan  # noqa: E402
from masanalyzer.testing import (  # noqa: E402
    build_android_tree,
    build_apk,
    build_dex,
    NSC_CLEARTEXT,
)

ELF_STUB = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24


class _ScanCase(unittest.TestCase):
    """Scan a fixture APK once per test and filter findings by rule."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="masan_parity_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _scan(self, name: str, **kwargs):
        return scan(build_apk(os.path.join(self.tmp, name), **kwargs))

    def _findings(self, result, rule_id: str):
        return [f for f in result.findings if f.rule_id == rule_id]


class PackerDetection(_ScanCase):
    def test_packer_library_filename_detected(self):
        res = self._scan(
            "packed.apk",
            so_files={"armeabi-v7a/libjiagu.so": ELF_STUB},
        )
        hits = self._findings(res, "MAS-BIN-017")
        self.assertTrue(hits, "libjiagu.so must raise MAS-BIN-017")
        self.assertIn("360", hits[0].evidence.note)
        self.assertIn("libjiagu", hits[0].evidence.file)

    def test_packer_stub_class_in_dex_pool_detected(self):
        dex = build_dex(strings=(
            b"Lcom/stub/StubApp;",
            b"Lcom/example/app/MainActivity;",
        ))
        res = self._scan("stub.apk", dex=dex)
        hits = self._findings(res, "MAS-BIN-017")
        self.assertTrue(hits, "com.stub.StubApp string must raise MAS-BIN-017")

    def test_ijiami_asset_signature_detected(self):
        dex = build_dex(strings=(
            b"assets/ijiami.dat",
            b"Lcom/example/app/MainActivity;",
        ))
        res = self._scan("ijm.apk", dex=dex)
        hits = self._findings(res, "MAS-BIN-017")
        self.assertTrue(hits)
        self.assertIn("Ijiami", hits[0].evidence.note)

    def test_clean_bundle_no_packer_finding(self):
        res = self._scan("clean.apk")
        self.assertEqual(self._findings(res, "MAS-BIN-017"), [])


class RootToolingDetection(_ScanCase):
    def test_xposed_reference_detected(self):
        dex = build_dex(strings=(
            b"Lde/robv/android/xposed/XposedBridge;",
            b"Lcom/example/app/MainActivity;",
        ))
        res = self._scan("xposed.apk", dex=dex)
        hits = self._findings(res, "MAS-BIN-018")
        self.assertTrue(hits, "Xposed package reference must raise MAS-BIN-018")
        self.assertIn("Xposed", hits[0].evidence.note)


class WebViewHardening(_ScanCase):
    def test_remote_debug_pool_reference_detected(self):
        dex = build_dex(strings=(
            b"setWebContentsDebuggingEnabled",
            b"Lcom/example/app/MainActivity;",
        ))
        res = self._scan("wdump.apk", dex=dex)
        hits = self._findings(res, "MAS-MIS-008")
        self.assertTrue(hits, "remote-debug API reference must raise MAS-MIS-008")
        self.assertIn("string pool", hits[0].evidence.note)


class SourceTreeChecks(_ScanCase):
    """Rules that need real source files (multiline/2-arg shapes)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_src_")
        cls.tree_root = build_android_tree(os.path.join(cls.tmp, "tree"))
        tree = cls.tree_root
        # extra source files with the MobSF-parity shapes
        cls.java_dir = os.path.join(
            tree, "app", "src", "main", "java", "com", "example")
        os.makedirs(cls.java_dir, exist_ok=True)
        with open(os.path.join(cls.java_dir, "WebClient.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "import android.webkit.*;\n"
                "public class WebClient extends WebViewClient {\n"
                "  public void onReceivedSslError(WebView v, SslErrorHandler h, "
                "SslError e) {\n"
                "    h.proceed();\n"
                "  }\n"
                "}\n")
        with open(os.path.join(cls.java_dir, "Config.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "import android.webkit.WebSettings;\n"
                "public class Config {\n"
                "  void cfg(WebSettings s) {\n"
                "    s.setMixedContentMode("
                "WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);\n"
                "    s.setWebContentsDebuggingEnabled(true);\n"
                "  }\n"
                "}\n")
        with open(os.path.join(cls.java_dir, "Repo.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "import com.fasterxml.jackson.databind.ObjectMapper;\n"
                "public class Repo {\n"
                "  ObjectMapper mapper = new ObjectMapper();\n"
                "  void init() {\n"
                "    mapper.enableDefaultTyping();\n"
                "  }\n"
                "}\n")
        with open(os.path.join(cls.java_dir, "Ipc.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "import android.net.LocalServerSocket;\n"
                "public class Ipc {\n"
                "  LocalServerSocket srv = new LocalServerSocket(\"cmd\");\n"
                "}\n")
        with open(os.path.join(cls.java_dir, "Crypto.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "import javax.crypto.Cipher;\n"
                "public class Crypto {\n"
                "  Cipher c = Cipher.getInstance(\"RSA/ECB/NoPadding\");\n"
                "}\n")
        cls.result = scan(tree)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _rule(self, rule_id: str):
        return [f for f in self.result.findings if f.rule_id == rule_id]

    def test_webview_ssl_bypass(self):
        hits = self._rule("MAS-NET-010")
        self.assertTrue(hits, "proceed() after onReceivedSslError")
        self.assertIn("proceed", hits[0].evidence.note)

    def test_mixed_content_always_allow(self):
        hits = self._rule("MAS-NET-011")
        self.assertTrue(hits)
        self.assertIn("MIXED_CONTENT_ALWAYS_ALLOW",
                      hits[0].evidence.snippet or hits[0].evidence.symbol or "")

    def test_remote_debug_source(self):
        hits = self._rule("MAS-MIS-008")
        self.assertTrue(hits, "setWebContentsDebuggingEnabled(true) in source")
        self.assertIn("true", hits[0].evidence.snippet)

    def test_insecure_deserialization(self):
        hits = self._rule("MAS-INPUT-007")
        self.assertTrue(hits, "enableDefaultTyping next to ObjectMapper")
        self.assertIn("default typing", hits[0].evidence.note.lower())

    def test_local_server_socket(self):
        hits = self._rule("MAS-INPUT-008")
        self.assertTrue(hits, "new LocalServerSocket(...)")

    def test_root_execution_call_site_is_distinct(self):
        with open(os.path.join(self.java_dir, "RootExec.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(
                "package com.example;\n"
                "public class RootExec {\n"
                "  void run() throws Exception {\n"
                "    Runtime.getRuntime().exec(\"su\");\n"
                "  }\n"
                "}\n")
        from masanalyzer.scanner import scan as _scan

        res = _scan(self.tree_root)
        hits = [f for f in res.findings
                if f.rule_id == "MAS-BIN-018"
                and "call site" in (f.evidence.note or "")]
        self.assertTrue(hits, "exec('su') must be flagged as a call site")
        self.assertIn("execute", hits[0].evidence.note)

    def test_rsa_no_padding(self):
        hits = self._rule("MAS-CRY-009")
        self.assertTrue(hits, "RSA/ECB/NoPadding must raise MAS-CRY-009")

    def test_all_new_findings_carry_evidence(self):
        new_ids = {"MAS-NET-010", "MAS-NET-011", "MAS-MIS-008",
                   "MAS-INPUT-007", "MAS-INPUT-008", "MAS-CRY-009",
                   "MAS-BIN-017", "MAS-BIN-018", "MAS-CRED-009"}
        for f in self.result.findings:
            if f.rule_id not in new_ids:
                continue
            ev = f.evidence
            self.assertTrue(
                ev.snippet or ev.symbol or ev.note or ev.offset is not None,
                f"{f.rule_id} finding has no detection basis: {ev}")

    def test_firebase_endpoint(self):
        # the tree fixture carries no firebase URL; assert via a dedicated
        # scan with the URL planted in the DEX string pool
        dex = build_dex(strings=(
            b"https://my-prod.firebaseio.com/",
            b"Lcom/example/app/MainActivity;",
        ))
        apk = build_apk(os.path.join(self.tmp, "fb.apk"), dex=dex,
                        nsc_xml=NSC_CLEARTEXT)
        res = scan(apk)
        hits = [f for f in res.findings if f.rule_id == "MAS-CRED-009"]
        self.assertTrue(hits, "firebaseio.com string must raise MAS-CRED-009")
        self.assertIn("firebaseio", hits[0].evidence.symbol)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

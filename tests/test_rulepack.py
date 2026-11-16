"""User-defined rule packs (masanalyzer.rulepack) + CLI --rules wiring."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.rulepack import (
    build_rule_pack,
    load_rule_pack,
)
from masanalyzer.testing import build_dex, manifest_axml

PACK = {
    "name": "testcorp",
    "description": "internal intel",
    "owasp": "M1",
    "rules": [
        {
            "id": "backend-host",
            "title": "Undisclosed backend",
            "description": "internal backend referenced in the payload",
            "severity": "high",
            "cwe": "CWE-200",
            "scopes": ["strings", "files"],
            "patterns": [
                {"kind": "regex", "value": r"https?://backend\.testcorp\.internal/[\w./-]*"},
            ],
        },
        {
            "id": "manifest-marker",
            "title": "Test-only package marker",
            "severity": "low",
            "scopes": ["manifest"],
            "patterns": [
                {"kind": "string", "value": "com.example.testapp", "ci": True},
            ],
        },
        {
            "id": "watermark-bytes",
            "title": "Watermark bytes",
            "severity": "medium",
            "scopes": [],
            "patterns": [
                {"kind": "bytes_hex", "value": "deadbeefc0ffee"},
            ],
        },
        {
            "id": "case-insensitive-literal",
            "title": "Legacy module literal",
            "severity": "info",
            "scopes": ["strings"],
            "patterns": [
                {"kind": "string", "value": "legacy_module_impl", "ci": True},
            ],
        },
    ],
}


def _apk(tmp: str) -> str:
    """Fixture APK carrying all four pack triggers + a clean flag."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(
            "AndroidManifest.xml",
            manifest_axml("com.example.testapp", "1.0"),
        )
        z.writestr("classes.dex", build_dex(strings=(
            b"Lcom/example/testapp/MainActivity;",
            b"https://backend.testcorp.internal/api/v2/sync",
            b"Legacy_Module_Impl",
        )))
        z.writestr("assets/notes.txt", "nothing special in this line\n")
        z.writestr(
            "assets/secret.dat",
            b"head\x00\xde\xad\xbe\xef\xc0\xff\xee\x00tail",
        )
    path = os.path.join(tmp, "pack.apk")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


class ValidationTests(unittest.TestCase):
    def test_valid_pack_compiles_rule_ids(self):
        pack = build_rule_pack(PACK)
        ids = [r.rule.rule_id for r in pack.rules]
        self.assertEqual(
            ids,
            [
                "CUSTOM-TESTCORP-BACKEND-HOST",
                "CUSTOM-TESTCORP-MANIFEST-MARKER",
                "CUSTOM-TESTCORP-WATERMARK-BYTES",
                "CUSTOM-TESTCORP-CASE-INSENSITIVE-LITERAL",
            ],
        )

    def test_load_from_file(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "pack.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(PACK, fh)
        pack = load_rule_pack(path)
        self.assertEqual(pack.title, "testcorp")

    def _bad(self, mutate, message_part):
        pack = json.loads(json.dumps(PACK))
        mutate(pack)
        with self.assertRaises(ValueError) as ctx:
            build_rule_pack(pack)
        self.assertIn(message_part, str(ctx.exception))

    def test_unknown_top_key(self):
        self._bad(lambda p: p.update(unsurprise=1), "unknown top-level")

    def test_bad_regex(self):
        def m(p):
            p["rules"][0]["patterns"][0]["value"] = "(unclosed[)"
        self._bad(m, "bad regex")

    def test_bad_severity(self):
        self._bad(lambda p: p["rules"][0].update(severity="apocalyptic"),
                  "severity")

    def test_duplicate_rule_id(self):
        def m(p):
            p["rules"].append(dict(p["rules"][0]))
        self._bad(m, "duplicate")

    def test_bad_owasp(self):
        self._bad(lambda p: p.update(owasp="M11"), "M1..M10")
        self._bad(lambda p: p["rules"][0].update(owasp="M0"), "owasp")

    def test_bad_scope(self):
        self._bad(lambda p: p["rules"][0].update(scopes=["frobnicate"]),
                  "unknown scope")

    def test_empty_rules(self):
        self._bad(lambda p: p.update(rules=[]), "non-empty")

    def test_bytes_hex_validation(self):
        self._bad(lambda p: p["rules"][2]["patterns"].append(
            {"kind": "bytes_hex", "value": "zzzz"}), "hex")

    def test_cvss_range(self):
        self._bad(lambda p: p["rules"][0].update(cvss=99), "0-10")


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_pack_")
        cls.apk = _apk(cls.tmp)
        cls.pack = build_rule_pack(PACK)
        from masanalyzer.scanner import scan

        cls.res = scan(cls.apk, rule_packs=[cls.pack])

    def test_custom_findings_present(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertIn("CUSTOM-TESTCORP-BACKEND-HOST", ids)
        self.assertIn("CUSTOM-TESTCORP-MANIFEST-MARKER", ids)
        self.assertIn("CUSTOM-TESTCORP-WATERMARK-BYTES", ids)
        self.assertIn("CUSTOM-TESTCORP-CASE-INSENSITIVE-LITERAL", ids)

    def test_evidence_content(self):
        host = next(f for f in self.res.findings
                    if f.rule_id == "CUSTOM-TESTCORP-BACKEND-HOST")
        self.assertEqual(
            host.evidence.symbol, "https://backend.testcorp.internal/api/v2/sync"
        )
        self.assertIn("classes.dex", host.evidence.file)
        byt = next(f for f in self.res.findings
                   if f.rule_id == "CUSTOM-TESTCORP-WATERMARK-BYTES")
        self.assertEqual(byt.evidence.symbol, "deadbeefc0ffee")
        self.assertIsNotNone(byt.evidence.offset)

    def test_builtins_still_run_with_packs(self):
        ids = {f.rule_id for f in self.res.findings}
        self.assertTrue(any(i.startswith("MAS-") for i in ids))

    def test_rule_catalog_includes_pack(self):
        from masanalyzer.analysis import rule_catalog

        ids = {r.rule_id for r in rule_catalog()}
        self.assertIn("CUSTOM-TESTCORP-BACKEND-HOST", ids)
        self.assertGreater(len(ids), 84)

    def test_report_roundtrip(self):
        from masanalyzer.reporting import render

        doc = json.loads(render(self.res, "json"))
        rids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("CUSTOM-TESTCORP-MANIFEST-MARKER", rids)


class CliTests(unittest.TestCase):
    def test_cli_scan_with_rules(self):
        from masanalyzer.cli import main

        tmp = tempfile.mkdtemp(prefix="masan_pack_cli_")
        apk = _apk(tmp)
        pack_path = os.path.join(tmp, "pack.json")
        with open(pack_path, "w", encoding="utf-8") as fh:
            json.dump(PACK, fh)
        out = os.path.join(tmp, "out")
        rc = main([apk, "-o", out, "--format", "json", "-q",
                   "--rules", pack_path])
        self.assertEqual(rc, 0)
        doc = json.load(open(os.path.join(out, "report.json"), encoding="utf-8"))
        rids = {f["rule_id"] for f in doc["findings"]}
        self.assertIn("CUSTOM-TESTCORP-BACKEND-HOST", rids)

    def test_cli_bad_pack_rejected(self):
        from masanalyzer.cli import main

        tmp = tempfile.mkdtemp(prefix="masan_pack_cli_bad_")
        apk = _apk(tmp)
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write('{"name": "x", "rules": "nope"}')
        rc = main([apk, "-o", os.path.join(tmp, "out"), "--format", "json",
                   "-q", "--rules", bad])
        self.assertEqual(rc, 2)

    def test_cli_list_rules_with_pack(self):
        from masanalyzer.cli import main
        import contextlib
        from io import StringIO

        tmp = tempfile.mkdtemp(prefix="masan_pack_cli_ls_")
        pack_path = os.path.join(tmp, "pack.json")
        with open(pack_path, "w", encoding="utf-8") as fh:
            json.dump(PACK, fh)
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--list-rules", "--rules", pack_path])
        self.assertEqual(rc, 0)
        self.assertIn("CUSTOM-TESTCORP-BACKEND-HOST", buf.getvalue())


if __name__ == "__main__":
    unittest.main()

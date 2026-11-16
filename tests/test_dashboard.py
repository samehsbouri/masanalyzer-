"""End-to-end contract for the local dashboard: upload -> scan -> reports.

Exercises the real HTTP layer on an ephemeral port (ThreadingHTTPServer in
a thread) with the real scanner, so the tests cover routing, multipart
parsing, job lifecycle, report rendering and download headers.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.dashboard import (  # noqa: E402
    _Handler,
    _Jobs,
    Dashboard,
    extract_upload,
    sanitize_upload_name,
)
from masanalyzer.testing import build_apk  # noqa: E402

BOUNDARY = "masantestboundary7f3a"


def _multipart(filename: str, content: bytes, field: str = "file") -> tuple:
    ctype = f"multipart/form-data; boundary={BOUNDARY}"
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    body = head + content + f"\r\n--{BOUNDARY}--\r\n".encode("utf-8")
    return ctype, body


def _surface_fixture_apk(dest_path: str) -> str:
    """Minimal APK whose text manifest exports one unguarded browsable
    activity (the manifest parser falls back to plain XML)."""
    from masanalyzer.testing import bank_dex, manifest_plain

    man = manifest_plain(
        "com.example.insecurebank", "2.3.1", min_sdk=21, target_sdk=30,
        body=(
            '    <uses-permission android:name='
            '"android.permission.ACCESS_FINE_LOCATION"/>\n'
            '    <activity android:name=".OpenActivity" '
            'android:exported="true">\n'
            '      <intent-filter>\n'
            '        <action android:name="android.intent.action.VIEW"/>\n'
            '        <category android:name='
            '"android.intent.category.DEFAULT"/>\n'
            '        <category android:name='
            '"android.intent.category.BROWSABLE"/>\n'
            '        <data android:scheme="myapp" android:host="fix.example" '
            'android:pathPrefix="/open"/>\n'
            '      </intent-filter>\n'
            '    </activity>\n'
        ),
    )
    with zipfile.ZipFile(dest_path, "w") as z:
        z.writestr("AndroidManifest.xml", man)
        z.writestr("classes.dex", bank_dex())
    return dest_path


class DashboardLive(unittest.TestCase):
    """One server, one shared upload, route-level assertions."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_dash_")
        cls.dash = Dashboard(
            workdir=os.path.join(cls.tmp, "work"),
            workers=1,
            max_upload_mib=2,
        )
        handler = type("BoundHandler", (_Handler,), {"dashboard": cls.dash})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(
            target=cls.httpd.serve_forever, daemon=True, name="dash-test"
        ).start()

        cls.apk_path = build_apk(os.path.join(cls.tmp, "app.apk"))
        with open(cls.apk_path, "rb") as fh:
            cls.apk_bytes = fh.read()

        # one shared, fully-scanned job for the read-only assertions
        cls.job = cls._upload_sync("app.apk", cls.apk_bytes)

        # second fixture: manifest with an exported browsable door so the
        # fix-first queue has something to rank
        surf_apk = _surface_fixture_apk(os.path.join(cls.tmp, "surface.apk"))
        with open(surf_apk, "rb") as fh:
            cls.surf_job = cls._upload_sync("surface.apk", fh.read())

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers ------------------------------------------------------------
    @classmethod
    def _request(cls, path: str, data: bytes = None, ctype: str = None):
        req = urllib.request.Request(cls.base + path, data=data)
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    @classmethod
    def _upload(cls, filename: str, content: bytes):
        ctype, body = _multipart(filename, content)
        return cls._request("/upload", body, ctype)

    @classmethod
    def _upload_sync(cls, filename: str, content: bytes) -> dict:
        code, _, body = cls._upload(filename, content)
        assert code == 201, f"upload failed: {code} {body[:200]!r}"
        job = json.loads(body)
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            _, _, now = cls._request(f"/job/{job['id']}")
            current = json.loads(now)
            if current.get("status") in ("done", "error"):
                return current
            time.sleep(0.2)
        raise AssertionError("job did not finish within 90s")

    # -- page + registry ------------------------------------------------------
    def test_index_page_renders(self):
        code, headers, body = self._request("/")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("masanalyzer dashboard", text)
        self.assertIn('/upload"', text)  # the upload form endpoint

    def test_jobs_endpoint_lists_the_job(self):
        code, _, body = self._request("/jobs")
        self.assertEqual(code, 200)
        doc = json.loads(body)
        self.assertTrue(
            any(j["id"] == self.job["id"] for j in doc["jobs"]),
            "shared job must appear in /jobs")

    def test_job_metadata_is_complete(self):
        code, _, body = self._request(f"/job/{self.job['id']}")
        self.assertEqual(code, 200)
        job = json.loads(body)
        self.assertEqual(job["status"], "done")
        self.assertTrue(job["grade"], "a finished scan must have a grade")
        self.assertIsInstance(job["score"], float)
        self.assertGreaterEqual(job["findings"], 1)
        self.assertTrue(job["severity"], "severity histogram expected")
        self.assertTrue(job["assurance"], "assurance histogram expected")
        self.assertEqual(
            sum(job["assurance"].values()), job["findings"],
            "every finding must be graded")
        for tier in job["assurance"]:
            self.assertIn(tier, ("verified", "structural", "heuristic"))
        self.assertEqual(
            sorted(job["formats"]),
            sorted(["report.json", "report.md", "report.html", "report.pdf",
                    "report.sarif", "report.sbom", "report.audit",
                    "report.csv", "report.junit", "report.gitlab"]),
        )
        self.assertIn(job["grade"], ("A+", "A", "B", "C", "D", "F"))

    def test_job_carries_attack_surface_summary(self):
        code, _, body = self._request(f"/job/{self.job['id']}")
        self.assertEqual(code, 200)
        surface = json.loads(body).get("surface") or {}
        self.assertTrue(surface, "apk fixture has a manifest -> surface")
        self.assertGreaterEqual(surface.get("external_entry_points", 0), 0)
        self.assertEqual(
            surface.get("surface_findings"),
            sum(e.get("finding_count", 0) for e in
                surface.get("entry_points", [])) if surface.get("entry_points")
            else surface.get("surface_findings", 0))

    def test_job_carries_fix_first_queue(self):
        code, _, body = self._request(f"/job/{self.surf_job['id']}")
        self.assertEqual(code, 200)
        surface = json.loads(body).get("surface") or {}
        queue = surface.get("fix_first") or []
        self.assertTrue(queue, "fix-first queue must reach the dashboard")
        self.assertIn("component", queue[0])
        self.assertIn("score", queue[0])
        self.assertTrue(queue[0]["why"], "top door must carry a rationale")
        scores = [e["score"] for e in queue]
        self.assertEqual(scores, sorted(scores, reverse=True))
        top = {e["component"] for e in queue}
        self.assertIn(
            "com.example.insecurebank.OpenActivity", top,
            "the exported browsable door must be ranked")
        # UI renders the fix-first chip
        _, _, page = self._request("/")
        self.assertIn("fix first:", page.decode("utf-8"))

    # -- overview page --------------------------------------------------------
    def test_overview_page_serves_facts(self):
        code, headers, body = self._request(f"/overview/{self.surf_job['id']}")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("File information", text)
        self.assertIn("SHA256", text)
        self.assertIn("App information", text)
        self.assertIn("com.example.insecurebank", text)
        self.assertIn("Permissions", text)
        self.assertIn("dangerous", text)
        self.assertIn("Attack surface", text)
        self.assertIn("Fix first", text)
        # XSS-safe: server-side escaping, no injection surface
        self.assertNotIn("<script>alert", text)

    def test_overview_unknown_job_404(self):
        code, _, _ = self._request(f"/overview/{'0' * 32}")
        self.assertEqual(code, 404)

    def test_overview_link_on_index(self):
        _, _, body = self._request("/")
        self.assertIn("/overview/", body.decode("utf-8"))

    def test_index_page_explains_tiers(self):
        code, _, body = self._request("/")
        text = body.decode("utf-8")
        self.assertEqual(code, 200)
        self.assertIn("Assurance", text)
        self.assertIn("tierChips", text)
        self.assertIn("surfTxt", text)

    # -- reports --------------------------------------------------------------
    def test_report_json_is_the_scan_document(self):
        code, headers, body = self._request(f"/report/{self.job['id']}/json")
        self.assertEqual(code, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        doc = json.loads(body)
        self.assertIn("findings", doc)
        self.assertGreaterEqual(len(doc["findings"]), 1)

    def test_report_html_inline_no_disposition(self):
        code, headers, body = self._request(f"/report/{self.job['id']}/html")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertNotIn("Content-Disposition", headers)
        self.assertIn("Mobile App Security Report", body.decode("utf-8"))

    def test_report_md_and_csv(self):
        code, _, body = self._request(f"/report/{self.job['id']}/md")
        self.assertEqual(code, 200)
        self.assertIn("# Mobile App Security Report", body.decode("utf-8"))
        code, _, body = self._request(f"/report/{self.job['id']}/csv")
        self.assertEqual(code, 200)
        self.assertIn("severity,", body.decode("utf-8").lower())

    def test_download_sets_attachment_disposition(self):
        code, headers, body = self._request(
            f"/download/{self.job['id']}/md")
        self.assertEqual(code, 200)
        disp = headers.get("Content-Disposition", "")
        self.assertIn("attachment", disp)
        self.assertIn("app-report.md", disp)
        # same body as the inline variant
        _, _, inline = self._request(f"/report/{self.job['id']}/md")
        self.assertEqual(body, inline)

    # -- styled report viewers -------------------------------------------------
    def test_view_json_serves_collapsible_tree(self):
        code, headers, body = self._request(f"/view/{self.job['id']}/json")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("json viewer", text)
        self.assertIn("id='payload'", text)     # the data island
        self.assertIn("id='tree'", text)        # the lazy tree
        self.assertIn("id='search'", text)      # search box
        # payload must parse back to the report document
        m = re.search(
            r"<script type='application/json' id='payload'>(.*?)</script>",
            text, re.S)
        self.assertTrue(m, "payload island present")
        doc = json.loads(m.group(1).replace("<\\/", "</"))
        self.assertIn("findings", doc)
        self.assertGreaterEqual(len(doc["findings"]), 1)
        self.assertNotIn("<script>alert", text)

    def test_view_md_renders_markdown(self):
        code, headers, body = self._request(f"/view/{self.job['id']}/md")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("markdown viewer", text)
        self.assertIn("<h2", text)              # headings rendered
        self.assertIn("<table>", text)          # pipe tables rendered
        # app-controlled content is escaped, never raw markup
        self.assertNotIn("<script>alert", text)
        # links from references survive as real anchors
        if "https://cwe.mitre.org" in text:
            self.assertIn("href=", text)

    def test_view_sarif_renders_triage_table(self):
        code, headers, body = self._request(f"/view/{self.job['id']}/sarif")
        self.assertEqual(code, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        text = body.decode("utf-8")
        self.assertIn("sarif viewer", text)
        self.assertIn("SARIF 2.1.0 triage", text)
        # level chips + rule ids + at least one result row
        self.assertIn("lv-error", text)
        self.assertIn("lv-warning", text)
        self.assertIn("Results (", text)
        # raw sarif is untouched on /report
        _, _, raw = self._request(f"/report/{self.job['id']}/sarif")
        doc = json.loads(raw.decode("utf-8"))
        self.assertIn("Results (", text)  # count line
        self.assertEqual(
            len(doc["runs"][0]["results"]),
            int(re.search(r"Results \((\d+)\)", text).group(1)))

    def test_view_unknown_format_and_job(self):
        code, _, _ = self._request(f"/view/{self.job['id']}/exe")
        self.assertEqual(code, 400)
        code, _, _ = self._request(f"/view/{'0' * 32}/json")
        self.assertEqual(code, 404)

    def test_index_links_to_viewers(self):
        _, _, body = self._request("/")
        text = body.decode("utf-8")
        self.assertIn("/view/", text)

    # -- error paths ------------------------------------------------------------
    def test_unknown_job_404(self):
        bogus = "0" * 32
        code, _, _ = self._request(f"/job/{bogus}")
        self.assertEqual(code, 404)
        code, _, _ = self._request(f"/report/{bogus}/json")
        self.assertEqual(code, 404)
        code, _, _ = self._request("/nope")
        self.assertEqual(code, 404)

    def test_bad_format_400(self):
        code, _, body = self._request(f"/report/{self.job['id']}/exe")
        self.assertEqual(code, 400)
        self.assertIn("fmt must be one of", body.decode("utf-8"))

    def test_non_multipart_post_400(self):
        code, _, body = self._request(
            "/upload", b"plain body", "text/plain")
        self.assertEqual(code, 400)
        self.assertIn("multipart", body.decode("utf-8"))

    def test_multipart_without_file_part_400(self):
        ctype, body = _multipart("ignored.txt", b"hi", field="other")
        code, _, _ = self._request("/upload", body, ctype)
        self.assertEqual(code, 400)

    def test_oversized_upload_413(self):
        original = self.dash.max_upload
        self.dash.max_upload = 1024  # shrink the cap for the probe
        try:
            code, _, body = self._upload("app.apk", self.apk_bytes)
            self.assertEqual(code, 413)
            self.assertIn("cap", body.decode("utf-8"))
        finally:
            self.dash.max_upload = original

    # -- upload parsing units ----------------------------------------------------
    def test_extract_upload_parses_name_and_content(self):
        ctype, body = _multipart("hello world.apk", b"PK\x03\x04payload")
        name, content = extract_upload({"Content-Type": ctype}, body)
        self.assertEqual(name, "hello world.apk")
        self.assertEqual(content, b"PK\x03\x04payload")

    def test_sanitize_upload_name_neutralises_paths(self):
        self.assertEqual(sanitize_upload_name(r"..\..\evil.exe"), "evil.bin")
        self.assertEqual(sanitize_upload_name("ok name.aab"), "ok name.aab")
        self.assertEqual(sanitize_upload_name("no-ext"), "no-ext")
        self.assertEqual(sanitize_upload_name(""), "upload")
        self.assertLessEqual(
            len(sanitize_upload_name("x" * 500)), 150)

    # -- persistence ----------------------------------------------------------------
    def test_jobs_survive_a_registry_restart(self):
        registry = _Jobs(self.dash.jobs.root)  # fresh instance, same root
        self.assertIsNotNone(registry.get(self.job["id"]))
        self.assertEqual(
            registry.get(self.job["id"])["status"], "done")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

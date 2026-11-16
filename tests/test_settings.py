"""/settings: stored display preferences and the pages that consume them."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.dashboard import (  # noqa: E402
    _Handler,
    _Settings,
    _board_page,
    _reports_page,
    _settings_page,
    Dashboard,
)

JOB_ID = "b" * 32


class SettingsStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.workdir = os.path.join(self.tmp, "work")
        os.makedirs(self.workdir)

    def test_defaults_without_a_file(self):
        settings = _Settings(self.workdir)
        self.assertEqual(settings.values["refresh_seconds"], 3)
        self.assertEqual(settings.preview, "md")
        self.assertEqual(settings.refresh_ms, 3000)
        self.assertFalse(os.path.exists(settings.path))

    def test_update_persists_and_reloads(self):
        settings = _Settings(self.workdir)
        self.assertTrue(settings.update({"refresh": "10", "preview": "json"}))
        self.assertEqual(settings.refresh_ms, 10000)
        self.assertTrue(os.path.isfile(settings.path))

        again = _Settings(self.workdir)
        self.assertEqual(again.values["refresh_seconds"], 10)
        self.assertEqual(again.preview, "json")

    def test_invalid_values_fall_back(self):
        settings = _Settings(self.workdir)
        settings.update({"refresh": "999", "preview": "../../etc"})
        self.assertEqual(settings.values["refresh_seconds"], 3)
        self.assertEqual(settings.preview, "md")
        settings.update({"refresh": "nonsense"})
        self.assertEqual(settings.values["refresh_seconds"], 3)

    def test_zero_means_manual_refresh(self):
        settings = _Settings(self.workdir)
        settings.update({"refresh": "0"})
        self.assertEqual(settings.refresh_ms, 0)

    def test_corrupt_file_is_ignored(self):
        path = os.path.join(self.workdir, "settings.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        settings = _Settings(self.workdir)
        self.assertEqual(settings.values["refresh_seconds"], 3)

    def test_partial_update_keeps_the_other_value(self):
        settings = _Settings(self.workdir)
        settings.update({"refresh": "30", "preview": "csv"})
        settings.update({"refresh": "2"})
        self.assertEqual(settings.values["refresh_seconds"], 2)
        self.assertEqual(settings.preview, "csv")


class SettingsPage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.settings = _Settings(self.tmp)
        self.runtime = [("Dashboard", "<code>http://127.0.0.1:8102/</code>"),
                        ("Scan workers", "1")]

    def test_page_shows_current_choices_and_runtime(self):
        self.settings.update({"refresh": "10", "preview": "json"})
        page = _settings_page(self.settings, self.runtime)
        self.assertIn("<h1>Settings</h1>", page)
        self.assertIn("name='refresh'", page)
        self.assertIn("<option value='10' selected>every 10 s</option>", page)
        self.assertIn("<option value='json' selected>report.json</option>", page)
        self.assertIn("Scan workers", page)
        self.assertNotIn("saved</span>", page)

    def test_saved_flag_renders_the_pill(self):
        page = _settings_page(self.settings, self.runtime, saved=True)
        self.assertIn("saved</span>", page)

    def test_board_page_uses_the_saved_interval(self):
        page = _board_page([], 10000)
        self.assertIn("const REFRESH_MS = 10000;", page)
        self.assertIn("refreshes every 10 s", page)

    def test_board_page_can_disable_the_interval(self):
        page = _board_page([], 0)
        self.assertIn("const REFRESH_MS = 0;", page)
        self.assertIn("manual refresh only", page)

    def test_page_ships_the_live_form(self):
        page = _settings_page(self.settings, self.runtime)
        self.assertIn("id='setform'", page)
        self.assertIn("id='setstatus'", page)
        self.assertIn("X-Requested-With", page)
        self.assertIn("preventDefault", page)

    def test_summary_describes_the_saved_state(self):
        self.settings.update({"refresh": "10", "preview": "json"})
        self.assertEqual(self.settings.summary(),
                         "board every 10 s \u00b7 reports open on report.json")
        self.settings.update({"refresh": "0", "preview": "none"})
        self.assertEqual(self.settings.summary(),
                         "board refresh off \u00b7 no reports preview")

    def test_reports_page_opens_with_the_default_format(self):
        job_dir = os.path.join(self.tmp, "job")
        os.makedirs(job_dir)
        for fmt in ("md", "json"):
            with open(os.path.join(job_dir, f"report.{fmt}"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}")
        job = {"id": JOB_ID, "name": "app.apk"}
        page = _reports_page(job, job_dir, "", "json")
        self.assertIn(f"src='/report/{JOB_ID}/json'", page)
        requested = _reports_page(job, job_dir, "md", "json")
        self.assertIn(f"src='/report/{JOB_ID}/md'", requested)


class SettingsOverHTTP(unittest.TestCase):
    """The live form posts in place; a plain form post still redirects."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_set_")
        cls.dash = Dashboard(workdir=os.path.join(cls.tmp, "work"), workers=1)
        handler = type("BoundHandler", (_Handler,), {"dashboard": cls.dash})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _post(self, body: str, fetch: bool):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if fetch:
            headers["X-Requested-With"] = "fetch"
        req = urllib.request.Request(self.base + "/settings",
                                     data=body.encode("utf-8"),
                                     headers=headers)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_fetch_post_answers_json_and_saves(self):
        status, body = self._post("refresh=10&preview=json", fetch=True)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["saved"])
        self.assertTrue(payload["changed"])
        self.assertEqual(payload["settings"]["refresh_seconds"], 10)
        self.assertIn("reports open on report.json", payload["summary"])
        self.assertEqual(self.dash.settings.values["refresh_seconds"], 10)

    def test_plain_post_still_redirects(self):
        status, _body = self._post("refresh=5&preview=md", fetch=False)
        self.assertEqual(status, 303)
        self.assertEqual(self.dash.settings.values["refresh_seconds"], 5)

    def test_second_identical_post_reports_no_change(self):
        self._post("refresh=3&preview=md", fetch=True)
        _status, body = self._post("refresh=3&preview=md", fetch=True)
        self.assertFalse(json.loads(body)["changed"])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 3xx instead of following it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

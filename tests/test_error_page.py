"""A crashing route must answer with a readable 500, never a dropped socket."""

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
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import masanalyzer.dashboard as dashboard  # noqa: E402
from masanalyzer.dashboard import (  # noqa: E402
    _Handler,
    _error_page,
    Dashboard,
)


class ErrorPageMarkup(unittest.TestCase):
    def test_page_names_the_error_and_the_path(self):
        try:
            raise ValueError("report.json is not a dict")
        except ValueError as exc:
            page = _error_page("/overview/" + "a" * 32, exc)
        self.assertIn("This page could not be rendered", page)
        self.assertIn("ValueError", page)
        self.assertIn("report.json is not a dict", page)
        self.assertIn("Traceback (last frames)", page)
        self.assertIn("href='/overview/" + "a" * 32 + "'", page)

    def test_markup_is_escaped(self):
        try:
            raise RuntimeError("<script>alert(1)</script>")
        except RuntimeError as exc:
            page = _error_page("/x?y=<b>", exc)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)


class ErrorPageOverHTTP(unittest.TestCase):
    """The real handler: a raising page builder answers 500, not nothing."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_err_")
        cls.dash = Dashboard(workdir=os.path.join(cls.tmp, "work"), workers=1)
        handler = type("BoundHandler", (_Handler,), {"dashboard": cls.dash})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_board_crash_returns_a_readable_500(self):
        def boom(*_args, **_kwargs):
            raise KeyError("board render exploded")
        with mock.patch.object(dashboard, "_board_page", boom):
            status, body = self._get("/")
        self.assertEqual(status, 500)
        self.assertIn("This page could not be rendered", body)
        self.assertIn("board render exploded", body)

    def test_json_route_reports_the_error_as_json(self):
        with mock.patch.object(type(self.dash.jobs), "list",
                               side_effect=RuntimeError("registry gone")):
            status, body = self._get("/jobs")
        self.assertEqual(status, 500)
        payload = json.loads(body)
        self.assertIn("RuntimeError", payload["error"])
        self.assertEqual(payload["path"], "/jobs")

    def test_pages_still_work_after_a_crash(self):
        with mock.patch.object(dashboard, "_board_page",
                               side_effect=RuntimeError("x")):
            self.assertEqual(self._get("/")[0], 500)
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("Scan board", body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

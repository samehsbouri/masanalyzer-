"""The dashboard overview page must render whatever shapes the report holds.

``inventory.callsites`` is normally a list of receipt dicts, but some report
producers write bare strings there.  That used to raise ``AttributeError``
inside the page builder, which closed the connection and gave the browser an
empty response ("this page isn't working").
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.dashboard import _overview_page, _rows  # noqa: E402

JOB = {"id": "a" * 32, "name": "selfcare.apk"}


class SectionRows(unittest.TestCase):
    """Inventory sections come back in several envelopes."""

    def test_total_rows_envelope(self):
        value = {"total": 16, "rows": [{"url": "a"}, {"url": "b"}]}
        self.assertEqual(_rows(value), [{"url": "a"}, {"url": "b"}])

    def test_bare_list_and_single_record(self):
        self.assertEqual(_rows([1, 2]), [1, 2])
        self.assertEqual(_rows({"url": "only"}), [{"url": "only"}])

    def test_scalars_are_not_iterated(self):
        self.assertEqual(_rows(None), [])
        self.assertEqual(_rows("com.example.Call"), ["com.example.Call"])


class OverviewPageShapes(unittest.TestCase):
    def test_callsite_envelope_renders_its_rows(self):
        inventory = {"callsites": {"total": 2, "rows": [
            {"url": "https://sdk.example/v1", "method": "aq3#a",
             "callee": "Ljava/net/URL;#<init>", "offset": 4956024},
            {"url": "https://sdk.example/v2", "method": "bq1#b",
             "callee": "Ljava/net/URLConnection;#run", "offset": 4956052},
        ]}}
        html = _overview_page(JOB, {"app": {"package": "com.example"}},
                              inventory, {"findings": [], "score": {}})
        self.assertIn("2 observed", html)
        self.assertIn("https://sdk.example/v1", html)
        self.assertIn("Ljava/net/URL;#&lt;init&gt;", html)
        # the envelope keys must never become table rows
        self.assertNotIn("<code>total</code>", html)
        self.assertNotIn("<code>rows</code>", html)

    def test_endpoints_card_uses_the_envelope_and_counts(self):
        inventory = {"endpoints": {
            "total": 1591,
            "counts": {"tracker": 10, "public": 1578, "cleartext": 0},
            "rows": [
                {"host": "c4d-cdn.adcolony.com", "kind": "url",
                 "classification": "tracker", "cleartext": True,
                 "occurrences": 1},
                {"host": "api.example.test", "kind": "url",
                 "classification": "first_party", "cleartext": False,
                 "occurrences": 12},
            ],
        }}
        html = _overview_page(JOB, {}, inventory, {})
        self.assertIn("id='endpoints'", html)
        self.assertIn("1591 hosts", html)
        self.assertIn("tracker 10", html)
        self.assertIn("api.example.test", html)
        # ordered by occurrences, cleartext gets its own flag
        self.assertLess(html.index("api.example.test"),
                        html.index("c4d-cdn.adcolony.com"))
        self.assertIn("cleartext</span>", html)
        self.assertNotIn("<code>total</code>", html)

    def test_trackers_card_lists_the_endpoint_hosts(self):
        inventory = {"endpoints": {"total": 3, "counts": {},"rows": [
            {"host": "www.inmobi.com", "classification": "tracker",
             "occurrences": 7},
            {"host": "www.inmobi.com", "classification": "tracker",
             "occurrences": 3},
            {"host": "api.example.test", "classification": "public",
             "occurrences": 9},
        ]}}
        html = _overview_page(JOB, {}, inventory, {})
        trackers = html.split("id='trackers'")[1].split("</section>")[0]
        self.assertIn("1 hosts", trackers)
        self.assertIn("www.inmobi.com", trackers)
        self.assertIn(">10</td>", trackers)      # 7 + 3 calls summed
        self.assertNotIn("api.example.test", trackers)  # not a tracker

    def test_trackers_fall_back_to_the_summary_line(self):
        overview = {"trackers": {"count": 4,
                                 "note": "tracker endpoints observed"}}
        html = _overview_page(JOB, overview, {}, {})
        self.assertNotIn("id='trackers'", html)
        self.assertIn("<b>4</b>", html)

    def test_every_card_can_be_collapsed(self):
        html = _overview_page(JOB, {}, {}, {})
        # the toggle is injected client-side, so the page ships its CSS+JS
        self.assertIn("ctog", html)
        self.assertIn(".card.collapsed", html)
        self.assertIn("mas.cards.", html)

    def test_privacy_card_lists_permissions(self):
        inventory = {"privacy": {
            "dangerous": 8, "excess": 1, "corroborated": 1,
            "rows": [
                {"permission": "android.permission.GET_ACCOUNTS",
                 "special": False, "signals": 2,
                 "observed": [{"marker": "accountmanager"},
                              {"marker": "getaccounts"}],
                 "corroborated": True},
            ],
        }}
        html = _overview_page(JOB, {}, inventory, {})
        self.assertIn("id='privacy'", html)
        self.assertIn("8 dangerous", html)
        self.assertIn("1 excess", html)
        self.assertIn("GET_ACCOUNTS", html)
        self.assertIn("accountmanager, getaccounts", html)
        self.assertIn("corroborated</span>", html)

    def test_absent_sections_do_not_render_cards(self):
        html = _overview_page(JOB, {}, {}, {})
        self.assertNotIn("id='endpoints'", html)
        self.assertNotIn("id='privacy'", html)

    def test_string_callsites_render_instead_of_crashing(self):
        inventory = {"callsites": ["com.example.Foo.bar@0x4012"]}
        html = _overview_page(JOB, {"app": {"package": "com.example"}},
                              inventory, {"findings": [], "score": {}})
        self.assertIn("com.example.Foo.bar@0x4012", html)

    def test_dict_callsites_keep_their_columns(self):
        inventory = {"callsites": [{
            "url": "https://api.example/v1",
            "method": "POST",
            "callee": "okhttp3.Call.execute",
            "offset": "0x0042",
        }]}
        html = _overview_page(JOB, {"app": {"package": "com.example"}},
                              inventory, {"findings": [], "score": {}})
        self.assertIn("https://api.example/v1", html)
        self.assertIn("okhttp3.Call.execute", html)

    def test_empty_report_sections_do_not_raise(self):
        html = _overview_page(JOB, {}, {}, {})
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("File information", html)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

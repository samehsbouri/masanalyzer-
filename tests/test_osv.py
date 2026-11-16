"""Feature: CVE currency via the OSV.dev cache (masanalyzer.osv + intelcli).

Verifies: coordinate mapping, /v1/query response trimming, version
matching, cache roundtrip/TTL semantics, m02's MAS-SCA-003 emission and
the refresh CLI with a stubbed fetcher (no network in tests)."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.osv import (  # noqa: E402
    IOS_POD_COORDS,
    OsvCache,
    coordinate_for,
    matches_version,
    osv_package,
    query_osv,
)
from masanalyzer.testing import build_apk, build_dex, build_ipa  # noqa: E402

ADVISORY = {
    "id": "GHSA-test-0001",
    "summary": "an example vulnerability in the library",
    "modified": "2026-01-01T00:00:00Z",
    "versions": ["3.10.0", "3.11.0"],
    "fixed": ["3.13.0"],
}


def _stub_response(**_kw) -> dict:
    return {"vulns": [{
        "id": "GHSA-test-0001",
        "summary": "an example vulnerability in the library",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [{
            "versions": ["3.10.0", "3.11.0"],
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "3.0.0"},
                                   {"fixed": "3.13.0"}]}],
        }],
    }]}


def _stub_fetch(coordinate: str, payload: bytes) -> dict:
    assert json.loads(payload)["package"]["name"] == coordinate
    assert json.loads(payload)["package"]["ecosystem"] == "Maven"
    return _stub_response()


class QueryTrimming(unittest.TestCase):
    def test_coordinate_mapping(self):
        self.assertEqual(
            coordinate_for({"id": "okhttp"}), "com.squareup.okhttp3:okhttp"
        )
        self.assertIsNone(coordinate_for({"id": "unknown-sdk"}))
        self.assertIsNone(coordinate_for({}))

    def test_osv_package_ecosystems(self):
        self.assertEqual(
            osv_package({"id": "okhttp"}),
            ("com.squareup.okhttp3:okhttp", "Maven"),
        )
        self.assertEqual(
            osv_package({"id": "alamofire-ios"}),
            ("https://github.com/Alamofire/Alamofire", "SwiftURL"),
        )
        self.assertEqual(
            osv_package({"id": "firebase-messaging-ios"}),
            ("https://github.com/firebase/firebase-ios-sdk", "SwiftURL"),
        )
        # closed-source SDKs are detected but deliberately unmapped
        self.assertIsNone(osv_package({"id": "applovin-ios"}))
        self.assertIsNone(osv_package({"id": "inmobi"}))
        self.assertIsNone(osv_package({}))

    def test_query_trims_fields(self):
        advisories = query_osv("com.squareup.okhttp3:okhttp", fetch=_stub_fetch)
        self.assertEqual(len(advisories), 1)
        a = advisories[0]
        self.assertEqual(a["id"], "GHSA-test-0001")
        self.assertEqual(a["versions"], ["3.10.0", "3.11.0"])
        self.assertEqual(a["fixed"], ["3.13.0"])
        self.assertEqual(a["summary"], "an example vulnerability in the library")

    def test_query_swift_ecosystem_payload(self):
        seen = {}

        def fetch(coordinate: str, payload: bytes) -> dict:
            seen.update(json.loads(payload))
            return {"vulns": []}

        repo = "https://github.com/Alamofire/Alamofire"
        advisories = query_osv(repo, ecosystem="SwiftURL", fetch=fetch)
        self.assertEqual(advisories, [])
        self.assertEqual(
            seen["package"],
            {"name": repo, "ecosystem": "SwiftURL"},
        )

    def test_empty_response(self):
        self.assertEqual(query_osv("x:y", fetch=lambda c, p: {}), [])


class VersionMatching(unittest.TestCase):
    def test_exact_list_match(self):
        self.assertTrue(matches_version(ADVISORY, "3.11.0"))

    def test_below_fixed_matches(self):
        self.assertTrue(matches_version(ADVISORY, "3.12.9"))

    def test_at_fixed_does_not_match(self):
        self.assertFalse(matches_version(ADVISORY, "3.13.0"))

    def test_above_fixed_does_not_match(self):
        self.assertFalse(matches_version(ADVISORY, "4.0.0"))

    def test_unparseable_version_never_matches(self):
        self.assertFalse(matches_version(ADVISORY, "release-candidate"))
        self.assertFalse(matches_version({"versions": [], "fixed": []}, "1.0"))


class CacheBehaviour(unittest.TestCase):
    def _now(self):
        return datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_save_load_roundtrip(self):
        tmp = tempfile.mkdtemp(prefix="masan_osv_")
        try:
            path = os.path.join(tmp, "osv.json")
            cache = OsvCache()
            cache.update("a:b", [ADVISORY], when=self._now())
            cache.save(path)
            loaded = OsvCache.load(path)
            self.assertEqual(loaded.entries["a:b"]["advisories"], [ADVISORY])
            self.assertFalse(loaded.stale("a:b", now=self._now()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_stale_entries(self):
        cache = OsvCache()
        self.assertTrue(cache.stale("a:b"), "missing entry is stale")
        cache.update("a:b", [], when=self._now() - timedelta(days=9))
        self.assertTrue(cache.stale("a:b", now=self._now()))
        cache.update("a:b", [], when=self._now() - timedelta(hours=1))
        self.assertFalse(cache.stale("a:b", now=self._now()))

    def test_refresh_respects_ttl_and_force(self):
        cache = OsvCache()
        cache.update("a:b", [ADVISORY], when=self._now())
        self.assertFalse(cache.refresh("a:b", ttl=86400, now=self._now()))
        self.assertTrue(cache.refresh("a:b", fetch=_stub_fetch, force=True,
                                      when=self._now()))
        self.assertEqual(len(cache.advisories_for("a:b")), 1)

    def test_save_writes_provenance_meta(self):
        tmp = tempfile.mkdtemp(prefix="masan_osv_meta_")
        try:
            path = os.path.join(tmp, "osv.json")
            cache = OsvCache()
            cache.update("a:b", [ADVISORY], when=self._now())
            cache.update("c:d", [], when=self._now() - timedelta(days=9))
            cache.save(path)
            loaded = OsvCache.load(path)
            self.assertEqual(loaded.meta["coordinates"], 2)
            self.assertEqual(loaded.meta["advisories"], 1)
            self.assertEqual(loaded.meta["built"], self._now().isoformat())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_freshness_counts_stale_coordinates(self):
        cache = OsvCache()
        cache.update("a:b", [ADVISORY], when=self._now())
        cache.update("c:d", [], when=self._now() - timedelta(days=9))
        fresh = cache.freshness(now=self._now())
        self.assertEqual(fresh["coordinates"], 2)
        self.assertEqual(fresh["stale"], 1)
        self.assertEqual(fresh["built"], self._now().isoformat())
        empty = OsvCache().freshness(now=self._now())
        self.assertEqual(empty["coordinates"], 0)
        self.assertEqual(empty["built"], "")

    def test_age_days_with_injected_clock(self):
        cache = OsvCache()
        cache.update("a:b", [], when=self._now() - timedelta(days=3))
        self.assertEqual(cache.age_days(now=self._now()), 3)
        self.assertIsNone(OsvCache().age_days(now=self._now()))


class FindingEmission(unittest.TestCase):
    """MAS-SCA-003 fires from the m02 analyzer using target.meta['osv_intel']."""

    def _target_with(okhttp_version: str):  # noqa: N805 - helper
        from masanalyzer.model import Target

        t = Target(input_path="synthetic", platform="android",
                   work_dir=".", name="x")
        t.meta["sdks"] = [{
            "id": "okhttp", "vendor": "OkHttp", "category": "network",
            "version": okhttp_version, "evidence": ["Lokhttp3/OkHttpClient;"],
        }]
        return t

    def test_matching_version_emits_sca003(self):
        from masanalyzer.analysis import m02

        target = FindingEmission._target_with("3.12.0")
        target.meta["osv_intel"] = {
            "osv": 1,
            "entries": {
                "com.squareup.okhttp3:okhttp": {
                    "fetched": "2026-06-01T00:00:00+00:00",
                    "advisories": [ADVISORY],
                },
            },
        }
        findings = [f for f in m02.analyze(target)
                    if f.rule_id == "MAS-SCA-003"]
        self.assertEqual(len(findings), 1)
        self.assertIn("GHSA-test-0001", findings[0].evidence.note)

    def test_safe_version_emits_nothing(self):
        from masanalyzer.analysis import m02

        target = FindingEmission._target_with("4.0.0")
        target.meta["osv_intel"] = {
            "osv": 1,
            "entries": {
                "com.squareup.okhttp3:okhttp": {
                    "fetched": "2026-06-01T00:00:00+00:00",
                    "advisories": [ADVISORY],
                },
            },
        }
        findings = [f for f in m02.analyze(target)
                    if f.rule_id == "MAS-SCA-003"]
        self.assertEqual(findings, [])

    def test_scan_end_to_end_with_cache(self):
        from masanalyzer.scanner import scan

        tmp = tempfile.mkdtemp(prefix="masan_osv_e2e_")
        try:
            dex = build_dex((
                b"Lokhttp3/OkHttpClient;",
                b"okhttp/3.12.0",
                b"Lcom/example/app;",
            ), types=[2], classes=[0], methods=[(0, 2)])
            apk = build_apk(os.path.join(tmp, "app.apk"), dex=dex)
            cache_path = os.path.join(tmp, "osv.json")
            cache = OsvCache()
            cache.update("com.squareup.okhttp3:okhttp", [ADVISORY],
                         when=datetime.now(timezone.utc))
            cache.save(cache_path)

            result = scan(apk, osv_cache=cache_path)
            ids = [f.rule_id for f in result.findings]
            cve_hits = [f for f in result.findings if f.rule_id == "MAS-SCA-003"]
            self.assertTrue(cve_hits, f"expected MAS-SCA-003, got {ids}")
            self.assertIn("GHSA-test-0001", cve_hits[0].evidence.note)

            # without a cache: no MAS-SCA-003 and no network error
            plain = scan(apk)
            self.assertFalse(
                [f for f in plain.findings if f.rule_id == "MAS-SCA-003"]
            )

            # the scan result carries deterministic cache provenance
            status = result.target.meta.get("intel_status") or {}
            self.assertEqual(status.get("coordinates"), 1)
            self.assertEqual(status.get("advisories"), 1)
            self.assertTrue(status.get("built"))
            self.assertNotIn(
                "stale", status,
                "wall-clock data must never enter reports (determinism)")

            # provenance lands in report.json inventory
            from masanalyzer.reporting import render

            doc = json.loads(render(result, "json"))
            intel = doc["inventory"].get("intel") or {}
            self.assertEqual(intel.get("coordinates"), 1)
            self.assertEqual(intel.get("advisories"), 1)
            self.assertIn("OSV.dev", intel.get("source", ""))

            # and the markdown carries the refresh hint
            md = render(result, "md")
            self.assertIn("masanalyzer-refresh-intel", md)

            # a cacheless scan has no intel section at all
            plain_doc = json.loads(render(plain, "json"))
            self.assertNotIn("intel", plain_doc.get("inventory") or {})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class AutoRefresh(unittest.TestCase):
    """The scan keeps its own CVE data current: stale coordinates are
    re-queried at scan time (best-effort), offline failures never fatal."""

    def _okhttp_apk(self, tmp):
        dex = build_dex((
            b"Lokhttp3/OkHttpClient;",
            b"okhttp/3.12.0",
            b"Lcom/example/app;",
        ), types=[2], classes=[0], methods=[(0, 2)])
        return build_apk(os.path.join(tmp, "app.apk"), dex=dex)

    def _scan_with_patched_query(self, tmp, fetch):
        """scan() with the raw OSV fetch layer patched to a stub; the
        trimming ``query_osv`` stays real. Returns (result, cache_path)."""
        from unittest.mock import patch

        from masanalyzer.scanner import scan

        apk = self._okhttp_apk(tmp)
        cache_path = os.path.join(tmp, "osv.json")
        cache = OsvCache()
        cache.update("com.squareup.okhttp3:okhttp", [ADVISORY],
                     when=datetime.now(timezone.utc) - timedelta(days=30))
        cache.save(cache_path)
        with patch("masanalyzer.osv._default_fetch", side_effect=fetch):
            result = scan(apk, osv_cache=cache_path)
        return result, cache_path

    def test_auto_refresh_queries_and_persists(self):
        tmp = tempfile.mkdtemp(prefix="masan_auto_")
        try:
            calls = []

            def fetch(coordinate, _payload):
                calls.append(coordinate)
                return _stub_response()

            result, cache_path = self._scan_with_patched_query(tmp, fetch)
            self.assertEqual(calls, ["com.squareup.okhttp3:okhttp"])
            self.assertEqual(
                result.target.meta.get("intel_refresh", {}).get("refreshed"),
                1)
            # the fresher view was persisted back to the cache file
            on_disk = OsvCache.load(cache_path)
            self.assertLess(
                (datetime.now(timezone.utc)
                 - datetime.fromisoformat(
                     on_disk.entries["com.squareup.okhttp3:okhttp"]
                     ["fetched"])).total_seconds(),
                120,
                "auto-refresh must stamp a fresh fetch time")
            # and the advisory still matches the bundle's SDK version
            self.assertTrue(
                [f for f in result.findings if f.rule_id == "MAS-SCA-003"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_offline_scan_degrades_gracefully(self):
        tmp = tempfile.mkdtemp(prefix="masan_off_")
        try:
            def fetch(_coordinate, _payload):
                raise OSError("network unreachable")

            result, _path = self._scan_with_patched_query(tmp, fetch)
            info = result.target.meta.get("intel_refresh") or {}
            self.assertEqual(info.get("failed"), 1)
            self.assertEqual(info.get("refreshed"), 0)
            # cached advisory still drives the finding
            hits = [f for f in result.findings if f.rule_id == "MAS-SCA-003"]
            self.assertTrue(hits, "offline scan must keep cached currency")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_refresh_disabled_keeps_cache_untouched(self):
        tmp = tempfile.mkdtemp(prefix="masan_norefresh_")
        try:
            calls = []

            def fetch(coordinate, _payload):
                calls.append(coordinate)
                return _stub_response()

            from unittest.mock import patch

            from masanalyzer.scanner import scan

            apk = self._okhttp_apk(tmp)
            cache_path = os.path.join(tmp, "osv.json")
            cache = OsvCache()
            cache.update("com.squareup.okhttp3:okhttp", [ADVISORY],
                         when=datetime.now(timezone.utc) - timedelta(days=30))
            cache.save(cache_path)
            with patch("masanalyzer.osv._default_fetch", side_effect=fetch):
                scan(apk, osv_cache=cache_path, refresh_intel=False)
            self.assertEqual(calls, [], "--no-intel-refresh must not query")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_auto_refresh_unit_respects_ttl_and_counts(self):
        from masanalyzer.osv import auto_refresh

        cache = OsvCache()
        cache.update("com.squareup.okhttp3:okhttp", [],
                     when=datetime.now(timezone.utc))  # fresh -> no query
        calls = []

        def fetch(coordinate, _payload):
            calls.append(coordinate)
            return _stub_response()

        hits = [{"id": "okhttp", "version": "3.12.0"}]
        refreshed, failed = auto_refresh(cache, hits, fetch=fetch)
        self.assertEqual((refreshed, failed), (0, 0))
        self.assertEqual(calls, [])
        # now with force: one query, no failure
        refreshed, failed = auto_refresh(cache, hits, fetch=fetch, force=True)
        self.assertEqual((refreshed, failed), (1, 0))
        # unmapped SDK ids never query
        refreshed, failed = auto_refresh(
            cache, [{"id": "unknown-sdk", "version": "1.0"}], fetch=fetch)
        self.assertEqual((refreshed, failed), (0, 0))
        # fetch raising counts as failure, never raises
        def broken(_c, _p):
            raise OSError("down")

        refreshed, failed = auto_refresh(
            cache, hits, fetch=broken, force=True)
        self.assertEqual((refreshed, failed), (0, 1))


class CurrencyWarnings(unittest.TestCase):
    """Operational staleness notices (stderr/dashboard), never in reports."""

    def _old_cache(self, tmp):
        cache = OsvCache()
        cache.update("a:b", [ADVISORY],
                     when=datetime.now(timezone.utc) - timedelta(days=30))
        path = os.path.join(tmp, "old.json")
        cache.save(path)
        return path

    def test_cli_warns_on_old_cache(self):
        import io

        from masanalyzer.cli import _warn_intel_age

        tmp = tempfile.mkdtemp(prefix="masan_osv_warn_")
        try:
            buf = io.StringIO()
            _warn_intel_age(self._old_cache(tmp), buf)
            self.assertIn("masanalyzer-refresh-intel", buf.getvalue())
            self.assertIn("30 day(s) old", buf.getvalue())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cli_silent_on_fresh_cache_and_no_cache(self):
        import io

        from masanalyzer.cli import _warn_intel_age

        tmp = tempfile.mkdtemp(prefix="masan_osv_ok_")
        try:
            cache = OsvCache()
            cache.update("a:b", [ADVISORY], when=datetime.now(timezone.utc))
            path = os.path.join(tmp, "fresh.json")
            cache.save(path)
            buf = io.StringIO()
            _warn_intel_age(path, buf)
            self.assertEqual(buf.getvalue(), "")
            buf2 = io.StringIO()
            _warn_intel_age(None, buf2)
            self.assertEqual(buf2.getvalue(), "")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class IpaCurrency(unittest.TestCase):
    """iOS side: framework detection -> pod coordinate -> cache finding."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_osv_ipa_")
        cls.ipa = build_ipa(
            os.path.join(cls.tmp, "app.ipa"),
            frameworks={"Alamofire": "4.0.0", "FirebaseMessaging": "7.0.0"},
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_ios_frameworks_detected_with_versions(self):
        from masanalyzer.scanner import scan

        result = scan(self.ipa)
        sdks = result.target.meta.get("sdks") or []
        by_id = {s["id"]: s for s in sdks}
        self.assertIn("alamofire-ios", by_id)
        self.assertEqual(by_id["alamofire-ios"].get("version"), "4.0.0")
        self.assertEqual(by_id["alamofire-ios"].get("category"), "network")
        self.assertIn("firebase-messaging-ios", by_id)
        self.assertEqual(
            by_id["firebase-messaging-ios"].get("version"), "7.0.0"
        )
        evidence = " ".join(by_id["alamofire-ios"].get("evidence") or [])
        self.assertIn("alamofire.framework", evidence.lower())

    def test_mas_sca_003_fires_for_unfixed_pod_version(self):
        # a cache whose Alamofire entry enumerates 4.0.0; Firebase stays
        # advisory-free so nothing may fire for it
        from masanalyzer.analysis import m02
        from masanalyzer.scanner import scan

        result = scan(self.ipa)
        result.target.meta["osv_intel"] = {
            "osv": 1,
            "entries": {
                "https://github.com/Alamofire/Alamofire": {
                    "fetched": "2026-06-01T00:00:00+00:00",
                    "ecosystem": "SwiftURL",
                    "advisories": [{
                        "id": "GHSA-swift-test",
                        "summary": "example pod advisory",
                        "modified": "2026-01-01T00:00:00Z",
                        "versions": ["4.0.0"],
                        "fixed": ["4.1.0"],
                    }],
                },
            },
        }
        findings = [f for f in m02.analyze(result.target)
                    if f.rule_id == "MAS-SCA-003"]
        self.assertEqual(len(findings), 1)
        self.assertIn("alamofire-ios", findings[0].evidence.note)
        self.assertIn("GHSA-swift-test", findings[0].evidence.note)

    def test_scan_end_to_end_with_pod_cache(self):
        from masanalyzer.scanner import scan

        cache_path = os.path.join(self.tmp, "osv.json")
        cache = OsvCache()
        cache.update("https://github.com/Alamofire/Alamofire", [{
            "id": "GHSA-swift-test",
            "summary": "example pod advisory",
            "modified": "2026-01-01T00:00:00Z",
            "versions": ["4.0.0"],
            "fixed": ["4.1.0"],
        }], ecosystem="SwiftURL", when=datetime.now(timezone.utc))
        cache.save(cache_path)

        result = scan(self.ipa, osv_cache=cache_path)
        hits = [f for f in result.findings if f.rule_id == "MAS-SCA-003"]
        self.assertTrue(
            hits, "alamofire-ios 4.0.0 must match the cached pod advisory"
        )
        self.assertIn("GHSA-swift-test", hits[0].evidence.note)


class RefreshCli(unittest.TestCase):
    def test_cli_refreshes_and_caches(self):
        from masanalyzer.intelcli import main

        tmp = tempfile.mkdtemp(prefix="masan_osv_cli_")
        try:
            dex = build_dex((
                b"Lokhttp3/OkHttpClient;",
                b"okhttp/3.12.0",
                b"Lcom/example/app;",
            ), types=[2], classes=[0], methods=[(0, 2)])
            apk = build_apk(os.path.join(tmp, "app.apk"), dex=dex)
            cache_path = os.path.join(tmp, "cache", "osv.json")
            code = main([apk, "--cache", cache_path], fetch=_stub_fetch)
            self.assertEqual(code, 0)
            with open(cache_path, "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            self.assertIn("com.squareup.okhttp3:okhttp", doc["entries"])
            advs = doc["entries"]["com.squareup.okhttp3:okhttp"]["advisories"]
            self.assertEqual(advs[0]["id"], "GHSA-test-0001")

            # a second (non-forced) run must not re-query, still exit 0
            calls = {"n": 0}

            def counting_fetch(c, p):
                calls["n"] += 1
                return _stub_response()

            code = main([apk, "--cache", cache_path], fetch=counting_fetch)
            self.assertEqual(code, 0)
            self.assertEqual(calls["n"], 0, "TTL must suppress re-queries")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

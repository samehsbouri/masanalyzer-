"""CVE currency for third-party SDK findings, via the OSV.dev public API.

The curated ``VULNERABLE_SDKS`` table in :mod:`masanalyzer.sdks` freezes at
whatever facts shipped with the tool.  To age well, deployments refresh an
*OSV cache*: one HTTP POST per known Maven coordinate to the keyless
``https://api.osv.dev/v1/query`` endpoint (stdlib ``urllib`` only),
trimmed advisories merged into a JSON file on disk.

Two refresh paths:

* explicit: ``masanalyzer-refresh-intel`` (CI cron / pre-release step);
* automatic: :func:`scan` refreshes the stale coordinates of the SDKs it
  just detected before the SCA rules run (best-effort, short timeout —
  a machine without network simply keeps its cache and every coordinate
  failure is counted, never fatal).  Disable per-scan with
  ``refresh_intel=False`` (CLI ``--no-intel-refresh``).

At match time the cache is read-only: advisories become ``MAS-SCA-003``
findings keyed by advisory id — exactly what OSV.dev said at the newest
fetch.

Conservative-claims policy: masanalyzer reports what the OSV database says
about a package coordinate and the version string observed in the bundle;
it does not invent advisories, and unknown tokens simply match nothing.
Android coordinates query ecosystem ``Maven``; iOS framework ids query
ecosystem ``SwiftURL`` (the Swift advisory database keys packages by git
repository URL).
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

OSV_API = "https://api.osv.dev/v1/query"

#: cache entries older than this are re-fetched by the refresh CLI
TTL_SECONDS = 24 * 3600

FetchFn = Callable[[str, bytes], dict]


# --------------------------------------------------------------------------
# Maven coordinates for detected SDKs (conservative subset; extend freely)
# --------------------------------------------------------------------------
MAVEN_COORDS: Dict[str, str] = {
    "okhttp": "com.squareup.okhttp3:okhttp",
    "retrofit": "com.squareup.retrofit2:retrofit",
    "glide": "com.github.bumptech.glide:glide",
    "picasso": "com.squareup.picasso:picasso",
    "gson": "com.google.code.gson:gson",
    "jackson": "com.fasterxml.jackson.core:jackson-databind",
    "jsoup": "org.jsoup:jsoup",
    "sentry": "io.sentry:sentry-android",
    "kotlin-stdlib": "org.jetbrains.kotlin:kotlin-stdlib",
    "grpc": "io.grpc:grpc-core",
    "coil": "io.coil-kt:coil",
    "fresco": "com.facebook.fresco:fresco",
    "zxing": "com.google.zxing:core",
    "stripe": "com.stripe:stripe-android",
}

#: iOS SDK ids -> git repository URLs.  The OSV ``SwiftURL`` ecosystem
#: (https://github.com/swift-advisories) identifies packages by their
#: repository URL, so those are the coordinates — verified against the
#: live /v1/query endpoint.  Extend at deployment time for internal pods
#: and frameworks; SDK hits without a mapping are inventoried but never
#: matched (claims nothing).
IOS_POD_COORDS: Dict[str, str] = {
    "alamofire-ios": "https://github.com/Alamofire/Alamofire",
    "trustkit-ios": "https://github.com/datadog/TrustKit",
    "amplitude-ios": "https://github.com/amplitude/Amplitude-iOS",
    "mixpanel-ios": "https://github.com/mixpanel/mixpanel-iphone",
    "appsflyer-ios": "https://github.com/AppsFlyerAF/AppsFlyerFramework",
    "sentry-ios": "https://github.com/getsentry/sentry-cocoa",
    "bugsnag-ios": "https://github.com/bugsnag/bugsnag-cocoa",
    "stripe-ios": "https://github.com/stripe/stripe-ios",
    "onesignal-ios": "https://github.com/OneSignal/OneSignal-iOS-SDK",
    "firebase-core-ios": "https://github.com/firebase/firebase-ios-sdk",
    "firebase-messaging-ios":
        "https://github.com/firebase/firebase-ios-sdk",
    "firebase-database-ios":
        "https://github.com/firebase/firebase-ios-sdk",
    "firebase-crashlytics-ios":
        "https://github.com/firebase/firebase-ios-sdk",
    # deliberately unmapped: AppLovinSDK ships as a closed-source binary
    # with no public repository, so no OSV coordinate can be claimed.
}


def coordinate_for(hit: dict) -> Optional[str]:
    """Maven ``group:artifact`` for a detected SDK id, if mapped."""
    return MAVEN_COORDS.get(str(hit.get("id") or ""))


def osv_package(hit: dict) -> Optional[Tuple[str, str]]:
    """``(package_name, ecosystem)`` for a detected SDK hit.

    Android ids resolve through :data:`MAVEN_COORDS` (ecosystem ``Maven``),
    iOS framework ids through :data:`IOS_POD_COORDS` (ecosystem
    ``SwiftURL`` — git repository URLs).  Unmapped ids yield ``None`` —
    without a coordinate the deployment can never tie an advisory to the
    hit, so nothing is claimed.
    """
    sdk_id = str(hit.get("id") or "")
    maven = MAVEN_COORDS.get(sdk_id)
    if maven:
        return (maven, "Maven")
    pod = IOS_POD_COORDS.get(sdk_id)
    if pod:
        return (pod, "SwiftURL")
    return None


# --------------------------------------------------------------------------
# OSV /v1/query
# --------------------------------------------------------------------------
def _default_fetch(coordinate: str, payload: bytes) -> dict:
    request = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_DEFAULT_TIMEOUT) as resp:
        body = resp.read()
        return json.loads(body.decode("utf-8", "replace"))


_DEFAULT_TIMEOUT = 15


def query_osv(
    coordinate: str,
    ecosystem: str = "Maven",
    fetch: Optional[FetchFn] = None,
    timeout: Optional[float] = None,
) -> List[dict]:
    """One OSV query; returns trimmed advisories: id/summary/modified/
    versions/fixed.  ``ecosystem`` selects the OSV package index —
    ``Maven`` for Android coordinates, ``Swift`` for CocoaPods/SPM names.
    ``fetch`` (coordinate, payload) -> parsed response exists for tests
    and for offline/diagnostic tooling."""
    global _DEFAULT_TIMEOUT
    if timeout is not None:
        _DEFAULT_TIMEOUT = timeout
    payload = json.dumps(
        {"package": {"name": coordinate, "ecosystem": ecosystem}}
    ).encode("utf-8")
    fn = fetch or _default_fetch
    raw = fn(coordinate, payload)
    out: List[dict] = []
    for vuln in raw.get("vulns") or []:
        versions: List[str] = []
        fixed: List[str] = []
        for affected in vuln.get("affected") or []:
            versions.extend(str(v) for v in (affected.get("versions") or []))
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if "fixed" in event:
                        fixed.append(str(event["fixed"]))
        out.append(
            {
                "id": str(vuln.get("id") or "?"),
                "summary": str(vuln.get("summary") or ""),
                "modified": str(vuln.get("modified") or ""),
                "versions": sorted(versions),
                "fixed": sorted(fixed),
            }
        )
    return out


def _version_tuple(version: str) -> Optional[Tuple[int, ...]]:
    parts = tuple(int(p) for p in re.findall(r"\d+", str(version))[:3])
    return parts if parts else None


def matches_version(advisory: dict, version: str) -> bool:
    """True when ``version`` is affected per the cached advisory shape.

    Exact member of the advisory's enumerated versions, or below the
    earliest fixed range event (tuple compare, conservative direction).
    """
    if not version:
        return False
    if version in (advisory.get("versions") or []):
        return True
    vt = _version_tuple(version)
    if not vt:
        return False
    for fixed in advisory.get("fixed") or []:
        ft = _version_tuple(fixed)
        if ft and vt < ft:
            return True
    return False


# --------------------------------------------------------------------------
# cache file (JSON on disk)
# --------------------------------------------------------------------------
def default_cache_path() -> str:
    """Per-user cache location (overridable by MASAN_HOME)."""
    root = os.environ.get("MASAN_HOME",
                          os.path.join(os.path.expanduser("~"), ".masan"))
    return os.path.join(root, "intel", "osv.json")


def _parse_when(iso: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(iso))
    except (ValueError, TypeError):
        return None


class OsvCache:
    """JSON hold-all: ``{group:artifact: {"fetched": iso, "advisories": []}}``."""

    def __init__(self, entries: Optional[Dict[str, dict]] = None,
                 meta: Optional[Dict[str, Any]] = None) -> None:
        self.entries: Dict[str, dict] = dict(entries or {})
        self.meta: Dict[str, Any] = dict(meta or {})

    # -- load / save ------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str] = None) -> "OsvCache":
        path = path or default_cache_path()
        with open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8", "replace"))
        entries = doc.get("entries") if isinstance(doc, dict) else None
        meta = doc.get("meta") if isinstance(doc, dict) else None
        return cls(entries if isinstance(entries, dict) else {},
                   meta if isinstance(meta, dict) else {})

    @classmethod
    def from_dict(cls, doc: dict) -> "OsvCache":
        entries = doc.get("entries") if isinstance(doc, dict) else None
        meta = doc.get("meta") if isinstance(doc, dict) else None
        return cls(entries if isinstance(entries, dict) else {},
                   meta if isinstance(meta, dict) else {})

    def save(self, path: Optional[str] = None) -> str:
        path = path or default_cache_path()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # deterministic provenance: derived from the entries themselves
        built = max(
            (str(e.get("fetched") or "") for e in self.entries.values()),
            default="",
        )
        self.meta = {
            "built": built,
            "coordinates": len(self.entries),
            "advisories": sum(
                len(e.get("advisories") or []) for e in self.entries.values()
            ),
        }
        with open(path, "wb") as fh:
            fh.write(
                json.dumps({"osv": 1, "meta": self.meta,
                            "entries": self.entries},
                           indent=1, sort_keys=True).encode("utf-8")
            )
        return path

    # -- maintenance -------------------------------------------------------
    def stale(self, coordinate: str, ttl: int = TTL_SECONDS,
              now: Optional[datetime] = None) -> bool:
        entry = self.entries.get(coordinate)
        fetched = _parse_when((entry or {}).get("fetched", ""))
        if fetched is None:
            return True
        now = now or datetime.now(timezone.utc)
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        return (now - fetched) >= timedelta(seconds=ttl)

    def update(self, coordinate: str, advisories: List[dict],
               when: Optional[datetime] = None,
               ecosystem: str = "Maven") -> None:
        when = when or datetime.now(timezone.utc)
        self.entries[coordinate] = {
            "fetched": when.isoformat(),
            "ecosystem": ecosystem,
            "advisories": list(advisories),
        }

    def refresh(self, coordinate: str, fetch: Optional[FetchFn] = None,
                ttl: int = TTL_SECONDS, force: bool = False,
                when: Optional[datetime] = None,
                now: Optional[datetime] = None,
                ecosystem: str = "Maven",
                timeout: Optional[float] = None) -> bool:
        """Fetch + merge one coordinate unless a fresh entry already covers
        it.  Returns True when a fetch happened.  ``now`` (staleness clock)
        and ``when`` (stamped fetch time) are injectable for tests."""
        if not force:
            clock = now if now is not None else when
            if not self.stale(coordinate, ttl=ttl, now=clock):
                return False
        self.update(coordinate, query_osv(coordinate, ecosystem=ecosystem,
                                          fetch=fetch, timeout=timeout),
                    when=when, ecosystem=ecosystem)
        return True

    # -- queries -----------------------------------------------------------
    def advisories_for(self, coordinate: str) -> List[dict]:
        entry = self.entries.get(coordinate) or {}
        return list(entry.get("advisories") or [])

    def matching(self, hit: dict) -> List[Tuple[str, dict]]:
        """``[(coordinate, advisory)]`` for one SDK hit, cache-shaped."""
        package = osv_package(hit)
        if package is None:
            return []
        coordinate = package[0]
        version = str(hit.get("version") or "")
        return [
            (coordinate, adv)
            for adv in self.advisories_for(coordinate)
            if matches_version(adv, version)
        ]

    def as_dict(self) -> dict:
        return {"osv": 1, "meta": dict(self.meta), "entries": self.entries}

    # -- freshness -----------------------------------------------------------
    def freshness(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """How current is this CVE data?

        Returns ``{"built", "coordinates", "advisories", "stale"}`` where
        ``built`` is the newest per-coordinate fetch timestamp (deterministic
        — derived from the cache content only) and ``stale`` counts
        coordinates older than :data:`TTL_SECONDS`. Safe on an empty cache.
        """
        stale = 0
        for coordinate in self.entries:
            if self.stale(coordinate, now=now):
                stale += 1
        return {
            "built": str(self.meta.get("built") or "") or self._max_fetched(),
            "coordinates": len(self.entries),
            "advisories": sum(
                len(e.get("advisories") or []) for e in self.entries.values()
            ),
            "stale": stale,
        }

    def _max_fetched(self) -> str:
        return max(
            (str(e.get("fetched") or "") for e in self.entries.values()),
            default="",
        )

    def age_days(self, now: Optional[datetime] = None) -> Optional[int]:
        """Whole days since the newest fetch; None when unknown."""
        built = _parse_when(self.freshness(now=now).get("built") or "")
        if built is None:
            return None
        now = now or datetime.now(timezone.utc)
        if built.tzinfo is None:
            built = built.replace(tzinfo=timezone.utc)
        return max(0, (now - built).days)


def cache_from(value: Any) -> Optional[OsvCache]:
    """Accept a path, a loaded dict, or an :class:`OsvCache` instance."""
    if value is None:
        return None
    if isinstance(value, OsvCache):
        return value
    if isinstance(value, dict):
        return OsvCache.from_dict(value)
    if isinstance(value, (str, bytes, os.PathLike)):
        return OsvCache.load(os.fspath(value))
    return None


#: network timeout for the automatic in-scan refresh (kept short so a
#: machine without connectivity does not stall the scan)
AUTO_REFRESH_TIMEOUT = 5.0


def auto_refresh(
    cache: OsvCache,
    hits: Iterable[dict],
    fetch: Optional[FetchFn] = None,
    ttl: int = TTL_SECONDS,
    force: bool = False,
    when: Optional[datetime] = None,
    now: Optional[datetime] = None,
    timeout: Optional[float] = None,
) -> Tuple[int, int]:
    """Best-effort refresh of the coordinates behind detected SDK hits.

    Stale (or never-fetched) coordinates are queried; fresh ones keep
    their cache entry.  Network errors are counted, never raised — a
    machine without connectivity simply keeps its cached view.  Returns
    ``(refreshed, failed)``.
    """
    refreshed = failed = 0
    for hit in hits or []:
        package = osv_package(hit)
        if package is None:
            continue
        coordinate, ecosystem = package
        try:
            if cache.refresh(coordinate, fetch=fetch, ttl=ttl,
                             force=force, when=when, now=now,
                             ecosystem=ecosystem, timeout=timeout):
                refreshed += 1
        except Exception:  # noqa: BLE001 - offline / transient: keep cache
            failed += 1
    return refreshed, failed

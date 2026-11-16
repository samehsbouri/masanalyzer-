"""Embedded third-party SDK fingerprinting (software-composition analysis).

Goal: answer *"which third-party SDKs are actually inside this bundle?"*
by matching curated class-descriptor / string signatures against the DEX
string tables (guaranteed complete — this module iterates every DEX
directly, immune to the ``string_pool`` cap) plus the shared string pool
and native-library strings.

What this is *not*: it does not claim a version is vulnerable on our own
authority. Detecting an SDK is reported as component inventory; the
version-aware findings come from the ``VULNERABLE_SDKS`` table (see
:func:`vulnerable_version_check`) — a small conservative default that
ships with the tool, overridable by integrators via
:func:`add_vulnerable_rule`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------
# signature database (curated; category drives report grouping)
# --------------------------------------------------------------------------
def _sig(sdk_id: str, vendor: str, category: str, prefixes: Tuple[str, ...],
         version_rxs: Tuple[str, ...] = ()) -> dict:
    return {
        "id": sdk_id,
        "vendor": vendor,
        "category": category,
        "prefixes": prefixes,
        "version_rxs": version_rxs,
    }


SDK_SIGNATURES: Tuple[dict, ...] = (
    # --- ads / attribution --------------------------------------------------
    _sig("appsflyer", "Appsflyer", "ads", ("Lcom/appsflyer/",)),
    _sig("adjust", "Adjust", "ads", ("Lcom/adjust/sdk/",)),
    _sig("branch", "Branch", "ads", ("Lio/branch/",)),
    _sig("kochava", "Kochava", "ads", ("Lcom/kochava/",)),
    _sig("inmobi", "InMobi", "ads", ("Lcom/inmobi/",)),
    _sig("admob", "Google AdMob", "ads", ("Lcom/google/android/gms/ads/", "Lcom/google/ads/")),
    _sig("unity-ads", "Unity Ads", "ads", ("Lcom/unity3d/ads/",)),
    _sig("vungle", "Vungle", "ads", ("Lcom/vungle/",)),
    _sig("chartboost", "Chartboost", "ads", ("Lcom/chartboost/",)),
    _sig("applovin", "AppLovin", "ads", ("Lcom/applovin/",)),
    _sig("ironsource", "ironSource", "ads", ("Lcom/ironsource/",)),
    _sig("mopub", "MoPub", "ads", ("Lcom/mopub/",)),
    _sig("tapjoy", "Tapjoy", "ads", ("Lcom/tapjoy/",)),
    _sig("adcolony", "AdColony", "ads", ("Lcom/adcolony/",)),
    _sig("facebook-audience", "Meta Audience Network", "ads", ("Lcom/facebook/ads/",)),
    _sig("flurry", "Flurry", "ads", ("Lcom/flurry/",)),
    # --- analytics ------------------------------------------------------------
    _sig("firebase-analytics", "Google Firebase Analytics", "analytics", ("Lcom/google/firebase/analytics/", "Lcom/google/android/gms/measurement/")),
    _sig("countly", "Countly", "analytics", ("Lorg/countly/",)),
    _sig("amplitude", "Amplitude", "analytics", ("Lcom/amplitude/",)),
    _sig("mixpanel", "Mixpanel", "analytics", ("Lcom/mixpanel/",)),
    _sig("umeng", "Umeng", "analytics", ("Lcom/umeng/",)),
    _sig("talkingdata", "TalkingData", "analytics", ("Lcom/tendcloud/", "Lcom/talkingdata/",)),
    _sig("answers", "Answers (Fabric)", "analytics", ("Lcom/answers/",)),
    # --- crash / quality ----------------------------------------------------
    _sig("crashlytics", "Firebase Crashlytics", "crash", ("Lcom/crashlytics/", "Lio/fabric/")),
    _sig("firebase-crashlytics", "Firebase Crashlytics", "crash", ("Lcom/google/firebase/crashlytics/",)),
    _sig("sentry", "Sentry", "crash", ("Lio/sentry/",)),
    _sig("bugsnag", "Bugsnag", "crash", ("Lcom/bugsnag/",)),
    _sig("instabug", "Instabug", "crash", ("Lcom/instabug/",)),
    _sig("hockeyapp", "HockeyApp", "crash", ("Lnet/hockeyapp/",)),
    # --- push ---------------------------------------------------------------
    _sig("firebase-messaging", "Firebase Cloud Messaging", "push", ("Lcom/google/firebase/messaging/", "Lcom/google/android/gms/gcm/")),
    _sig("onesignal", "OneSignal", "push", ("Lcom/onesignal/",)),
    _sig("urbanairship", "Airship", "push", ("Lcom/urbanairship/",)),
    # --- payments -----------------------------------------------------------
    _sig("play-billing", "Google Play Billing", "payments", ("Lcom/android/billingclient/",)),
    _sig("stripe", "Stripe", "payments", ("Lcom/stripe/android/",)),
    _sig("braintree", "Braintree", "payments", ("Lcom/braintreepayments/",)),
    _sig("paypal", "PayPal", "payments", ("Lcom/paypal/android/",)),
    _sig("revenuecat", "RevenueCat", "payments", ("Lcom/revenuecat/",)),
    # --- social -------------------------------------------------------------
    _sig("facebook-login", "Facebook Login SDK", "social", ("Lcom/facebook/login/", "Lcom/facebook/FacebookSdk")),
    _sig("twitter-sdk", "Twitter SDK", "social", ("Lcom/twitter/sdk/",)),
    # --- image ---------------------------------------------------------------
    _sig("glide", "Glide", "image", ("Lcom/bumptech/glide/",)),
    _sig("picasso", "Picasso", "image", ("Lcom/squareup/picasso/",)),
    _sig("fresco", "Fresco", "image", ("Lcom/facebook/imagepipeline/", "Lcom/facebook/drawee/")),
    _sig("coil", "Coil", "image", ("Lcoil/",)),
    # --- network --------------------------------------------------------------
    _sig("okhttp", "OkHttp", "network", ("Lokhttp3/", "Lokhttp/",), ("okhttp/([0-9][0-9.]*)",)),
    _sig("retrofit", "Retrofit", "network", ("Lretrofit2/",)),
    _sig("apache-http", "Apache HttpClient (legacy Android port)", "network", ("Lorg/apache/http/",)),
    _sig("grpc", "gRPC", "network", ("Lio/grpc/",)),
    # --- runtime / framework -----------------------------------------------------
    _sig("kotlin-stdlib", "Kotlin Stdlib", "runtime", ("Lkotlin/",)),
    _sig("kotlin-coroutines", "Kotlinx Coroutines", "runtime", ("Lkotlinx/coroutines/",)),
    _sig("react-native", "React Native", "runtime", ("Lcom/facebook/react/",)),
    _sig("flutter", "Flutter", "runtime", ("Lio/flutter/",)),
    _sig("cordova", "Apache Cordova", "runtime", ("Lorg/apache/cordova/",)),
    _sig("play-services", "Google Play Services", "runtime", ("Lcom/google/android/gms/",)),
    # --- utility / io --------------------------------------------------------------
    _sig("gson", "Gson", "utility", ("Lcom/google/gson/",)),
    _sig("jackson", "Jackson", "utility", ("Lcom/fasterxml/jackson/",)),
    _sig("jsoup", "jsoup", "utility", ("Lorg/jsoup/",)),
    _sig("zxing", "ZXing", "utility", ("Lcom/google/zxing/",)),
    # --- ml -------------------------------------------------------------------------
    _sig("tensorflow-lite", "TensorFlow Lite", "ml", ("Lorg/tensorflow/lite/",)),
    _sig("opencv", "OpenCV", "ml", ("Lorg/opencv/",)),
)

class SdkHit(dict):
    """One detected SDK (a dict so it stays JSON-serializable)."""


# --------------------------------------------------------------------------
# iOS signatures: framework bundles inside an .app tree
# --------------------------------------------------------------------------
# On iOS, embedded third-party SDKs materialize as ``<Name>.framework``
# directories under ``Payload/<App>.app/Frameworks/`` (their version is
# almost always the ``CFBundleShortVersionString`` of the framework's own
# ``Info.plist``).  The curated table below names each *framework bundle*
# exactly as it ships; ``osv.IOS_POD_COORDS`` maps every id to its
# CocoaPods/SPM package name for the OSV CVE cache.
def _isig(sdk_id: str, vendor: str, category: str,
          frameworks: Tuple[str, ...]) -> dict:
    return {
        "id": sdk_id,
        "vendor": vendor,
        "category": category,
        "frameworks": frameworks,
    }


IOS_SDK_SIGNATURES: Tuple[dict, ...] = (
    # --- network -------------------------------------------------------------
    _isig("alamofire-ios", "Alamofire", "network", ("Alamofire",)),
    _isig("trustkit-ios", "TrustKit", "network", ("TrustKit",)),
    # --- analytics / ads -------------------------------------------------------
    _isig("amplitude-ios", "Amplitude", "analytics", ("Amplitude",)),
    _isig("mixpanel-ios", "Mixpanel", "analytics", ("Mixpanel",)),
    _isig("appsflyer-ios", "AppsFlyer", "ads", ("AppsFlyerLib",)),
    _isig("applovin-ios", "AppLovin", "ads", ("AppLovinSDK",)),
    # --- crash / quality ---------------------------------------------------------
    _isig("sentry-ios", "Sentry (cocoa)", "crash", ("Sentry",)),
    _isig("bugsnag-ios", "Bugsnag", "crash", ("Bugsnag", "BugsnagObjectiveCRuntime")),
    # --- payments ------------------------------------------------------------------
    _isig("stripe-ios", "Stripe", "payments", ("Stripe", "StripeCore", "StripePayments")),
    # --- push -----------------------------------------------------------------
    _isig("onesignal-ios", "OneSignal", "push", ("OneSignal",)),
    # --- runtime ----------------------------------------------------------------
    _isig("firebase-core-ios", "Firebase Core", "runtime", ("FirebaseCore",)),
    _isig("firebase-messaging-ios", "Firebase Cloud Messaging", "push",
          ("FirebaseMessaging",)),
    _isig("firebase-database-ios", "Firebase Realtime Database", "runtime",
          ("FirebaseDatabase",)),
    _isig("firebase-crashlytics-ios", "Firebase Crashlytics", "crash",
          ("FirebaseCrashlytics",)),
)

_FRAMEWORK_MAP: Dict[str, dict] = {}
for _ios_sig in IOS_SDK_SIGNATURES:
    for _fw in _ios_sig["frameworks"]:
        _FRAMEWORK_MAP.setdefault(_fw.lower(), _ios_sig)

_FRAMEWORK_RX = re.compile(r"([a-z0-9_]+)\.framework[/\\]", re.IGNORECASE)
_FW_VERSION_PLIST_RX = re.compile(r"^\d+(?:\.\d+){0,3}(?:[.+-]\w[\w.\-]*)?$")


def _ios_target_hits(target) -> Tuple[List[SdkHit], int]:
    """Detect iOS SDKs from ``<Name>.framework/`` paths + plists.

    Returns ``(hits, frameworks_seen)``; hits carry the framework dir as
    evidence and - when present - the CFBundleShortVersionString /
    CFBundleVersion of the framework's own Info.plist as version.
    """
    found: Dict[str, SdkHit] = {}
    fw_dirs: Dict[str, str] = {}
    for sf in getattr(target, "files", ()):
        rel = str(getattr(sf, "relpath", ""))
        for m in _FRAMEWORK_RX.finditer(rel.lower()):
            fw = m.group(1)
            if fw in fw_dirs:
                continue
            fw_dirs[fw] = rel
    sig_by_id: Dict[str, dict] = {}
    for fw, rel in sorted(fw_dirs.items()):
        sig = _FRAMEWORK_MAP.get(fw)
        if sig is None:
            continue
        sig_by_id[sig["id"]] = sig
        found[sig["id"]] = SdkHit(
            id=sig["id"],
            vendor=sig["vendor"],
            category=sig["category"],
            version=None,
            evidence=[rel[:160]],
            sources=["framework-dir"],
        )

    fw_versions: Dict[str, str] = {}
    for plist_rel, plist in ((getattr(target, "meta", None) or {})
                             .get("plists") or {}).items():
        try:
            low = str(plist_rel).replace("\\", "/").lower()
        except (TypeError, AttributeError):
            continue
        m = _FRAMEWORK_RX.search(low)
        if m is None or not low.endswith("/info.plist"):
            continue
        if not isinstance(plist, dict):
            continue
        version = (plist.get("CFBundleShortVersionString")
                   or plist.get("CFBundleVersion") or "")
        version = str(version).strip()
        if version and _FW_VERSION_PLIST_RX.match(version):
            fw_versions.setdefault(m.group(1), version)

    hits: List[SdkHit] = []
    for sdk_id in sorted(found):
        hit = found[sdk_id]
        own = {s.lower() for s in sig_by_id[sdk_id]["frameworks"]}
        for fw, version in fw_versions.items():
            if fw in own:
                hit["version"] = version
                break
        hits.append(hit)
    return hits, len(fw_dirs)


def _iter_dex_strings(target) -> Iterable[str]:
    """Every string in the bundle's DEX string tables.

    Iterates each parsed DEX directly - NOT the (capped) shared string
    pool - so big multi-dex apps are handled completely.
    """
    for dex in (getattr(target, "meta", {}).get("dex_files") or []):
        iterator = getattr(dex, "iter_strings", None)
        if iterator is None:
            continue
        for _off, value in iterator():
            if value:
                yield value


def emit_trie(node):
    """Emit a nested-group trie fragment (branches only at character forks).

    ``node`` maps one char to its subtrie; the ``""`` key marks that a
    signature prefix terminates here, so the pattern must be able to stop.
    """
    term = "" in node
    parts = [c + emit_trie(node[c]) for c in sorted(node) if c != ""]
    if term and len(parts) > 1:
        return "(?:" + "|".join(parts) + "|)"
    if term and len(parts) == 1:
        return "(?:" + parts[0] + ")?"
    if term:
        return ""
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return "(?:" + "|".join(parts) + ")"


def _compile_matcher() -> Tuple[re.Pattern, List[Tuple[str, dict, str]]]:
    """Character-trie over the prefixes; positive matches map to the SDK.

    A flat ``|``-alternation makes python's ``re`` try every branch at
    every position, so scan cost scales with branch count; a *nested*
    trie keeps branch points at actual character forks (~1 op/position).
    The tree has no capture groups: on a hit, ``m.group(0)`` is decoded to
    the owning signature through the longest standing prefix table.
    """
    members: List[Tuple[str, dict, str]] = []  # kept for API stability
    prefix_to_sig: Dict[str, dict] = {}
    root: Dict[str, dict] = {}
    for sig in SDK_SIGNATURES:
        for prefix in sig["prefixes"]:
            members.append((re.escape(prefix), sig, prefix))
            prefix_to_sig[prefix] = sig
            node = root
            for ch in prefix:
                node = node.setdefault(ch, {})
            node[""] = {}
    pattern = emit_trie(root)
    rx = re.compile(pattern) if pattern else re.compile(r"(?!)")
    return rx, prefix_to_sig


_MATCHER = _compile_matcher()

_MATCHER = _compile_matcher()


def _compile_version_matcher():
    """Alternation regex over every sig's ``version_rxs``.

    Each alternative is wrapped in its own capture group so its index can
    be precomputed; the SDK *value* is the innermost inner capture of that
    alternative (``version_rxs`` entries must contain one capturing group
    for the version).
    """
    entries: List[Tuple[int, int, str]] = []  # (outer_group, inner_groups, id)
    parts: List[str] = []
    next_group = 1
    for sig in SDK_SIGNATURES:
        for rx in sig["version_rxs"]:
            inner = re.compile(rx).groups
            entries.append((next_group, inner, sig["id"]))
            parts.append("(" + rx + ")")
            next_group += 1 + inner
    rx = re.compile("|".join(parts)) if parts else re.compile(r"(?!)")
    return rx, entries


_VERSION_MATCHER = _compile_version_matcher()


def _version_from_match(m, entries) -> Optional[Tuple[str, str]]:
    out_group, inner, sdk_id = entries[m.lastindex - 1]
    value = m.group(out_group + inner) if inner else m.group(out_group)
    return (sdk_id, value) if value else None


#: version literal candidates longer than this are skipped (versions are short)
_VERSION_LOOK_MAX = 200


def detect_sdks(target) -> List[SdkHit]:
    """Match every curated signature against DEX descriptors + pool."""
    rx, prefix_to_sig = _MATCHER
    version_rx, version_entries = _VERSION_MATCHER
    # longest prefix first: the trie may stop at a stem shared with a longer
    # signature (e.g. 'Lokhttp/' vs 'Lokhttp3/'), the longer one owns the hit
    prefixes_longest = sorted(prefix_to_sig, key=len, reverse=True)

    found: Dict[str, SdkHit] = {}
    versions: Dict[str, List[str]] = {}

    seen_strings = 0

    def _record(m, source: str, full: str) -> None:
        text = m.group(0)
        for prefix in prefixes_longest:
            if text.startswith(prefix):
                sig = prefix_to_sig[prefix]
                break
        else:  # pragma: no cover - trie guarantees a matching prefix
            return
        if sig["id"] in found:
            return
        found[sig["id"]] = SdkHit(
            id=sig["id"],
            vendor=sig["vendor"],
            category=sig["category"],
            version=None,
            evidence=[full[:120]],
            sources=[source],
        )

    # dex string tables: prefixes anchor descriptors at the start -> rx.match
    for value in _iter_dex_strings(target):
        seen_strings += 1
        # version literals are short; skipping the tail of huge strings keeps
        # the per-string cost flat on multi-dex apps
        if len(value) <= _VERSION_LOOK_MAX:
            vm = version_rx.search(value)
            if vm is not None:
                hit_v = _version_from_match(vm, version_entries)
                if hit_v and hit_v[0] not in versions:
                    versions[hit_v[0]] = [hit_v[1]]
        if value[0] == "L" and value[-1] == ";":
            m = rx.match(value)
            if m is not None:
                _record(m, "dex-descriptors", value)

    # pool strings (NDK libstrings, arsc, plain-text file content): search
    for _rel, value in (getattr(target, "string_pool", None) or []):
        if not value:
            continue
        m = rx.search(value)
        if m is not None:
            _record(m, "string-pool", value)
        if len(value) <= _VERSION_LOOK_MAX:
            vm = version_rx.search(value)
            if vm is not None:
                hit_v = _version_from_match(vm, version_entries)
                if hit_v and hit_v[0] not in versions:
                    versions[hit_v[0]] = [hit_v[1]]

    hits: List[SdkHit] = []
    for sdk_id in sorted(found):
        hit = found[sdk_id]
        ver = versions.get(sdk_id)
        if ver:
            hit["version"] = ver[0]
        hits.append(hit)

    # iOS layer: framework-bundle evidence for IPA targets (no-op on APKs)
    ios_hits, frameworks_seen = _ios_target_hits(target)
    for hit in ios_hits:
        if hit["id"] not in found:
            hits.append(hit)

    import os as _os
    if _os.environ.get("MASAN_SDK_DEBUG"):
        print("SD.DEBUG found=", dict(found), "versions=", versions, file=sys.stderr)

    target.meta["sdks"] = hits
    target.meta["sdks_stats"] = {
        "dex_strings_scanned": seen_strings,
        "signatures": len(SDK_SIGNATURES),
        "detected": len(hits),
        "ios_frameworks_scanned": frameworks_seen,
    }
    return hits


def vulnerable_version_check(hit: dict) -> Optional[str]:
    """Return a reason string when an SDK hit sits in a vulnerable band.

    Default table ships *conservative, vendor-documented* facts; teams can
    extend it in deployment via :func:`add_vulnerable_rule` (or by editing
    the table) - masanalyzer never invents a CVE for an SDK on its own.
    """
    version = hit.get("version")
    if not version:
        return None
    parsed = _version_tuple(version)
    if not parsed:
        return None
    rule = VULNERABLE_SDKS.get(hit["id"])
    if not rule:
        return None
    try:
        if parsed < _version_tuple(rule["below"]):
            return rule["reason"]
    except (TypeError, ValueError):
        return None
    return None


def _version_tuple(version: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", str(version))[:3])


#: conservative default: vendor-documented behavior changes only
VULNERABLE_SDKS: Dict[str, dict] = {
    # OkHttp 3.13 release notes: per-supported API levels moved *out* of the
    # default TLS policy - pre-3.13 releases still negotiate TLS 1.0/1.1.
    "okhttp": {
        "below": (3, 13, 0),
        "reason": "okhttp %s negotiates TLS 1.0/1.1 by default (pre-3.13 "
                  "behavior); weak-transport posture for new integrations",
    },
}

#: families that are end-of-life and should not ship in new builds
EOL_SDKS: Dict[str, str] = {
    "apache-http": "Apache's HttpClient port was removed from the Android "
                   "platform in API 23; carrying it signals legacy code "
                   "and an unmaintained network stack",
    "hockeyapp": "HockeyApp was retired by Microsoft in 2019 - pools "
                 "must move to App Center / alternatives",
    "mopub": "MoPub SDK was sunset by AppLovin in 2022; versions are "
             "unpatched from that point on",
    "answers": "Fabric/Answers was retired with Fabric (2019); "
               "unmaintained analytics",
}


def add_vulnerable_rule(sdk_id: str, below: str, reason: str) -> None:
    """Deployment hook: extend the vulnerable-version table at runtime."""
    VULNERABLE_SDKS[sdk_id] = {"below": _version_tuple(below), "reason": reason}

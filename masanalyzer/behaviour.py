"""Behaviour analysis: quark-style API-behaviour rules over DEX receipts.

Quark-style in that behaviours are small, auditable rule IDs bound to
*exact Android API matchers* (``class#method`` pairs) instead of a
monolithic "risk score".  Every hit is attributed to the declaring
method (``method`` + bytecode ``offset``) — evidence pointing into the
binary, stronger than file-level claims and stronger than quark's own
output, which stops at matched functions without source attribution.

Honesty notes:

* receipts are **evidence pointers**, not a dataflow guarantee (the
  linear decode does not track control-flow merges — the same caveat as
  the callsite walker);
* presence of an API is reported, never intent: ``Cipher#getInstance``
  means "requests a cipher", not "encrypts badly" (the cipher-mode
  *quality* rules live in the OWASP analyzers with string evidence);
* a behaviour not listed here is not claimed.

Results land in ``target.meta["behaviour"]`` and render in the report
formats and the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

#: maximum behaviour rows kept in ``meta["behaviour"]["rows"]``
MAX_ROWS = 200
#: example declaring methods kept per behaviour
MAX_METHODS = 20


@dataclass(frozen=True)
class BehaviourRule:
    """One API behaviour with its exact ``Lcls;#method`` matchers."""

    rule_id: str
    title: str
    description: str
    #: (class descriptor with semicolons, method name or "*")
    matchers: Tuple[Tuple[str, str], ...]
    confidence: str = "high"


BEHAVIOURS: Tuple[BehaviourRule, ...] = (
    BehaviourRule(
        "BEH-001",
        "Dynamic code execution",
        "The app launches native processes (Runtime.exec / "
        "ProcessBuilder.start). Worth review: what is executed, with what "
        "input.",
        (
            ("Ljava/lang/Runtime;", "exec"),
            ("Ljava/lang/ProcessBuilder;", "start"),
        ),
    ),
    BehaviourRule(
        "BEH-002",
        "Reflective code loading",
        "The app resolves classes/methods by name at runtime "
        "(Class.forName, Method.invoke) or loads DEX files dynamically "
        "(DexClassLoader). Reflection hides code from static review.",
        (
            ("Ljava/lang/Class;", "forName"),
            ("Ljava/lang/reflect/Method;", "invoke"),
            ("Ldalvik/system/DexClassLoader;", "*"),
            ("Ldalvik/system/PathClassLoader;", "*"),
            ("Ldalvik/system/InMemoryDexClassLoader;", "*"),
        ),
    ),
    BehaviourRule(
        "BEH-003",
        "Cipher requested",
        "The app requests a JCA cipher (Cipher.getInstance). The "
        "transformation string it passes decides the actual strength - "
        "see the crypto findings for the literal evidence.",
        (("Ljavax/crypto/Cipher;", "getInstance"),),
    ),
    BehaviourRule(
        "BEH-004",
        "Hash function requested",
        "The app requests a message digest (MessageDigest.getInstance). "
        "MD5/SHA-1 requests are flagged separately as crypto findings.",
        (("Ljava/security/MessageDigest;", "getInstance"),),
    ),
    BehaviourRule(
        "BEH-005",
        "WebView content loading",
        "The app loads web content into a WebView. Loaded URLs and the "
        "cleartext policy determine the exposure.",
        (
            ("Landroid/webkit/WebView;", "loadUrl"),
            ("Landroid/webkit/WebView;", "loadData"),
            ("Landroid/webkit/WebView;", "loadDataWithBaseURL"),
            ("Landroid/webkit/WebView;", "postUrl"),
        ),
    ),
    BehaviourRule(
        "BEH-006",
        "JavaScript bridge exposed",
        "The app exposes a Java object to WebView JavaScript "
        "(addJavascriptInterface). On API < 17 this enables RCE via "
        "reflection; review the exposed object's surface.",
        (("Landroid/webkit/WebView;", "addJavascriptInterface"),),
    ),
    BehaviourRule(
        "BEH-007",
        "SMS sent",
        "The app sends SMS messages via SmsManager (premium-content "
        "indicator in unsolicited contexts).",
        (
            ("Landroid/telephony/SmsManager;", "sendTextMessage"),
            ("Landroid/telephony/SmsManager;", "sendMultipartTextMessage"),
            ("Landroid/telephony/SmsManager;", "sendDataMessage"),
        ),
    ),
    BehaviourRule(
        "BEH-008",
        "Location updates requested",
        "The app subscribes to device location (LocationManager). "
        "Frequency and coarseness decide the privacy impact.",
        (
            ("Landroid/location/LocationManager;", "requestLocationUpdates"),
            ("Landroid/location/LocationManager;", "getLastKnownLocation"),
        ),
    ),
    BehaviourRule(
        "BEH-009",
        "Runtime broadcast receiver",
        "The app registers broadcast receivers at runtime - components "
        "not visible in the manifest's receiver list.",
        (("Landroid/content/Context;", "registerReceiver"),),
    ),
    BehaviourRule(
        "BEH-010",
        "Outbound connections opened",
        "The app opens network connections (URL.openConnection / "
        "OkHttp newCall). The endpoint inventory lists the observed "
        "destinations.",
        (
            ("Ljava/net/URL;", "openConnection"),
            ("Lokhttp3/OkHttpClient;", "newCall"),
            ("Lorg/apache/http/impl/client/DefaultHttpClient;", "*"),
        ),
    ),
    BehaviourRule(
        "BEH-011",
        "Device identifiers read",
        "The app reads hardware/subscription identifiers (IMEI, "
        "subscriber id, SIM serial). Persistent identifiers enable "
        "cross-app tracking; combined with the tracker inventory this "
        "shows what they can feed.",
        (
            ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
            ("Landroid/telephony/TelephonyManager;", "getImei"),
            ("Landroid/telephony/TelephonyManager;", "getMeid"),
            ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
            ("Landroid/telephony/TelephonyManager;", "getSimSerialNumber"),
        ),
    ),
    BehaviourRule(
        "BEH-012",
        "Clipboard access",
        "The app reads or writes the system clipboard. Users copy "
        "passwords/OTPs into it; background reads are a classic leak.",
        (
            ("Landroid/content/ClipboardManager;", "getPrimaryClip"),
            ("Landroid/content/ClipboardManager;", "setPrimaryClip"),
            ("Landroid/content/ClipboardManager;",
             "getPrimaryClipDescription"),
        ),
    ),
    BehaviourRule(
        "BEH-013",
        "Global/secure settings read",
        "The app reads global or secure settings (Settings.Secure/"
        "Global.getString) - including ANDROID_ID, the app-scoped "
        "advertising identifier.",
        (
            ("Landroid/provider/Settings$Secure;", "getString"),
            ("Landroid/provider/Settings$Global;", "getString"),
        ),
    ),
    BehaviourRule(
        "BEH-014",
        "Key-value data persisted",
        "The app writes string/typed data to SharedPreferences. What is "
        "stored there (tokens, PII) and its file permissions decide the "
        "impact (see the storage findings).",
        (
            ("Landroid/content/SharedPreferences$Editor;", "putString"),
            ("Landroid/content/SharedPreferences$Editor;", "putStringSet"),
            ("Landroid/content/SharedPreferences$Editor;", "putInt"),
            ("Landroid/content/SharedPreferences$Editor;", "putBoolean"),
        ),
    ),
    BehaviourRule(
        "BEH-015",
        "Key material requested",
        "The app requests key material (KeyGenerator/KeyStore). Paired "
        "with the cipher behaviour this maps the app's crypto surface.",
        (
            ("Ljavax/crypto/KeyGenerator;", "getInstance"),
            ("Ljava/security/KeyStore;", "getKey"),
        ),
    ),
)


def _matcher_index() -> Dict[Tuple[str, str], Tuple[str, ...]]:
    """(class, name) -> rule ids using this behaviour (name '*' = any)."""
    index: Dict[Tuple[str, str], Tuple[str, ...]] = {}
    for rule in BEHAVIOURS:
        for cls, name in rule.matchers:
            key = (cls, name)
            ids = index.get(key, ())
            index[key] = ids + (rule.rule_id,)  # type: ignore[assignment]
    return index


_MATCHER_INDEX = _matcher_index()


def match_callee(callee: str) -> Tuple[str, ...]:
    """Behaviour ids whose matchers hit one raw callee reference.

    ``callee`` is the raw DEX method ref form ``Lpkg/Class;#method``;
    unparseable shapes match nothing (no fuzzy guessing).
    """
    cls, sep, name = callee.partition("#")
    if not sep:
        return ()
    ids = _MATCHER_INDEX.get((cls, name), ())
    star = _MATCHER_INDEX.get((cls, "*"), ())
    return ids + star


def _matcher_fn() -> Callable[[str], bool]:
    """A ``collect_api_calls`` filter matching any behaviour rule."""
    return lambda callee: bool(match_callee(callee))


def collect_behaviour(
    dex_files: List[Any],
) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Run the behaviour matchers over every DEX and aggregate.

    Returns ``(behaviours, rows)``:

    ``behaviours`` maps rule id -> ``{id, title, description, confidence,
    receipts, methods, callees}`` where ``methods`` are the declaring
    methods (capped) and ``callees`` the unique raw references hit.

    ``rows`` are per-hit receipts (capped) with their DEX file, ready to
    be embedded in ``meta["behaviour"]``.
    """
    per_rule: Dict[str, Dict[str, Any]] = {}
    rows: List[Dict[str, Any]] = []
    stats: Dict[str, Dict[str, int]] = {}
    matcher = _matcher_fn()

    for dex in dex_files:
        relpath = str(getattr(dex, "relpath", "") or "classes.dex")
        try:
            dex.collect_api_calls(match=matcher, limit=MAX_ROWS * 4)
        except Exception:                       # noqa: BLE001 - best effort
            continue
        stats[relpath] = dict(getattr(dex, "api_stats", {}) or {})
        for rec in getattr(dex, "api_receipts", ()):
            callee = str(rec.get("callee", "") or "")
            for rule_id in match_callee(callee):
                entry = per_rule.get(rule_id)
                if entry is None:
                    rule = next(r for r in BEHAVIOURS if r.rule_id == rule_id)
                    entry = {
                        "id": rule.rule_id,
                        "title": rule.title,
                        "description": rule.description,
                        "confidence": rule.confidence,
                        "receipts": 0,
                        "methods": [],
                        "callees": [],
                        "_seen_methods": set(),
                        "_seen_callees": set(),
                    }
                    per_rule[rule_id] = entry
                entry["receipts"] += 1
                method = str(rec.get("method", "") or "")
                if method and method not in entry["_seen_methods"] \
                        and len(entry["methods"]) < MAX_METHODS:
                    entry["_seen_methods"].add(method)
                    entry["methods"].append(method)
                if callee and callee not in entry["_seen_callees"] \
                        and len(entry["callees"]) < 10:
                    entry["_seen_callees"].add(callee)
                    entry["callees"].append(callee)
                if len(rows) < MAX_ROWS:
                    rows.append(
                        {
                            "behaviour": rule_id,
                            "dex": relpath,
                            "method": method,
                            "callee": callee,
                            "offset": rec.get("offset", 0),
                        }
                    )

    for entry in per_rule.values():
        entry.pop("_seen_methods", None)
        entry.pop("_seen_callees", None)
    return per_rule, rows


def behaviour_meta(dex_files: List[Any]) -> Dict[str, Any]:
    """JSON-ready ``meta["behaviour"]`` dict (empty when no DEX)."""
    per_rule, rows = collect_behaviour(dex_files)
    if not per_rule and not rows:
        return {}
    stats = {}
    for dex in dex_files:
        relpath = str(getattr(dex, "relpath", "") or "classes.dex")
        api_stats = getattr(dex, "api_stats", None) or {}
        if api_stats:
            stats[relpath] = dict(api_stats)
    return {
        "behaviours": [
            per_rule[rule.rule_id]
            for rule in BEHAVIOURS
            if rule.rule_id in per_rule
        ],
        "rows": rows,
        "total_receipts": sum(
            e["receipts"] for e in per_rule.values()),
        "stats": stats,
    }

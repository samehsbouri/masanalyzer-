"""Endpoint / URL inventory harvested from the bundle's string material.

Feature goal: answer *"where does this app talk?"* statically.

* URLs, bare domains and IPv4 literals are collected from

  - the container ``string_pool`` (DEX string tables, ``resources.arsc``,
    native ``.so`` strings, binary plists, ``strings`` output of binaries)
  - plain text-ish files (xml resources, code, properties, config)

* every host is classified:

  - ``local``      loopback / localhost / ``.local``-style names
  - ``private``    RFC1918 or link-local address literals
  - ``tracker``    suffix match against a curated analytics/ad network list
  - ``first_party`` the host shares tokens with the app's package id
  - ``public``     everything else (cross-checks belong to the review)

The result is stored as ``target.meta["endpoints"]`` - a JSON-ready dict with
sorted rows and counts - before the analyzer modules run, so rules and the
report renderers can both use it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------
RX_URL = re.compile(
    r"\bhttps?://[A-Za-z0-9_\-\.]+(?::\d{1,5})?(?:/[^\s\"'<>\\]{1,160})?",
    re.IGNORECASE,
)

#: bare domain names (min 2 labels) with a known-ish TLD; URLs are captured
#: separately, so this pattern only needs to walk pool strings
_RX_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
RX_DOMAIN = re.compile(
    rf"(?<![\w@.\-/]){_RX_LABEL}(?:\.{_RX_LABEL})+\.(?:"
    "com|net|org|io|dev|app|co|ru|cn|us|uk|de|fr|jp|kr|in|au|ca|it|es|nl|se|no|"
    "br|mx|gov|edu|mil|info|biz|me|tv|ai|ch|at|be|cz|dk|fi|gr|hu|ie|il|pl|pt|"
    "ro|tr|za|id|my|ph|sg|th|vn|nz|ar|cl|mx"
    r")(?![\w.\-/])",
    re.IGNORECASE,
)

RX_IPV4 = re.compile(
    r"(?<![\w.\-/])(?:\d{1,3}\.){3}\d{1,3}(?![\w.\-/])"
)

#: hostnames that never make network sense as API endpoints
TRIVIAL_HOSTS = {
    "schemas.android.com", "www.w3.org", "xml.apache.org",
    "ns.adobe.com", "apache.org", "example.com", "example.org",
    "example.net", "www.w3.org.", "android.com", "aapt.attr",
    "json.org", "jwt.io", "tukaani.org", "zlib.net", "ispras.ru",
    "unicode.org", "w3.org", "purl.org", "ibm.com", "bouncycastle.org",
    "openjdk.java.net", "source.android.com", "developer.android.com",
    "tools.ietf.org", "ietf.org", "rfc-editor.org", "reactjs.org",
    "orientation.reactnative.dev", "reactnative.dev", "facebook.com",
    "github.com", "gitlab.com", "bitbucket.org", "wikipedia.org",
    "facebook.github.io", "webkit.org", "sqlite.org", "gcc.gnu.org",
    "gnu.org", "openssl.org", "lbs.google.com",
}

#: curated analytics/ad network backends (suffix match on registrable base)
TRACKER_SUFFIXES: Tuple[str, ...] = (
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "googlesyndication.com", "googleadservices.com", "admob.com",
    "appsflyer.com", "applovin.com", "adcolony.com", "inmobi.com",
    "unityads.unity3d.com", "chartboost.com", "vungle.com",
    "ironsrc.com", "mopub.com", "tapjoy.com", "adcolony.s3",
    "branch.io", "mixpanel.com", "segment.io", "segment.com",
    "sentry.io", "crashlytics.com", "answers.sh", "amplitude.com",
    "onesignal.com", "airship.com", "urbanairship.com",
    "umeng.com", "umengcloud.com", "talkingdata.com",
    "facebook.net", "instal.com", "kochava.com", "adjust.com",
    "countly.com", "matomo.cloud", "flyrames", "yahoo.co.jp",
)

#: self-authored notable; tokens often generic in package ids
_GENERIC_TOKENS = {
    "com", "org", "net", "app", "dev", "www", "android", "ios", "mobile",
    "company", "mycompany", "application", "theapp", "debug", "release",
    "main", "prod", "staging", "test", "corp", "inc", "llc", "io", "mx",
}

MAX_ENDPOINTS = 2000        # keep flattened inventory bounded
MAX_SOURCES = 6             # evidence paths kept per endpoint


@dataclass
class Endpoint:
    """One observed network destination."""

    host: str
    kind: str            # "url" | "domain" | "ip"
    scheme: str          # "http" | "https" | "" (bare host)
    classification: str  # first_party | tracker | private | local | public
    cleartext: bool
    sources: List[str] = field(default_factory=list)
    port: Optional[int] = None


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _registrable(host: str) -> str:
    """Last two labels of a dotted hostname (registrable-domain guess)."""
    labels = [l for l in host.lower().split(".") if l]
    if len(labels) < 2:
        return host.lower()
    return ".".join(labels[-2:])


def _classify_host(
    host: str,
    scheme: str,
    package_tokens: Set[str],
) -> str:
    low = host.lower().rstrip(".")
    host_ip = None
    try:
        host_ip = ipaddress.ip_address(low.strip("[]"))
    except ValueError:
        pass
    if host_ip is not None:
        if host_ip.is_loopback:
            return "local"
        if host_ip.is_private or host_ip.is_link_local or not host_ip.is_global:
            return "private"
        return "public"
    if low == "localhost" or low.endswith(".localhost"):
        return "local"
    if low.endswith((".local", ".lan", ".internal", ".corp", ".home", ".intranet")):
        return "local"
    if any(low == t or low.endswith("." + t) for t in TRACKER_SUFFIXES):
        return "tracker"
    reg = _registrable(low)
    base = reg.split(".")[0]
    if base and base not in _GENERIC_TOKENS and base in package_tokens:
        return "first_party"
    return "public"


def _parse_url(url: str) -> Tuple[str, str, Optional[int]]:
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        return host, (parts.scheme or "").lower(), parts.port
    except ValueError:
        return "", "", None


def host_is_trivial(host: str) -> bool:
    """Vendor/schema/documentation hosts that should not pollute the report."""
    low = (host or "").lower().rstrip(".")
    return (
        low in {t.rstrip(".") for t in TRIVIAL_HOSTS}
        or "_." in low
    )


def _is_private(host: str) -> bool:
    """True for dotted quads that will be classified as private/local."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not ip.is_global or ip.is_loopback


# --------------------------------------------------------------------------
# harvesting
# --------------------------------------------------------------------------
def harvest_strings(target) -> List[Tuple[str, str, str]]:
    """`(source, raw, kind)` candidates from every string source."""
    found: List[Tuple[str, str, str]] = []
    seen_hosts: Set[str] = set()

    def add(source: str, raw: str, kind: str, host: str) -> None:
        if host and host not in seen_hosts:
            seen_hosts.add(host)
        found.append((source, raw, kind))

    for rel, value in getattr(target, "string_pool", []) or []:
        for m in RX_URL.finditer(value or ""):
            url = m.group(0)
            host, _scheme, _port = _parse_url(url)
            if host:
                add(rel, url, "url", host)
        for m in RX_DOMAIN.finditer(value or ""):
            add(rel, m.group(0).lower(), "domain", m.group(0).lower())
        for m in RX_IPV4.finditer(value or ""):
            cand = m.group(0)
            try:
                ipaddress.IPv4Address(cand)          # only dotted quad
            except ipaddress.AddressValueError:
                continue
            add(rel, cand, "ip", cand)

    # text files: URLs live in code / xml / config more than pool strings
    for sf in getattr(target, "files", []) or []:
        if sf.kind not in ("code", "smali", "resource", "plist", "manifest", "text"):
            continue
        text = sf.read_text()
        if not text:
            continue
        for m in RX_URL.finditer(text):
            url = m.group(0)
            host, _scheme, _port = _parse_url(url)
            if host:
                add(sf.relpath, url, "url", host)
        if sf.kind in ("resource", "manifest"):
            for m in RX_DOMAIN.finditer(text):
                add(sf.relpath, m.group(0).lower(), "domain", m.group(0).lower())
    return found


def _called_from_map(target) -> Dict[Tuple[str, str], List[str]]:
    """Map ``(host, scheme)`` -> calling methods, from DEX callsite receipts."""
    calls: Dict[Tuple[str, str], List[str]] = {}
    for rec in (target.meta.get("callsites") or []):
        host, scheme, _port = _parse_url(rec.get("url") or "")
        if not host:
            continue
        bucket = calls.setdefault((host, scheme), [])
        method = rec.get("method") or "?"
        if method not in bucket:
            bucket.append(method)
    return calls


def build_inventory(target) -> Dict[str, Any]:
    """Collect + classify + store the inventory under ``meta["endpoints"]``."""
    package = (getattr(target, "package", "") or "").lower()
    tokens = {t for t in package.split(".") if t}

    endpoints: Dict[str, Endpoint] = {}
    harvested = list(harvest_strings(target))
    # callsite receipts are first-class URL sources: the shared string pool
    # is capped, so on big multi-dex targets a receipt URL may never have
    # made it into the pool - it must still show up as an endpoint row and
    # carry its `called_from` methods.
    for rec in (target.meta.get("callsites") or []):
        raw = rec.get("url") or ""
        if raw:
            harvested.append(("callsites", raw, "url"))

    for source, raw, kind in harvested:
        if kind == "url":
            host, scheme, port = _parse_url(raw)
            if not host:
                continue
        else:
            host, scheme, port = raw.lower(), "", None
        if host_is_trivial(host):
            continue
        key = (host, scheme if kind == "url" else "")
        ep = endpoints.get(key)
        cls = _classify_host(host, scheme, tokens)
        if ep is None:
            ep = endpoints[key] = Endpoint(
                host=host,
                kind=kind,
                scheme=scheme,
                port=port,
                classification=cls,
                cleartext=scheme == "http",
                sources=[],
            )
            ep.sources.append(source)
        else:
            ep.sources.append(source)
            if cls == "tracker":
                ep.classification = "tracker"
            elif cls in ("private", "local") and ep.classification not in ("tracker",):
                ep.classification = cls
            elif cls == "first_party" and ep.classification == "public":
                ep.classification = "first_party"
            if ep.cleartext is False and scheme == "http":
                ep.cleartext = True
                ep.scheme = "http"

    rows: List[Dict[str, Any]] = []
    order = {"tracker": 0, "private": 1, "local": 2, "first_party": 3, "public": 4}
    called_from = _called_from_map(target)
    for ep in sorted(
        endpoints.values(),
        key=lambda e: (order.get(e.classification, 5), e.host, e.kind),
    ):
        seen_src, src_list = set(), []
        for src in ep.sources:
            if src not in seen_src:
                seen_src.add(src)
                src_list.append(src)
            if len(src_list) >= MAX_SOURCES:
                break
        row = {
            "host": ep.host,
            "kind": ep.kind,
            "scheme": ep.scheme,
            "port": ep.port,
            "classification": ep.classification,
            "cleartext": ep.cleartext,
            "sources": src_list,
            "occurrences": min(len(ep.sources), 9999),
        }
        callers = called_from.get((ep.host, ep.scheme)) if ep.kind == "url" else None
        if callers:
            row["called_from"] = callers[:4]
        rows.append(row)

    counts: Dict[str, int] = {
        "tracker": 0, "private": 0, "local": 0, "first_party": 0,
        "public": 0, "cleartext": 0,
    }
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
        if row["cleartext"]:
            counts["cleartext"] += 1

    inventory = {
        "total": len(rows),
        "counts": counts,
        "rows": rows[:MAX_ENDPOINTS],
    }
    target.meta["endpoints"] = inventory
    return inventory

"""M5 - Insecure Communication.

Manifest cleartext opt-ins, permissive network security configs, trust of
user-added CAs, http:// endpoints in code, compiled strings and resources,
accept-all TLS validators and the iOS App Transport Security opt-out.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Optional

from ..model import Confidence, Finding, Severity, Target
from .common import (
    code_lines,
    ev_pool,
    make_rule,
    matches_in_text,
    secret_poc,
    text_scan,
)

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
CRITICAL = Severity.CRITICAL
HIGH = Severity.HIGH
MEDIUM = Severity.MEDIUM
LOW = Severity.LOW

R_CLT_MANIFEST = make_rule(
    "MAS-NET-001",
    "M5",
    "Cleartext traffic enabled platform-wide",
    'android:usesCleartextTraffic="true" permits HTTP-byte traffic for every '
    "destination, allowing network-level observers to read or modify app data.",
    HIGH,
    "Remove the flag and use TLS for all transports; declare per-domain "
    "exemptions only when strictly unavoidable.",
    cwe="CWE-319",
    confidence=Confidence.HIGH,
    cvss=7.4,
    platform="android",
)

R_NSC_CLEARTEXT = make_rule(
    "MAS-NET-002",
    "M5",
    "Network security config permits cleartext",
    "The android:networkSecurityConfig explicitly allows cleartext for the "
    "base config or for a domain; those endpoints are exposed to sniffing.",
    HIGH,
    "Set cleartextTrafficPermitted=\"false\" and provide TLS endpoints only.",
    cwe="CWE-319",
    confidence=Confidence.HIGH,
    cvss=7.2,
    platform="android",
)

R_USER_CERTS = make_rule(
    "MAS-NET-003",
    "M5",
    "Trust anchors include user-added certificates",
    '<certificates src="user"/> makes the app trust CA certificates the device '
    "owner (or an attacker with device access) installed, defeating "
    "server authentication.",
    HIGH,
    'Trust only system anchors (remove src="user") and add pinning for '
    "sensitive endpoints.",
    cwe="CWE-295",
    confidence=Confidence.HIGH,
    cvss=7.5,
    platform="android",
)

R_NO_PINS = make_rule(
    "MAS-NET-004",
    "M5",
    "No certificate pinning configured",
    "The network security config has no pin-set; TLS validation relies only on "
    "the CA tree.",
    LOW,
    "Add pin-set entries for the endpoints handling sensitive data (keep a "
    "backup pin for rotation).",
    cwe="CWE-295",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_HTTP_URL = make_rule(
    "MAS-NET-005",
    "M5",
    "Unencrypted HTTP endpoint referenced",
    "An http:// URL is used in code, resources or the compiled string pool - "
    "those calls transmit credentials and session data unencrypted.",
    MEDIUM,
    "Switch the endpoint to https:// (and HSTS server-side).",
    cwe="CWE-319",
    confidence=Confidence.MEDIUM,
    cvss=6.0,
)

R_TRUST_ALL = make_rule(
    "MAS-NET-006",
    "M5",
    "TLS certificate validation disabled (trust-all manager)",
    "A custom X509TrustManager/HostnameVerifier accepts any certificate (or "
    "returns true for every name), turning MITM into trivial server "
    "impersonation.",
    CRITICAL,
    "Remove the custom trust manager / verifier and rely on system validation "
    "plus pinning.",
    cwe="CWE-295",
    confidence=Confidence.HIGH,
    cvss=9.1,
)

R_ATS_ARBITRARY = make_rule(
    "MAS-NET-007",
    "M5",
    "App Transport Security disabled (NSAllowsArbitraryLoads)",
    "The iOS ATS opt-out allows any cleartext connection from the app "
    "process, silently degrading all HTTPS to optional.",
    HIGH,
    "Remove NSAllowsArbitraryLoads; add NSExceptionDomains entries with "
    "NSExceptionAllowsInsecureHTTPLoads only where legacy servers require it.",
    cwe="CWE-319",
    confidence=Confidence.HIGH,
    cvss=7.2,
    platform="ios",
)

R_TRACKER_HOST = make_rule(
    "MAS-NET-008",
    "M5",
    "Third-party tracking / analytics endpoint embedded",
    "The bundle references a known advertising or analytics backend "
    "(matched against a curated list). Those SDKs expand the app's data "
    "disclosure surface and attribute traffic to ad networks - reviewers "
    "should confirm the data categories sent before any GDPR/CCPA story "
    "is believed.",
    LOW,
    "Document the SDK's collection purpose in the privacy policy, restrict "
    "the data sent to first-party needs, or remove the SDK if unused.",
    cwe="CWE-359",
    confidence=Confidence.HIGH,
)

R_PRIVATE_HOST = make_rule(
    "MAS-NET-009",
    "M5",
    "Private or internal network address shipped in the bundle",
    "An RFC1918 / loopback / internal name is referenced by shipped code "
    "or resources. Internal hostnames, staging addresses and "
    "10.x/192.168.x endpoints leaked into release artifacts map an "
    "attacker's pivot path into the corporate network.",
    LOW,
    "Strip internal endpoints from release builds (build-type conditionals) "
    "and keep debug-only traffic behind build flags.",
    cwe="CWE-200",
    confidence=Confidence.MEDIUM,
)

R_WEBVIEW_SSL_IGNORE = make_rule(
    "MAS-NET-010",
    "M5",
    "WebView ignores TLS certificate errors",
    "The WebViewClient proceeds after onReceivedSslError (calls "
    "handler.proceed()), so the WebView silently accepts invalid, expired "
    "or attacker-presented certificates - a MITM can script everything the "
    "WebView loads.",
    HIGH,
    "Always call handler.cancel() (the default) and remove custom "
    "onReceivedSslError overrides that proceed.",
    cwe="CWE-295",
    confidence=Confidence.HIGH,
    cvss=7.4,
    platform="android",
)

R_MIXED_CONTENT = make_rule(
    "MAS-NET-011",
    "M5",
    "WebView mixed content unrestricted",
    "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) lets an HTTPS page "
    "loaded in the WebView pull scripts/resources from plain HTTP "
    "origins, re-opening a MITM content-injection channel inside the app.",
    MEDIUM,
    "Use MIXED_CONTENT_NEVER_ALLOW (the default) or "
    "COMPATIBILITY_MODE with a reviewed allow-list.",
    cwe="CWE-319",
    confidence=Confidence.HIGH,
    cvss=6.5,
    platform="android",
)

_RX_TRUST_ALL = re.compile(
    r"(X509TrustManager|TrustAllCert|allowAllHostnameVerifier|"
    r"SSLSocketFactory.*ALLOWS_HOSTNAME|checkServerTrusted\s*\([^)]*\)\s*\{\s*\})"
)
_RX_HOSTNAME_TRUE = re.compile(
    r"(verify\s*\(\s*[^)]*\)\s*\{\s*(?:return\s+)?true|HostnameVerifier\s*\{[^}]*return\s+true)"
)
_RX_HTTP_URL = re.compile(r"https?://(?!schemas\.android|www\.w3|xml\.apache|ns\.adobe|www\.apple|www\.google|dl\.google|developer\.android|tools\.android|maven\.|repo\.jitpack|plugins\.gradle)[A-Za-z0-9._\-]{4,}")
_RX_SSL_PROCEED = re.compile(
    r"onReceivedSslError[\s\S]{0,300}?\.proceed\s*\(\s*\)"
)
_RX_MIXED_CONTENT = re.compile(
    r"setMixedContentMode\s*\(\s*[^)]{0,48}MIXED_CONTENT_ALWAYS_ALLOW"
)


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []
    platform = target.platform

    # --- manifest ------------------------------------------------------------
    manifest = target.manifest
    if manifest is not None:
        if manifest.uses_cleartext_traffic is True:
            out.append(
                R_CLT_MANIFEST.finding(
                    file=target.meta.get("manifest_path", "AndroidManifest.xml"),
                    symbol="android:usesCleartextTraffic=\"true\"",
                    note="flag parsed from the compiled AXML manifest",
                )
            )

    # --- network security config ----------------------------------------------
    nsc = target.meta.get("network_security_config")
    if nsc is not None:
        if nsc.allows_cleartext():
            where = getattr(nsc, "path", None) or "network_security_config.xml"
            out.append(
                R_NSC_CLEARTEXT.finding(
                    file=where,
                    symbol="<base-config cleartextTrafficPermitted=\"true\">",
                    note="parsed from the network security config XML",
                )
            )
        if nsc.allows_user_certs:
            where = getattr(nsc, "path", None) or "network_security_config.xml"
            out.append(
                R_USER_CERTS.finding(
                    file=where,
                    symbol='<certificates src="user"/>',
                    note="user-added trust anchors parsed from the config",
                )
            )
        if not nsc.has_pins:
            where = getattr(nsc, "path", None) or "network_security_config.xml"
            out.append(
                R_NO_PINS.finding(
                    file=where,
                    note="no <pin-set> in the network security config "
                         "(absence detected over the parsed config)",
                )
            )

    # --- iOS plists (dedupe by basename: IPA scan keys vs full relpaths) ----------
    seen_ats: set = set()
    plists = target.meta.get("plists") or {}
    for rel, data in plists.items():
        ats = data.get("NSAppTransportSecurity") if isinstance(data, dict) else None
        if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
            base = os.path.basename(rel)
            if base not in seen_ats:
                out.append(
                    R_ATS_ARBITRARY.finding(
                        file=rel,
                        symbol="NSAllowsArbitraryLoads = true",
                        note="ATS dictionary parsed from the plist",
                    )
                )
                seen_ats.add(base)

    # --- http endpoints in code/resources ---------------------------------------
    for sf, lineno, text in text_scan(target, kinds=("code", "resource")):
        m = _RX_HTTP_URL.search(text)
        if m and "example" not in m.group(0):
            out.append(
                R_HTTP_URL.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
    for rel, value in _pool(target):
        m = _RX_HTTP_URL.search(value)
        if m and "example" not in m.group(0):
            out.append(R_HTTP_URL.finding(file=rel, symbol=value[:80]))

    # --- endpoint inventory rules (built during packaging) -----------------------
    inventory = target.meta.get("endpoints") or {}
    for row in inventory.get("rows", []):
        if row.get("classification") == "tracker":
            out.append(
                R_TRACKER_HOST.finding(
                    file=row["sources"][0] if row["sources"] else "string-pool",
                    symbol=row["host"][:80],
                    note="tracker endpoint",
                )
            )
        elif row.get("classification") in ("private", "local"):
            out.append(
                R_PRIVATE_HOST.finding(
                    file=row["sources"][0] if row["sources"] else "string-pool",
                    symbol=row["host"][:80],
                    note=f"{'cleartext' if row.get('cleartext') else 'private'} endpoint",
                )
            )

    # --- trust-all validators (one finding per file/rule) ------------------------
    seen_trust: set = set()
    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        if _RX_TRUST_ALL.search(text) or _RX_HOSTNAME_TRUE.search(text):
            if sf.relpath not in seen_trust:
                out.append(
                    R_TRUST_ALL.finding(
                        file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                    )
                )
                seen_trust.add(sf.relpath)

    # --- WebView TLS / mixed-content hardening -----------------------------------
    for sf in target.code_files():
        text = sf.read_text()
        if not text:
            continue
        if _RX_SSL_PROCEED.search(text):
            line_no = text[: _RX_SSL_PROCEED.search(text).start()].count("\n") + 1
            out.append(
                R_WEBVIEW_SSL_IGNORE.finding(
                    file=sf.relpath,
                    line=line_no,
                    snippet=sf.line_at(line_no) or "",
                    note="onReceivedSslError handler calls proceed()",
                )
            )
        m = _RX_MIXED_CONTENT.search(text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            out.append(
                R_MIXED_CONTENT.finding(
                    file=sf.relpath,
                    line=line_no,
                    snippet=sf.line_at(line_no) or m.group(0),
                )
            )
    return out


def _pool(target: Target):
    for rel, value in target.string_pool:
        if len(value) < 8:
            continue
        low = value.lower()
        if any(b in low for b in ("schemas.android.com", "w3.org", "apache.org",
                                  "adobe.com", "apple.com", "google.com/apis"
                                  )):
            continue
        yield rel, value

"""M8 - Security Misconfiguration.

Dangerous build defaults: backup allowed without rules, WebView hardening
turned off, signature-only permissions requested for packaging tricks, and
test-only builds.
"""

from __future__ import annotations

import re
from typing import Iterable, List

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, iter_pool, make_rule

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
LOW = Severity.LOW

R_ALLOW_BACKUP = make_rule(
    "MAS-MIS-001",
    "M8",
    "App data included in backups / cloud restore",
    'android:allowBackup="true" without dataExtractionRules/fullBackupContent '
    "lets a debugging bridge (adb backup/idle restore) or cloud transfer "
    "duplicate app-private data.",
    MEDIUM,
    'Set allowBackup="false" or restrict with dataExtractionRules; exclude '
    "credentials.",
    cwe="CWE-530",
    confidence=Confidence.HIGH,
    cvss=5.5,
    platform="android",
)

R_TEST_ONLY = make_rule(
    "MAS-MIS-002",
    "M8",
    "Build marked test-only shipped outside dev",
    "android:testOnly marks the install as impossible for real distribution "
    "but signals debugging / instrumentation hooks in the shipped build.",
    MEDIUM,
    "Ship normal release artifacts; test-only builds are dev images only.",
    cwe="CWE-489",
    confidence=Confidence.HIGH,
    platform="android",
)

R_SIGNATURE_PERM_ABUSE = make_rule(
    "MAS-MIS-003",
    "M8",
    "System/signature-level permission requested",
    "The app requests permissions reserved for platform/signature holders "
    "(SET_DEBUG_APP, INSTALL_PACKAGES, ...); declared they weaken the trust "
    "model and hint at instrumentation or root abuse paths.",
    MEDIUM,
    "Remove signature-only permission requests unless the whole install is "
    "signed by the platform vendor.",
    cwe="CWE-250",
    confidence=Confidence.HIGH,
    cvss=5.5,
    platform="android",
)

R_INVALID_TARGET_WEBVIEW = make_rule(
    "MAS-MIS-004",
    "M8",
    "WebView JavaScript interface exposed with file access",
    "addJavascriptInterface is combined with javascript enabled and/or "
    "setAllowFileAccess, so a compromised renderer can call app-native "
    "helpers and read app files.",
    HIGH,
    "Restrict the WebView to allow-listed origins, keep "
    "setAllowFileAccess(false) and expose interfaces only to trusted JS.",
    cwe="CWE-749",
    confidence=Confidence.HIGH,
    cvss=7.8,
)

R_WEAK_WEBVIEW_JS = make_rule(
    "MAS-MIS-005",
    "M8",
    "JavaScript enabled in a WebView",
    "setJavaScriptEnabled(true) on a WebView lowers attack surface hardening "
    "and should exist only where dynamic content is required.",
    MEDIUM,
    "Disable JavaScript unless required, then pin/allow-list the origins "
    "loaded.",
    cwe="CWE-749",
    confidence=Confidence.MEDIUM,
)

R_EXTRACT_NATIVELIBS = make_rule(
    "MAS-MIS-006",
    "M8",
    "Native libraries extracted to disk",
    'android:extractNativeLibs="true" places .so files in the app data dir '
    "(writable), enabling on-device library substitution during updates.",
    LOW,
    "Use install-time from extracted (default false with Android 6+ "
    "allocations) and rely on the compressed APK layout.",
    cwe="CWE-250",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_SPECIAL_ACCESS = make_rule(
    "MAS-MIS-007",
    "M8",
    "Special-access privilege declared (store-policy attention)",
    "The manifest holds a special-access grant (install packages, "
    "application overlay, all-files access, write settings, external app "
    "inventory). These bypass the usual dialog flow: store policy "
    "requires an explicit justification, and each is a known abuse vector "
    "(dropper installs, tapjacking overlays, mass file access).",
    MEDIUM,
    "Verify the product need; keep only grants with a user-visible "
    "justification and remove the rest.",
    cwe="CWE-250",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_WEBVIEW_REMOTE_DEBUG = make_rule(
    "MAS-MIS-008",
    "M8",
    "WebView remote debugging enabled",
    "setWebContentsDebuggingEnabled(true) exposes the in-app WebView to "
    "chrome://inspect over USB and through local debugging channels; any "
    "content the WebView renders (including MITM-injected content) can be "
    "scripted by an attacker with device access.",
    MEDIUM,
    "Enable remote debugging only in debug builds (BuildConfig.DEBUG "
    "guard); ship releases with it off.",
    cwe="CWE-489",
    confidence=Confidence.MEDIUM,
    platform="android",
)

_RX_JS_ENABLED = re.compile(r"setJavaScriptEnabled\s*\(\s*true", re.I)
_RX_JS_INTERFACE = re.compile(r"(addJavascriptInterface|webMessageListener|JSInterface)\s*\(\s*[A-Za-z]", re.I)
_RX_FILE_ACCESS = re.compile(r"setAllowFileAccess(?:FromFileURLs)?\s*\(\s*true", re.I)
_RX_REMOTE_DEBUG = re.compile(r"setWebContentsDebuggingEnabled\s*\(\s*true", re.I)
_RX_REMOTE_DEBUG_API = re.compile(r"setWebContentsDebuggingEnabled", re.I)


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []
    manifest = target.manifest
    manifest_path = target.meta.get("manifest_path") or "AndroidManifest.xml"

    if manifest is not None:
        if manifest.allow_backup and not manifest.backup_agent \
                and manifest.data_extraction_rules is None and manifest.full_backup_content is None:
            out.append(
                R_ALLOW_BACKUP.finding(
                    file=manifest_path,
                    note="no backup rules declared",
                )
            )
        if manifest.test_only:
            out.append(
                R_TEST_ONLY.finding(
                    file=manifest_path,
                    symbol="android:testOnly=\"true\"",
                    note="flag parsed from the compiled AXML manifest",
                )
            )
        for perm in manifest.signature_permissions():
            if not perm.name:
                continue
            out.append(
                R_SIGNATURE_PERM_ABUSE.finding(
                    file=manifest_path, symbol=perm.name
                )
            )
        if manifest.native_libs_extractable and any(
            f.suffix == ".so" for f in target.files
        ):
            out.append(
                R_EXTRACT_NATIVELIBS.finding(
                    file=manifest_path, note="extractNativeLibs=true with .so files present"
                )
            )
        # special-access declarations (privacy matrix table, M8 track)
        from .privacy import SPECIAL_ACCESS

        for perm in sorted(getattr(manifest, "uses_permissions", None) or []):
            if perm in SPECIAL_ACCESS:
                out.append(
                    R_SPECIAL_ACCESS.finding(
                        file=manifest_path, symbol=perm
                    )
                )

    # WebView hardening (source code)
    seen: dict = {}
    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        has_js = _RX_JS_ENABLED.search(text)
        has_iface = _RX_JS_INTERFACE.search(text)
        has_file = _RX_FILE_ACCESS.search(text)
        if _RX_REMOTE_DEBUG.search(text):
            out.append(
                R_WEBVIEW_REMOTE_DEBUG.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                )
            )
        if has_iface:
            out.append(
                R_INVALID_TARGET_WEBVIEW.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                )
            )
        elif has_js or has_file:
            out.append(
                R_WEAK_WEBVIEW_JS.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                )
            )
            seen[sf.relpath] = True

    # compiled DEX pools: the API name is only referenced when used
    seen_remote: set = set()
    for rel, value in iter_pool(target):
        if _RX_REMOTE_DEBUG_API.search(value) and rel not in seen_remote:
            out.append(
                R_WEBVIEW_REMOTE_DEBUG.finding(
                    file=rel,
                    symbol=value[:80],
                    note="API reference in the compiled string pool; "
                         "verify it is only enabled in debug builds",
                )
            )
            seen_remote.add(rel)
    return out

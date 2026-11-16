"""OWASP Mobile Top 10 taxonomy.

The tool maps findings onto the **2024** revision of the OWASP Mobile Top 10
and keeps the 2016 identifiers (which most commercial scanners still emit)
as a secondary label so that reports can be compared with legacy tooling.

Reference: https://owasp.org/www-project-mobile-top-10/
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class OwaspCategory:
    id: str                 # "M9"
    name: str
    short: str              # abbreviated title for tables
    summary: str
    legacy: Optional[str]   # 2016 list id
    typical_tests: str


CATEGORIES: Dict[str, OwaspCategory] = {
    c.id: c
    for c in [
        OwaspCategory(
            id="M1",
            name="Improper Credential Usage",
            short="Improper Credential Usage",
            summary=(
                "Hardcoded credentials, credentials in shared storage, or secrets "
                "shipped inside the binary that let an attacker authenticate as the "
                "app or as another user."
            ),
            legacy="M1",
            typical_tests="Grep the byte code, resources and native libraries for keys, tokens and passwords.",
        ),
        OwaspCategory(
            id="M2",
            name="Inadequate Supply Chain Security",
            short="Supply Chain Security",
            summary=(
                "Vulnerable, outdated or tampered third party components, SDKs and "
                "native libraries, plus unsigned or repackaged application bundles."
            ),
            legacy=None,
            typical_tests="Inventory dependencies, native libraries and check signing/publisher consistency.",
        ),
        OwaspCategory(
            id="M3",
            name="Insecure Authentication/Authorization",
            short="Insecure Authentication/Authorization",
            summary=(
                "Client side authentication decisions, exported components that skip "
                "authorisation checks, or implicit intents that leak privileged data."
            ),
            legacy="M4",
            typical_tests="Review exported activities/services/receivers/providers and their permission guards.",
        ),
        OwaspCategory(
            id="M4",
            name="Insufficient Input/Output Validation",
            short="Insufficient Input/Output Validation",
            summary=(
                "Untrusted input reaching SQL queries, WebViews, file paths or IPC "
                "without validation, enabling injection, XSS or path traversal."
            ),
            legacy=None,
            typical_tests="Trace intent/deep-link/URL input into sinks such as SQL, loadUrl, file paths.",
        ),
        OwaspCategory(
            id="M5",
            name="Insecure Communication",
            short="Insecure Communication",
            summary=(
                "Cleartext traffic, broken TLS validation, missing certificate "
                "pinning or disabled platform transport security."
            ),
            legacy="M3",
            typical_tests="Check for http:// endpoints, trust-all TrustManagers, allowsArbitraryLoads, pinning.",
        ),
        OwaspCategory(
            id="M6",
            name="Inadequate Privacy Controls",
            short="Inadequate Privacy Controls",
            summary=(
                "Sensitive data written to logs, clipboard, analytics, screenshots or "
                "third party SDKs without consent or minimisation."
            ),
            legacy="M6",
            typical_tests="Look for Log calls with PII, clipboard usage, screenshot leakage flags.",
        ),
        OwaspCategory(
            id="M7",
            name="Insufficient Binary Protections",
            short="Insufficient Binary Protections",
            summary=(
                "Missing or weak reverse engineering defences: no obfuscation, "
                "debuggable builds, missing PIE/stack protections, symbol rich or "
                "unencrypted Mach-O images."
            ),
            legacy="M7",
            typical_tests="Inspect build flags, debuggable/allowBackup, PIE, ARC, canaries, symbol tables.",
        ),
        OwaspCategory(
            id="M8",
            name="Security Misconfiguration",
            short="Security Misconfiguration",
            summary=(
                "Insecure default configuration: permissive network security config, "
                "JavaScript bridges enabled, disabled ATS, world readable files, "
                "dangerous permissions granted by default."
            ),
            legacy="M10",
            typical_tests="Review manifests/plists, WebView settings, file modes and default permissions.",
        ),
        OwaspCategory(
            id="M9",
            name="Insecure Data Storage",
            short="Insecure Data Storage",
            summary=(
                "Sensitive data stored unencrypted in SharedPreferences, plists, "
                "SQLite databases, external storage, backups or the clipboard."
            ),
            legacy="M2",
            typical_tests="Check SharedPreferences/NSUserDefaults/SQLite/external storage usage and encryption.",
        ),
        OwaspCategory(
            id="M10",
            name="Insufficient Cryptography",
            short="Insufficient Cryptography",
            summary=(
                "Deprecated algorithms, hardcoded keys, static IVs/salts, ECB mode, "
                "unauthenticated ciphers, weak KDFs and predictable randomness."
            ),
            legacy="M5",
            typical_tests="Enumerate Cipher/MD5/SHA1/Random usage and key material provenance.",
        ),
    ]
}

#: legacy (2016) -> current (2024) identifier
LEGACY_TO_CURRENT: Dict[str, str] = {
    "M1": "M7",   # Improper Platform Usage  -> binary protections / misconfiguration
    "M2": "M9",   # Insecure Data Storage
    "M3": "M5",   # Insecure Communication
    "M4": "M3",   # Insecure Authentication
    "M5": "M10",  # Insufficient Cryptography
    "M6": "M7",   # Insecure Authorization  -> binary protections adjacent
    "M7": "M6",   # Client Code Quality      -> privacy / code hygiene
    "M8": "M8",   # Code Tampering           -> misconfiguration
    "M9": "M7",   # Reverse Engineering      -> binary protections
    "M10": "M8",  # Extraneous Functionality -> misconfiguration
}

ORDER: List[str] = [f"M{i}" for i in range(1, 11)]


def category(owasp_id: str) -> Optional[OwaspCategory]:
    return CATEGORIES.get((owasp_id or "").upper())


def category_name(owasp_id: str) -> str:
    cat = category(owasp_id)
    return cat.name if cat else "Uncategorised"


def category_short(owasp_id: str) -> str:
    cat = category(owasp_id)
    return cat.short if cat else "Uncategorised"


def legacy_name(owasp_id: str) -> str:
    """Human readable legacy (2016) label for a 2024 identifier."""
    cat = category(owasp_id)
    return cat.legacy or "-" if cat else "-"

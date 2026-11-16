"""M6 - Inadequate Privacy Controls.

Sensitive (PII / credential) data written to logs, standard output or
unprotected persistence; overly chatty diagnostics.
"""

from __future__ import annotations

import re
from typing import Iterable, List

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, ev_pool, make_rule, secret_poc, text_scan
from .privacy import SENSITIVE_PERMISSIONS

MEDIUM = Severity.MEDIUM
LOW = Severity.LOW

R_LOG_CREDENTIAL = make_rule(
    "MAS-PRI-001",
    "M6",
    "Credential material written to logs",
    "A log/print call includes a password/token/key variable or literal, so "
    "credentials reach system logs and crash reports.",
    MEDIUM,
    "Log non-secret identifiers only; strip secrets before logging and "
    "restrict log level in release builds.",
    cwe="CWE-532",
    confidence=Confidence.HIGH,
    cvss=5.5,
)

R_LOG_PII = make_rule(
    "MAS-PRI-002",
    "M6",
    "Personal data written to logs",
    "A log call includes personal data fields (user id, email, phone, "
    "location) without redaction.",
    MEDIUM,
    "Log aggregate/pseudonymised data and rotate away from verbose logging "
    "in production.",
    cwe="CWE-532",
    confidence=Confidence.MEDIUM,
)

R_STDOUT_TOKEN = make_rule(
    "MAS-PRI-003",
    "M6",
    "Secret value printed to standard output",
    "print/console output leaks token/password material to the device console "
    "(ideal for an attached attacker with a debug session).",
    MEDIUM,
    "Remove debug prints in release executables.",
    cwe="CWE-532",
    confidence=Confidence.HIGH,
    cvss=5.0,
    platform="ios",
)

R_PII_PLIST = make_rule(
    "MAS-PRI-005",
    "M6",
    "Personal data persisted in a preferences file",
    "A property list key carries personal data (email/user/phone/identifier) "
    "outside the Keychain, where file-system access or backups expose it.",
    MEDIUM,
    "Persist personal data only in the Keychain or encrypt before storing.",
    cwe="CWE-359",
    confidence=Confidence.MEDIUM,
    platform="ios",
)

R_CLIPPING = make_rule(
    "MAS-PRI-006",
    "M6",
    "Sensitive view exposed to screen capture",
    "The app does not disable screenshots/no-screen-capture flags while "
    "showing credential fields (FLAG_SECURE absent in visible credential UI).",
    LOW,
    "Set FLAG_SECURE on credential-bearing screens and blur on app switcher.",
    cwe="CWE-200",
    confidence=Confidence.LOW,
    platform="android",
)

R_PRI_EXCESS_SENSITIVE = make_rule(
    "MAS-PRI-007",
    "M6",
    "Excess access: sensitive permission never exercised in the artifact",
    "A sensitive runtime permission (location, camera, microphone, "
    "contacts, SMS, phone-identity) is declared in the manifest, but the "
    "static artifact shows no code path that exercises its APIs - classic "
    "excess access (permission granted by promise, never used and never "
    "audited). Check the privacy matrix rows under "
    "inventory.privacy for the corroborated/unused split.",
    MEDIUM,
    "Remove the permission (or gate it behind the feature that actually "
    "uses it); re-run the scan to confirm the matrix row flips to "
    "'corroborated'.",
    cwe="CWE-250",
    confidence=Confidence.LOW,
    cvss=5.0,
    platform="android",
)

R_PRI_EXCESS = make_rule(
    "MAS-PRI-008",
    "M6",
    "Excess access: dangerous permission without observed use",
    "A dangerous runtime permission is declared but the scan found no "
    "corroborating API use in classes, strings or manifest wiring - dead "
    "privilege that keeps the app in review-scope for no product value.",
    LOW,
    "Trim the declaration; every remaining dangerous permission should map "
    "to an observed behavior (privacy matrix > corroborated).",
    cwe="CWE-250",
    confidence=Confidence.LOW,
    platform="android",
)

_RX_LOG_SECRET = re.compile(
    r"(?:Log|NSLog|logger|Log\.)(?:\.[underschdfivw])?\s*\([^\n]{0,120}"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|credential|pin)[^\n]{0,200}",
    re.I,
)
_RX_PRINT_SECRET = re.compile(
    r"(?:print|println)\s*\([^\n]{0,80}(?:token|password|secret|credential|key)[^\n]{0,120}",
    re.I,
)
_RX_LOG_PII = re.compile(
    r"(?:Log\.|NSLog|println)\s*\([^\n]{0,120}"
    r"(?:user(?:name|id)?|email|phone|ssn|dob|location)[^\n]{0,150}",
    re.I,
)
_RX_PII_KEYS = re.compile(
    r"^(?:.*)((?:user|customer).{0,4}id|email|e-mail|phone(?:number)?|ssn|dob|birthdate)$",
    re.I,
)


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []
    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        if _RX_LOG_SECRET.search(text):
            out.append(
                R_LOG_CREDENTIAL.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        elif _RX_PRINT_SECRET.search(text):
            out.append(
                R_STDOUT_TOKEN.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        elif _RX_LOG_PII.search(text):
            out.append(
                R_LOG_PII.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )

    # iOS plist PII snapshot
    for rel, data in (target.meta.get("plists") or {}).items():
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(key, str) and _RX_PII_KEYS.match(key) and val:
                    shown = val if isinstance(val, str) else str(val)
                    f = R_PII_PLIST.finding(
                        file=rel, symbol=str(key)[:60], note="plist key with PII value"
                    )
                    f.poc = secret_poc(shown)
                    out.append(f)

    # excess-access privacy matrix (built during packaging on android)
    matrix = target.meta.get("privacy_matrix") or {}
    for row in matrix.get("rows") or []:
        if not row.get("excess"):
            continue
        name = str(row.get("permission", "?"))
        note = "declared dangerous permission; no corroboration in dex/strings/manifest"
        if name in ("android.permission.ACCESS_BACKGROUND_LOCATION",):
            note += "; note the grant persists location tracking across app death"
        rule = R_PRI_EXCESS_SENSITIVE \
            if name in SENSITIVE_PERMISSIONS else R_PRI_EXCESS
        out.append(
            rule.finding(
                file=target.meta.get("manifest_path", "AndroidManifest.xml"),
                symbol=name,
                note=note,
            )
        )
    return out

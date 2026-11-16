"""M9 - Insecure Data Storage.

Unencrypted persistence of sensitive material: world-readable preferences,
external storage writes of credentials, plaintext databases, and
preferences/plists carrying raw secrets.
"""

from __future__ import annotations

import re
from typing import Iterable, List

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, make_rule, secret_poc

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
CRITICAL = Severity.CRITICAL
LOW = Severity.LOW

R_WORLD_READABLE = make_rule(
    "MAS-STO-001",
    "M9",
    "Preferences opened world-readable",
    'MODE_WORLD_READABLE/WRITEABLE (or a 0666 open) makes the SharedPreferences '
    "file readable by every other app on the device.",
    CRITICAL,
    "Use MODE_PRIVATE and EncryptedSharedPreferences; nothing app-inside "
    "belongs in world-readable storage.",
    cwe="CWE-312",
    confidence=Confidence.HIGH,
    cvss=8.5,
)

R_EXTERNAL_STORAGE = make_rule(
    "MAS-STO-002",
    "M9",
    "Sensitive data written to shared external storage",
    "Writes under Environment.getExternalStorageDirectory (or "
    "WRITE_EXTERNAL_STORAGE paths) are globally readable and survive app removal.",
    MEDIUM,
    "Store app data in the private files dir; encrypt before anything leaves "
    "the app sandbox.",
    cwe="CWE-312",
    confidence=Confidence.HIGH,
    cvss=5.5,
)

R_STATUS_PLIST = make_rule(
    "MAS-STO-005",
    "M9",
    "Credential material stored outside the Keychain",
    "UserDefaults/plist persistence of a password, token or PIN; the plist is "
    "readable whenever the device is jail-broken or a backup is taken and "
    "does not require the Keychain's protection class.",
    MEDIUM,
    "Persist credentials via the Keychain (kSecClassGenericPassword) and keep "
    "UserDefaults for non-sensitive settings.",
    cwe="CWE-312",
    confidence=Confidence.HIGH,
    cvss=6.5,
    platform="ios",
)

R_UNENCRYPTED_DB = make_rule(
    "MAS-STO-007",
    "M9",
    "Plaintext database used for sensitive records",
    "openOrCreateDatabase/SQLiteOpenHelper is used without an encryption "
    "pass (SQLCipher) although the tables are credential-shaped.",
    MEDIUM,
    "Encrypt sensitive fields or use SQLCipher for the whole file.",
    cwe="CWE-312",
    confidence=Confidence.MEDIUM,
)

R_TOKEN_IN_SOURCE = make_rule(
    "MAS-STO-010",
    "M9",
    "Session material reconstructed from constants",
    "Instance state constants carry session/token material (saved bundle "
    "strings), which persists unencrypted over the activity lifecycle.",
    LOW,
    "Rebuild sessions from non-secret seeds and always store tokens in "
    "encrypted durable storage.",
    cwe="CWE-312",
    confidence=Confidence.LOW,
)

_RX_WORLD_READABLE = re.compile(
    r"(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|chmod\(.*[\"|']?06[67][46]|"
    r"openFileOutput\s*\([^)]*,\s*MODE_WORLD)",
    re.I,
)
_RX_EXTERNAL_STORAGE = re.compile(
    r"(getExternalStorageDirectory|getExternalStoragePublicDirectory|"
    r"WRITE_EXTERNAL_STORAGE.*write|getExternalFilesDir)",
    re.I,
)
_RX_DB_OPEN = re.compile(r"(openOrCreateDatabase|SQLiteOpenHelper)\s*\(", re.I)
_RX_DB_SENSITIVE = re.compile(r"(password|token|pin|credential|secret|user)", re.I)
_RX_BUNDLE_SESSION = re.compile(r"(savedInstanceState|onSaveInstanceState)[^\n]{0,120}(token|session|auth)", re.I)
_RX_PII_KEYS = re.compile(
    r"^(?:.*)(?:password|passwd|pwd|secret|token|pin|credential|auth)$", re.I
)


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []

    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        if _RX_WORLD_READABLE.search(text):
            out.append(
                MAS_STO_001_world(sf, lineno, text)
            )
        elif _RX_EXTERNAL_STORAGE.search(text) and _looks_sensitive(sf, target):
            out.append(
                R_EXTERNAL_STORAGE.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        elif _RX_DB_OPEN.search(text) and _RX_DB_SENSITIVE.search(text):
            out.append(
                R_UNENCRYPTED_DB.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_BUNDLE_SESSION.search(text):
            out.append(
                R_TOKEN_IN_SOURCE.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )

    # iOS/Android plist snapshot material — sensitive keys with non-empty values
    for rel, data in (target.meta.get("plists") or {}).items():
        if isinstance(data, dict):
            for key, val in _walk(data):
                low = str(key).lower()
                if _RX_PII_KEYS.match(low) and val not in (None, "", False, []):
                    f = R_STATUS_PLIST.finding(file=rel, symbol=str(key)[:60])
                    f.poc = secret_poc(str(val))
                    out.append(f)
    return out


def MAS_STO_001_world(sf, lineno, text):  # noqa: N802 (rule-local helper)
    return R_WORLD_READABLE.finding(
        file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
    )


def _looks_sensitive(sf, target) -> bool:
    body = sf.read_text()
    if not body:
        return False
    low = body.lower()
    return any(w in low for w in ("password", "token", "secret", "credential", "pin"))


def _walk(node) -> Iterable[tuple]:
    if isinstance(node, dict):
        for key, val in node.items():
            yield key, val
            yield from _walk(val)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk(item)

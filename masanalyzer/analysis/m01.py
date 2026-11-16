"""M1 - Improper Credential Usage.

Looks for authentication material (passwords, API keys, tokens, cloud keys,
DB connection strings, basic-auth URLs) hard-coded in source files, compiled
string pools and application property lists.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..model import Confidence, Finding, Severity, Target
from .common import (
    ev,
    ev_pool,
    iter_pool,
    make_rule,
    secret_poc,
    text_scan,
)

HIGH = Severity.HIGH
MEDIUM = Severity.MEDIUM

R_PASSWORD = make_rule(
    "MAS-CRED-001",
    "M1",
    "Hard-coded password in source code",
    'A password literal ("password = ..."/"setPassword(...)") is embedded in the '
    "shipped source. Anyone able to decompile or download the bundle can use it.",
    HIGH,
    "Remove the credential from code, ship secrets via a runtime-injected secure "
    "channel and store only derived material in secure storage.",
    cwe="CWE-798",
    confidence=Confidence.HIGH,
    cvss=8.2,
)

R_API_KEY = make_rule(
    "MAS-CRED-002",
    "M1",
    "Hard-coded API key or secret token",
    "A variable/constant named like an API key, secret or token is assigned a "
    "non-trivial literal value in the shipped code.",
    HIGH,
    "Move key material out of the client into a backend-owned exchange or a "
    "per-install bootstrap secret.",
    cwe="CWE-798",
    confidence=Confidence.MEDIUM,
    cvss=7.5,
)

R_CLOUD_KEY = make_rule(
    "MAS-CRED-003",
    "M1",
    "Cloud provider credential embedded in the bundle",
    "A well-known cloud/static credential format (AWS access key, Google API "
    "key, GitHub token) appears in the compiled binary assets.",
    HIGH,
    "Rotate the exposed credential immediately and serve it from a backend "
    "using restricted, short-lived tokens.",
    cwe="CWE-798",
    confidence=Confidence.HIGH,
    cvss=8.5,
)

R_BEARER = make_rule(
    "MAS-CRED-004",
    "M1",
    "Bearer token or JWT shipped in the binary",
    "A Bearer/JWT-shaped token is present in the compiled string pool of the "
    "application.",
    HIGH,
    "Tokens must be session-scoped and fetched at runtime; ship refresh "
    "material only via a platform secure store seeded by the server.",
    cwe="CWE-522",
    confidence=Confidence.MEDIUM,
    cvss=7.4,
)

R_JDBC = make_rule(
    "MAS-CRED-005",
    "M1",
    "Database connection string with embedded credentials",
    "A connection string of the form scheme://user:password@host (or "
    "jdbc:...://user:pass@) is embedded in the bundle.",
    HIGH,
    "The application should never carry direct database credentials; access "
    "the data store exclusively via the backend API.",
    cwe="CWE-798",
    confidence=Confidence.HIGH,
    cvss=9.1,
)

R_BASIC_AUTH_URL = make_rule(
    "MAS-CRED-006",
    "M1",
    "Basic-auth credentials in a URL",
    "A URL embeds user information (https://user:pass@host), leaking "
    "credentials into logs and proxies.",
    MEDIUM,
    "Use HTTP authentication headers populated at runtime instead of "
    "user-info URLs.",
    cwe="CWE-522",
    confidence=Confidence.MEDIUM,
)

R_URL_QUERY = make_rule(
    "MAS-CRED-007",
    "M1",
    "Credential passed in a URL query string",
    "A URL literal carries a password/token/secret-looking query parameter; "
    "such values typically end up in server, proxy and crash logs.",
    MEDIUM,
    "Send secrets in the request body over TLS or as runtime-supplied "
    "headers, never in the URL.",
    cwe="CWE-598",
    confidence=Confidence.MEDIUM,
)

R_PREFS_KEY = make_rule(
    "MAS-CRED-008",
    "M1",
    "Credential persisted in an application property list",
    "A key named like a password/token/secret in a property list carries a "
    "non-empty value; anyone with the bundle or a backup can read it.",
    MEDIUM,
    "Store credentials in the platform secure store (Keychain / "
    "EncryptedSharedPreferences) instead of preference files.",
    cwe="CWE-312",
    confidence=Confidence.MEDIUM,
    platform="ios",
)

R_FIREBASE = make_rule(
    "MAS-CRED-009",
    "M1",
    "Firebase backend endpoint embedded in the bundle",
    "A firebaseio.com endpoint (Realtime Database / Firestore web URL) is "
    "hard-coded in the bundle. Google documents that projects relying on "
    "the default rule set can expose all records publicly; whether this "
    "project's rules are open cannot be verified offline - verify the "
    "rules yourself.",
    MEDIUM,
    "Verify the Firebase security rules deny unauthenticated access, and "
    "keep endpoints out of release strings where possible.",
    cwe="CWE-200",
    confidence=Confidence.MEDIUM,
    extra_refs=["https://firebase.google.com/docs/rules/basics"],
)

# -- regexes -----------------------------------------------------------------
rx_password = re.compile(
    r'["\'](?:password|passwd|pwd)["\']\s*[:=,]?\s*["\']([^"\']+)["\']'
    r"| setPassword\s*\(\s*\"([^\"]+)\""
    r"| (?:password|passwd|pwd)\s*=\s*\"([^\"]+)\"",
    re.I,
)
rx_api_key = re.compile(
    r"(?:api[_-]?key|api[_-]?secret|secret|token|access[_-]?key|"
    r"client[_-]?(?:id|secret)|auth[_-]?token)\w*\s*[:=]\s*\"([^\"'\s]{8,})\"",
    re.I,
)
rx_cloud_key = re.compile(
    r"(AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_\-]{35}|ghp_[A-Za-z0-9]{36}"
    r"|gho_[A-Za-z0-9]{36}|sk_live_[0-9a-zA-Z]{16,})"
)
rx_bearer = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+/[=]{0,2}|Bearer\s+ey[A-Za-z0-9_\-\.]{10,}")
rx_jwt = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")
rx_db_url = re.compile(r"(?:jdbc:mysql|jdbc:postgresql|mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"]*:[^\s'\"]{2,}@")
rx_firebase = re.compile(r"(?:https?://)?[A-Za-z0-9._%-]{1,60}\.firebaseio\.com")
rx_basic_url = re.compile(r"https?://[A-Za-z0-9._%~:\-]+:[^@\s/'\"]{1,64}@")
rx_query_secret = re.compile(
    r"https?://[^\s'\"]{1,200}\?(?:[^\s'\"]*&)*(?:[\w.\-]*"
    r"(?:password|passwd|pwd|token|secret|api[_-]?key|session|auth)[\w.\-]*)=",
    re.I,
)
rx_sensitive_key = re.compile(
    r"^(?:.*)(?:password|passwd|pwd|secret|token|credential|api[_-]?key)",
    re.I,
)


def analyze(target: Target) -> Iterable[Finding]:
    out = []

    def add(finding: Finding) -> None:
        out.append(finding)

    # --- source code --------------------------------------------------------
    for sf, lineno, text in text_scan(target, kinds=("code", "resource")):
        m = rx_password.search(text)
        if m:
            secret = next((g for g in m.groups() if g), "")
            f = R_PASSWORD.finding(
                file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
            )
            f.poc = secret_poc(secret)
            add(f)
            continue
        m = rx_api_key.search(text)
        if m:
            secret = m.group(1)
            f = R_API_KEY.finding(
                file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
            )
            f.poc = secret_poc(secret)
            add(f)
            continue
        if rx_query_secret.search(text):
            add(
                R_URL_QUERY.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if rx_basic_url.search(text):
            add(
                R_BASIC_AUTH_URL.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if rx_firebase.search(text):
            add(
                R_FIREBASE.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )

    # --- compiled string pool ------------------------------------------------
    seen_pool: set = set()          # dedupe identical secrets across containers

    def pool_dedupe(normalized: str) -> bool:
        if normalized in seen_pool:
            return True
        seen_pool.add(normalized)
        return False

    for rel, value in iter_pool(target):
        norm = value.lstrip("_-()/\\ \t")
        m = rx_cloud_key.search(value)
        if m:
            if pool_dedupe(m.group(1)):
                continue
            f = R_CLOUD_KEY.finding(file=rel, snippet=ev_pool(rel, value).symbol)
            f.evidence = ev_pool(rel, value)
            f.poc = secret_poc(m.group(1))
            add(f)
            continue
        if rx_bearer.search(value) or rx_jwt.search(value):
            if pool_dedupe(norm):
                continue
            f = R_BEARER.finding()
            f.evidence = ev_pool(rel, value)
            f.poc = secret_poc(value[:80])
            add(f)
            continue
        if rx_db_url.search(value):
            if pool_dedupe(norm):
                continue
            f = R_JDBC.finding()
            f.evidence = ev_pool(rel, value)
            f.poc = secret_poc(value[:80])
            add(f)
            continue
        if rx_firebase.search(value):
            if pool_dedupe(norm):
                continue
            f = R_FIREBASE.finding()
            f.evidence = ev_pool(rel, value)
            f.poc = secret_poc(value[:80])
            add(f)
            continue

    # --- iOS plists -----------------------------------------------------------
    plists = target.meta.get("plists") or {}

    def walk(rel: str, node) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if isinstance(key, str) and rx_password_str(key):
                    if isinstance(val, str) and val and not key.lower().endswith("tokenHelper"):
                        f = R_PREFS_KEY.finding()
                        f.evidence = ev_pool(rel, str(key), note="plist credential key")
                        f.poc = secret_poc(val)
                        add(f)
                walk(rel, val)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(rel, item)

    def rx_password_str(key: str) -> bool:
        low = key.lower().replace("-", "_")
        return any(w in low for w in ("password", "passwd", "pwd", "secret", "token", "api_key"))

    for rel, data in plists.items():
        if isinstance(data, dict):
            walk(rel, data)

    return out

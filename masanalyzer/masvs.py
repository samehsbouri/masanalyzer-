"""OWASP MASVS v2 requirement mapping - audit-grade requirement matrix.

MASVS groups findings into requirement families.  ``audit()`` takes one scan
result and answers the audit question *per requirement*: FAIL (a kept
finding maps here), PASS (the covering analyzer ran, nothing fires) or N/A
(no analyzer covered that category).

The ``RULE_TO_MASVS`` table is masanalyzer's editorial mapping between its
rules and the MASVS v2 requirement identifiers; the requirement glosses are
abbreviated, self-contained descriptions written for this report, not the
normative MASVS text (read the standard itself for the official wording).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

STATUS_FAIL = "FAIL"
STATUS_PASS = "PASS"
STATUS_NOT_ASSESSED = "N/A"

#: requirement id -> short self-authored gloss (what the audit row means)
MASVS_REQUIREMENTS: Dict[str, str] = {
    "MASVS-STORAGE-1": "Sensitive data is stored only in protected "
    "application storage (no world-readable files, no external storage, "
    "no plaintext databases).",
    "MASVS-STORAGE-2": "No sensitive data leaves the app through backup, "
    "cloud restore or extracted native payloads.",
    "MASVS-CRYPTO-1": "Cryptography uses modern, authenticated schemes "
    "(no MD5/SHA-1 for security, no ECB, explicit modes, MAC present).",
    "MASVS-CRYPTO-2": "Key material and randomness come from platform "
    "providers (CSPRNG, no predictable seeds, no shipped IVs).",
    "MASVS-AUTHENTICATION-1": "User identity material is not embedded in "
    "the bundle (no hard-coded passwords, keys, tokens, JDBC strings).",
    "MASVS-AUTHENTICATION-2": "Authentication material never travels or "
    "persists in redesignable channels (URLs, plists, constant-derived "
    "sessions).",
    "MASVS-AUTHORIZATION-1": "Cross-app boundaries enforce explicit "
    "authorization (exported components guarded, no sharedUserId).",
    "MASVS-NETWORK-1": "All traffic is encrypted (no cleartext flags, "
    "config allows, or http:// endpoints).",
    "MASVS-NETWORK-2": "Server identity is verified (no user trust "
    "anchors, no trust-all TLS, pinning present).",
    "MASVS-PLATFORM-1": "Platform protections stay enabled (no "
    "debuggable/test-only builds, no signature-permission abuse).",
    "MASVS-PLATFORM-2": "Embedding engines are hardened (WebView JS "
    "interface exposure, JS enablement, file access).",
    "MASVS-PLATFORM-3": "Untrusted input is validated on the path to "
    "sensitive sinks (SQL, commands, paths, WebViews, taint flows).",
    "MASVS-INTERACTION-1": "App-to-app entry points validate their input "
    "(deep links, WebView navigation).",
    "MASVS-PRIVACY-1": "Personal data does not leak into diagnostic "
    "channels or capture-able screen state.",
    "MASVS-PRIVACY-2": "Secrets are not printed to stdout / diagnostics.",
    "MASVS-RESILIENCE-1": "The bundle is signed and configured in a "
    "security-hardened release mode (verification, certificates, "
    "provisioning).",
    "MASVS-RESILIENCE-2": "Anti-tamper posture of shipped binaries (ZIP "
    "layout, page hashes, PIE/NX/RELRO, writable text).",
    "MASVS-CODE-1": "Ship-ready code hygiene (obfuscation, stripped "
    "binaries, current toolchain/dependencies).",
}

#: OWASP M# -> default requirements when a rule is not explicitly mapped
_OWASP_DEFAULTS: Dict[str, Tuple[str, ...]] = {
    "M1": ("MASVS-AUTHENTICATION-1",),
    "M2": ("MASVS-RESILIENCE-1",),
    "M3": ("MASVS-AUTHORIZATION-1",),
    "M4": ("MASVS-PLATFORM-3",),
    "M5": ("MASVS-NETWORK-2",),
    "M6": ("MASVS-PRIVACY-1",),
    "M7": ("MASVS-RESILIENCE-2",),
    "M8": ("MASVS-PLATFORM-1",),
    "M9": ("MASVS-STORAGE-1",),
    "M10": ("MASVS-CRYPTO-1",),
    "M4+M5": (),
}

RULE_TO_MASVS: Dict[str, Tuple[str, ...]] = {
    # M1 - credentials
    "MAS-CRED-001": ("MASVS-AUTHENTICATION-1",),
    "MAS-CRED-002": ("MASVS-AUTHENTICATION-1",),
    "MAS-CRED-003": ("MASVS-AUTHENTICATION-1",),
    "MAS-CRED-004": ("MASVS-AUTHENTICATION-1",),
    "MAS-CRED-005": ("MASVS-AUTHENTICATION-1",),
    "MAS-CRED-006": ("MASVS-AUTHENTICATION-2",),
    "MAS-CRED-007": ("MASVS-AUTHENTICATION-2",),
    "MAS-CRED-008": ("MASVS-AUTHENTICATION-2", "MASVS-STORAGE-1"),
    "MAS-CRED-009": ("MASVS-STORAGE-1",),
    # M10 - cryptography
    "MAS-CRY-001": ("MASVS-CRYPTO-1",),
    "MAS-CRY-002": ("MASVS-CRYPTO-1",),
    "MAS-CRY-003": ("MASVS-CRYPTO-1",),
    "MAS-CRY-004": ("MASVS-CRYPTO-1",),
    "MAS-CRY-005": ("MASVS-CRYPTO-2",),
    "MAS-CRY-006": ("MASVS-CRYPTO-2",),
    "MAS-CRY-007": ("MASVS-CRYPTO-2",),
    "MAS-CRY-008": ("MASVS-CRYPTO-1",),
    "MAS-CRY-009": ("MASVS-CRYPTO-1",),
    # M2 - supply chain / signing
    "MAS-SUP-001": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-002": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-003": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-004": ("MASVS-CODE-1",),
    "MAS-SUP-005": ("MASVS-CODE-1",),
    "MAS-SUP-007": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-008": ("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2"),
    "MAS-SUP-009": ("MASVS-RESILIENCE-2",),
    "MAS-SUP-010": ("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2"),
    "MAS-SUP-011": ("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2"),
    "MAS-SUP-012": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-013": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-014": ("MASVS-RESILIENCE-1",),
    "MAS-SUP-015": ("MASVS-RESILIENCE-1",),
    "MAS-SCA-001": ("MASVS-RESILIENCE-1", "MASVS-CODE-1"),
    "MAS-SCA-002": ("MASVS-CODE-1",),
    "MAS-BIN-006": ("MASVS-CODE-1",),
    "MAS-BIN-010": ("MASVS-RESILIENCE-1",),
    # M3 - authorization
    "MAS-AUTH-001": ("MASVS-AUTHORIZATION-1",),
    "MAS-AUTH-002": ("MASVS-AUTHORIZATION-1",),
    "MAS-AUTH-003": ("MASVS-AUTHORIZATION-1",),
    "MAS-AUTH-004": ("MASVS-AUTHORIZATION-1", "MASVS-AUTHENTICATION-1"),
    "MAS-AUTH-005": ("MASVS-AUTHORIZATION-1",),
    "MAS-AUTH-006": ("MASVS-INTERACTION-1",),
    # M4 - input handling
    "MAS-INPUT-001": ("MASVS-PLATFORM-3",),
    "MAS-INPUT-002": ("MASVS-PLATFORM-3",),
    "MAS-INPUT-003": ("MASVS-PLATFORM-3", "MASVS-STORAGE-1"),
    "MAS-INPUT-004": ("MASVS-PLATFORM-2", "MASVS-INTERACTION-1"),
    "MAS-INPUT-005": ("MASVS-PLATFORM-3",),
    "MAS-INPUT-006": ("MASVS-PLATFORM-3",),
    "MAS-INPUT-007": ("MASVS-PLATFORM-3",),
    "MAS-INPUT-008": ("MASVS-PLATFORM-3",),
    # M5 - communication
    "MAS-NET-001": ("MASVS-NETWORK-1",),
    "MAS-NET-002": ("MASVS-NETWORK-1",),
    "MAS-NET-003": ("MASVS-NETWORK-2",),
    "MAS-NET-004": ("MASVS-NETWORK-2",),
    "MAS-NET-005": ("MASVS-NETWORK-1",),
    "MAS-NET-006": ("MASVS-NETWORK-2",),
    "MAS-NET-007": ("MASVS-NETWORK-2",),
    "MAS-NET-008": ("MASVS-NETWORK-1", "MASVS-PRIVACY-1"),
    "MAS-NET-009": ("MASVS-NETWORK-1",),
    "MAS-NET-010": ("MASVS-NETWORK-2",),
    "MAS-NET-011": ("MASVS-NETWORK-1",),
    # M6 - privacy
    "MAS-PRI-001": ("MASVS-PRIVACY-2",),
    "MAS-PRI-002": ("MASVS-PRIVACY-1",),
    "MAS-PRI-003": ("MASVS-PRIVACY-2",),
    "MAS-PRI-005": ("MASVS-PRIVACY-1", "MASVS-STORAGE-1"),
    "MAS-PRI-006": ("MASVS-PRIVACY-1",),
    # M7 - binary protections
    "MAS-BIN-001": ("MASVS-PLATFORM-1",),
    "MAS-BIN-002": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-003": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-004": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-005": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-007": ("MASVS-CODE-1",),
    "MAS-BIN-008": ("MASVS-RESILIENCE-1",),
    "MAS-BIN-011": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-012": ("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2"),
    "MAS-BIN-013": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-014": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-015": ("MASVS-CODE-1",),
    "MAS-BIN-016": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-017": ("MASVS-RESILIENCE-2",),
    "MAS-BIN-018": ("MASVS-RESILIENCE-1",),
    # M8 - misconfiguration
    "MAS-MIS-001": ("MASVS-STORAGE-2",),
    "MAS-MIS-002": ("MASVS-PLATFORM-1",),
    "MAS-MIS-003": ("MASVS-AUTHORIZATION-1",),
    "MAS-MIS-004": ("MASVS-PLATFORM-2",),
    "MAS-MIS-005": ("MASVS-PLATFORM-2",),
    "MAS-MIS-006": ("MASVS-STORAGE-2",),
    "MAS-MIS-008": ("MASVS-PLATFORM-2",),
    # M9 - storage
    "MAS-STO-001": ("MASVS-STORAGE-1",),
    "MAS-STO-002": ("MASVS-STORAGE-1",),
    "MAS-STO-005": ("MASVS-STORAGE-1", "MASVS-AUTHENTICATION-2"),
    "MAS-STO-007": ("MASVS-STORAGE-1",),
    "MAS-STO-010": ("MASVS-AUTHENTICATION-2",),
}


def rule_requirements(rule_id: str, owasp: str = "") -> Tuple[str, ...]:
    """Map one rule to its MASVS requirement ids (explicit table first)."""
    if rule_id in RULE_TO_MASVS:
        return RULE_TO_MASVS[rule_id]
    return _OWASP_DEFAULTS.get(owasp.upper(), ())


def audit(result: Any) -> Dict[str, Any]:
    """Requirement-level status for one scanned target.

    Returns ``{"requirements": [row...], "counts": {...}}`` where each row
    has ``id, requirement, status, worst, findings``. A kept finding makes
    the requirement FAIL at its own severity level; a requirement whose
    covering OWASP category was assessed (an analyzer ran) with no finding
    PASSes; everything else is N/A.
    """
    from .model import SEVERITY_RANK

    severity_worst: Dict[str, Tuple[int, Any]] = {}   # req -> (rank, severity)
    rows: List[Dict[str, Any]] = []

    for f in getattr(result, "findings", None) or []:
        for req in rule_requirements(
            str(getattr(f, "rule_id", "")), str(getattr(f, "owasp", ""))
        ):
            sev = getattr(f, "severity", None)
            rank = SEVERITY_RANK.get(sev, 0)
            if req not in severity_worst or rank > severity_worst[req][0]:
                severity_worst[req] = (rank, sev)

    # requirement -> OWASP M# categories its analyzers come from
    covered = set(getattr(result, "covered_categories", None) or [])
    req_category: Dict[str, Tuple[str, ...]] = {
        "MASVS-STORAGE-1": ("M9",),
        "MASVS-STORAGE-2": ("M8",),
        "MASVS-CRYPTO-1": ("M10",),
        "MASVS-CRYPTO-2": ("M10",),
        "MASVS-AUTHENTICATION-1": ("M1",),
        "MASVS-AUTHENTICATION-2": ("M1",),
        "MASVS-AUTHORIZATION-1": ("M3",),
        "MASVS-NETWORK-1": ("M5",),
        "MASVS-NETWORK-2": ("M5",),
        "MASVS-PLATFORM-1": ("M8", "M7"),
        "MASVS-PLATFORM-2": ("M8",),
        "MASVS-PLATFORM-3": ("M4",),
        "MASVS-INTERACTION-1": ("M4", "M3"),
        "MASVS-PRIVACY-1": ("M6",),
        "MASVS-PRIVACY-2": ("M6",),
        "MASVS-RESILIENCE-1": ("M2",),
        "MASVS-RESILIENCE-2": ("M7", "M2"),
        "MASVS-CODE-1": ("M2", "M7"),
    }

    for req in MASVS_REQUIREMENTS:
        if req in severity_worst:
            rank, sev = severity_worst[req]
            rows.append({
                "id": req,
                "requirement": MASVS_REQUIREMENTS[req],
                "status": STATUS_FAIL,
                "worst": getattr(sev, "value", None) or str(sev),
                "findings": 1,
            })
            continue
        cats = req_category.get(req, ())
        if all(c in covered for c in cats) and cats:
            rows.append({
                "id": req,
                "requirement": MASVS_REQUIREMENTS[req],
                "status": STATUS_PASS,
                "worst": "",
                "findings": 0,
            })
        else:
            rows.append({
                "id": req,
                "requirement": MASVS_REQUIREMENTS[req],
                "status": STATUS_NOT_ASSESSED,
                "worst": "",
                "findings": 0,
            })
    counts: Dict[str, int] = {STATUS_FAIL: 0, STATUS_PASS: 0, STATUS_NOT_ASSESSED: 0}
    for r in rows:
        counts[r["status"]] += 1
    return {"requirements": rows, "counts": counts}


def render_audit(result: Any) -> str:
    """Render the requirement matrix as compact Markdown text."""
    doc = audit(result)
    lines = [
        "# MASVS v2 requirement audit",
        "",
        "| Requirement | Status | Worst severity | Covers |",
        "| --- | --- | --- | --- |",
    ]
    for row in doc["requirements"]:
        covers = row["status"] == STATUS_FAIL and row.get("worst") or ""
        lines.append(
            f"| {row['id']} | {row['status']} | {covers} | {row['requirement']} |"
        )
    c = doc["counts"]
    lines += [
        "",
        f"**Summary**: {c[STATUS_FAIL]} FAIL · {c[STATUS_PASS]} PASS · "
        f"{c[STATUS_NOT_ASSESSED]} not assessed",
        "",
        "Requirement glosses are abbreviated; failures point at the mapped "
        "rule findings in the JSON/markdown report.",
    ]
    return "\n".join(lines) + "\n"

"""NIAP-style assurance matrix (honest subset, not a certification).

A *NIAP-style assurance subset*: a requirement corpus in the shape of a
NIAP protection-profile matrix (identifier / requirement / status /
detail), where every row is mapped to the concrete masanalyzer rule IDs
whose findings satisfy or violate it - plus a couple of rows computed
from the parsed signing facts directly.

Honesty notes, stated on every render:

* this is **not** a NIAP certification and claims none of its process
  steps (no evaluation lab, no ALC, no vulnerability analysis depth);
* ``pass`` means "the mapped checks ran and none of them produced a
  finding" - it is exactly as strong as those checks;
* ``not assessed`` rows mark facts the run did not evaluate
  (e.g. no v2/v3 block to verify), instead of passing silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

STATUS_PASS = "pass"
STATUS_ATTN = "attention"
STATUS_NA = "not applicable"
STATUS_UNK = "not assessed"


@dataclass(frozen=True)
class NiapRequirement:
    """One requirement row: mapped to the rule IDs that decide it."""

    ident: str
    requirement: str
    #: what the row's status actually means (scope of the check)
    detail: str
    #: masanalyzer rule IDs whose findings violate the requirement
    rules: Tuple[str, ...]
    platforms: Tuple[str, ...] = ("android", "ios")


REQUIREMENTS: Tuple[NiapRequirement, ...] = (
    NiapRequirement(
        "NIA-01",
        "Application identity and provenance recorded",
        "Bundle hashes, package identity, version and signer certificate "
        "extracted and reported (FPT-style identity baseline).",
        (
            "MAS-SUP-001", "MAS-SUP-002", "MAS-SUP-013", "MAS-SUP-014",
            "MAS-BIN-010", "MAS-BIN-012",
        ),
    ),
    NiapRequirement(
        "NIA-02",
        "Whole-file code signature present and verified",
        "v2/v3 signing blocks verified cryptographically against the file "
        "content (failed verification = tampering evidence).",
        (
            "MAS-SUP-008", "MAS-SUP-009", "MAS-SUP-010", "MAS-SUP-011",
            "MAS-SUP-012", "MAS-SUP-015",
        ),
        platforms=("android",),
    ),
    NiapRequirement(
        "NIA-03",
        "Development/debug builds not shipped as release",
        "debuggable flag, test-only flag, get-task-allow profile and "
        "debug certificates checked.",
        ("MAS-BIN-001", "MAS-BIN-008", "MAS-SUP-002", "MAS-MIS-002"),
    ),
    NiapRequirement(
        "NIA-04",
        "Embedded dependencies identified and versioned",
        "Embedded SDK fingerprints, outdated/EOL versions and OSV advisory "
        "matches reported.",
        ("MAS-SUP-004", "MAS-SUP-007", "MAS-SCA-001", "MAS-SCA-002",
         "MAS-SCA-003"),
    ),
    NiapRequirement(
        "NIA-05",
        "Secret material not embedded in the binary",
        "Hard-coded passwords, API keys, tokens, connection strings and "
        "backend endpoints searched across every text resource.",
        ("MAS-CRED-001", "MAS-CRED-002", "MAS-CRED-003", "MAS-CRED-004",
         "MAS-CRED-005", "MAS-CRED-006", "MAS-CRED-007", "MAS-CRED-008",
         "MAS-CRED-009"),
    ),
    NiapRequirement(
        "NIA-06",
        "Externally reachable attack surface guarded",
        "Exported components/providers, implicit exports, shared user IDs "
        "and browsable deep links checked for permission guards.",
        ("MAS-AUTH-001", "MAS-AUTH-002", "MAS-AUTH-003", "MAS-AUTH-004",
         "MAS-AUTH-005", "MAS-AUTH-006"),
    ),
    NiapRequirement(
        "NIA-07",
        "Untrusted input validated before sensitive sinks",
        "SQL/command/path concatenation, WebView navigation, "
        "deserialization and taint flows from user input.",
        ("MAS-INPUT-001", "MAS-INPUT-002", "MAS-INPUT-003", "MAS-INPUT-004",
         "MAS-INPUT-005", "MAS-INPUT-006", "MAS-INPUT-007", "MAS-INPUT-008"),
    ),
    NiapRequirement(
        "NIA-08",
        "Transport confidentiality enforced",
        "Cleartext policy, user trust anchors, TLS validation, pinning "
        "and cleartext endpoints checked.",
        ("MAS-NET-001", "MAS-NET-002", "MAS-NET-003", "MAS-NET-004",
         "MAS-NET-005", "MAS-NET-006", "MAS-NET-007", "MAS-NET-010",
         "MAS-NET-011"),
    ),
    NiapRequirement(
        "NIA-09",
        "Data at rest confined to the app sandbox",
        "World-readable preferences, external storage writes, plaintext "
        "databases, non-Keychain credential storage and backup/restore "
        "exposure checked.",
        ("MAS-STO-001", "MAS-STO-002", "MAS-STO-005", "MAS-STO-007",
         "MAS-STO-010", "MAS-MIS-001", "MAS-MIS-006"),
    ),
    NiapRequirement(
        "NIA-10",
        "Cryptographic primitives current",
        "Deprecated hashes (MD5/SHA-1), broken ciphers, ECB mode, "
        "implicit modes, static IVs, missing MAC and weak PRNGs checked.",
        ("MAS-CRY-001", "MAS-CRY-002", "MAS-CRY-003", "MAS-CRY-004",
         "MAS-CRY-005", "MAS-CRY-006", "MAS-CRY-007", "MAS-CRY-008",
         "MAS-CRY-009"),
    ),
    NiapRequirement(
        "NIA-11",
        "Binaries hardened and not anti-analysis-tripped",
        "PIE, executable stack, RELRO/BIND_NOW, stack canaries, FORTIFY, "
        "missing dependencies, dynamic loading, packers and root "
        "tooling checked.",
        ("MAS-BIN-002", "MAS-BIN-003", "MAS-BIN-004", "MAS-BIN-005",
         "MAS-BIN-011", "MAS-BIN-013", "MAS-BIN-014", "MAS-BIN-015",
         "MAS-BIN-016", "MAS-BIN-017", "MAS-BIN-018", "MAS-BIN-019",
         "MAS-BIN-020"),
    ),
    NiapRequirement(
        "NIA-12",
        "Privacy surface disclosed",
        "Permission usage vs. declarations, sensitive data in logs, "
        "screen-capture exposure and tracking endpoints enumerated.",
        ("MAS-PRI-001", "MAS-PRI-002", "MAS-PRI-003", "MAS-PRI-005",
         "MAS-PRI-006", "MAS-PRI-007", "MAS-PRI-008", "MAS-NET-008",
         "MAS-NET-009"),
    ),
    NiapRequirement(
        "NIA-13",
        "Platform privilege surface minimized",
        "System/signature-level permission requests, WebView JavaScript "
        "bridges, remote debugging and special-access privileges "
        "reviewed.",
        ("MAS-MIS-003", "MAS-MIS-004", "MAS-MIS-005", "MAS-MIS-007",
         "MAS-MIS-008"),
    ),
)


def _worst(sevs: List[str]) -> str:
    return max(sevs, key=lambda s: SEV_RANK.get(s, 0)) if sevs else "info"


def _signature_rows(result: Any) -> List[Dict[str, str]]:
    """Rows computed directly from the parsed signing facts."""
    rows: List[Dict[str, str]] = []
    try:
        from .overview import build_overview

        sig = (build_overview(result).get("signature") or {})
    except Exception:                               # noqa: BLE001 - best effort
        return rows
    schemes = sig.get("schemes") or {}
    if not schemes:
        return rows

    def entry(name: str) -> Optional[Dict[str, Any]]:
        e = schemes.get(name)
        return e if isinstance(e, dict) else None

    v2, v3, v1 = entry("v2"), entry("v3"), entry("v1")
    if v2:
        if v2.get("verified") is True:
            rows.append({
                "identifier": "NIA-SIG",
                "requirement": "v2 whole-file signature verified",
                "feature": "verifiable protection - signature pass",
                "status": STATUS_PASS,
                "detail": "v2 block verified against the file content digest",
            })
        elif v2.get("verified") is False:
            rows.append({
                "identifier": "NIA-SIG",
                "requirement": "v2 whole-file signature verified",
                "feature": "signature verification FAILED",
                "status": STATUS_ATTN,
                "detail": "the v2 block does not verify - tampering evidence",
            })
        else:
            rows.append({
                "identifier": "NIA-SIG",
                "requirement": "v2 whole-file signature verified",
                "feature": "v2 block present, verification not completed",
                "status": STATUS_UNK,
                "detail": "the block could not be fully verified with the "
                          "stdlib verifier",
            })
    if v3:
        if v3.get("verified") is True:
            rows.append({
                "identifier": "NIA-ROT",
                "requirement": "v3 (rotation-aware) signature verified",
                "feature": "verifiable protection - signature pass",
                "status": STATUS_PASS,
                "detail": "v3 block verified; key rotation metadata parsed",
            })
        elif v3.get("verified") is False:
            rows.append({
                "identifier": "NIA-ROT",
                "requirement": "v3 (rotation-aware) signature verified",
                "feature": "signature verification FAILED",
                "status": STATUS_ATTN,
                "detail": "the v3 block does not verify",
            })
        else:
            rows.append({
                "identifier": "NIA-ROT",
                "requirement": "v3 (rotation-aware) signature verified",
                "feature": "v3 block present, verification not completed",
                "status": STATUS_UNK,
                "detail": "no verified claim without a full verification",
            })
    if v1 and not v2 and not v3:
        rows.append({
            "identifier": "NIA-SIG",
            "requirement": "signature scheme covers the whole file",
            "feature": "v1-only signing (JAR scheme)",
            "status": STATUS_ATTN,
            "detail": "v1 covers entry names/digests only (Janus exposure "
                      "unless v2+ is present)",
        })
    return rows


def niap_matrix(result: Any) -> Dict[str, Any]:
    """Build the assurance matrix for one scan result (never raises).

    Returns ``{"rows": [...], "counts": {...}, "note": ...}``.
    """
    out: Dict[str, Any] = {"note": "NIAP-style assurance subset - not a "
                                   "NIAP certification"}
    try:
        platform = str(getattr(getattr(result, "target", None),
                               "platform", "") or "")
        findings = list(getattr(result, "findings", None) or [])
        by_rule: Dict[str, List[Any]] = {}
        for f in findings:
            rid = str(getattr(f, "rule_id", "") or "")
            if rid:
                by_rule.setdefault(rid, []).append(f)

        rows: List[Dict[str, str]] = []
        for req in REQUIREMENTS:
            hits = [f for rid in req.rules for f in by_rule.get(rid, ())]
            if not platform:
                rows.append({
                    "identifier": req.ident,
                    "requirement": req.requirement,
                    "feature": "",
                    "status": STATUS_UNK,
                    "detail": "target platform unknown",
                })
            elif req.platforms and platform not in req.platforms:
                rows.append({
                    "identifier": req.ident,
                    "requirement": req.requirement,
                    "feature": "",
                    "status": STATUS_NA,
                    "detail": f"checks map to {req.platforms} targets",
                })
            elif hits:
                sevs = [str(getattr(getattr(f, "severity", None), "value",
                                    getattr(f, "severity", "info")))
                        for f in hits]
                rules = sorted({str(f.rule_id) for f in hits})
                rows.append({
                    "identifier": req.ident,
                    "requirement": req.requirement,
                    "feature": f"attention: {len(hits)} finding(s)",
                    "status": STATUS_ATTN,
                    "detail": f"worst severity {_worst(sevs)}; rules: "
                              + ", ".join(rules[:6]),
                })
            else:
                rows.append({
                    "identifier": req.ident,
                    "requirement": req.requirement,
                    "feature": "mapped checks ran, no violations detected",
                    "status": STATUS_PASS,
                    "detail": f"covers {len(req.rules)} rule checks "
                              f"({', '.join(req.rules[:4])}...)",
                })
        rows.extend(_signature_rows(result))

        counts: Dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        out["rows"] = rows
        out["counts"] = counts
    except Exception:                               # noqa: BLE001 - never raise
        return out
    return out

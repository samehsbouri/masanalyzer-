"""Assurance tiers - how was this finding established?

Every masanalyzer finding is graded by its *verification method*, so a
reviewer instantly knows how much trust to put in it:

``verified``   derived from cryptographic verification or binary structure
               parsing (signature-chain verification, ELF/Mach-O program
               headers, X.509 parsing, OSV advisory joins on parsed
               versions). Reproducible on the same artifact by anyone.
``structural`` parsed configuration facts (manifest flags, network security
               config XML, property lists, ZIP layout, permission tables,
               URL inventory classification).
``heuristic``  pattern match over source/binary text (or lexical taint).
               The evidence line is the review anchor; run-time behaviour
               may differ.

MobSF-style scanners report every finding flat. masanalyzer does not:
the tier travels with the finding into every report format, which makes
the triage queue honest - "verified" findings can gate a release,
"heuristic" ones open a review task.
"""

from __future__ import annotations

from typing import Iterable

VERIFIED = "verified"
STRUCTURAL = "structural"
HEURISTIC = "heuristic"

#: rule-id -> assurance tier. Rules not listed default to ``heuristic``.
_RULE_ASSURANCE = {
    # -- verified: cryptographic verification / binary header parsing --------
    "MAS-SUP-008": VERIFIED,   # v1 PKCS#7 -> .SF -> manifest chain
    "MAS-SUP-010": VERIFIED,   # v2 whole-file digest/signature checks
    "MAS-SUP-011": VERIFIED,   # v3 rotation-aware checks
    "MAS-SUP-012": VERIFIED,   # .SF banner bytes
    "MAS-SUP-013": VERIFIED,   # X.509 validity window parse
    "MAS-SUP-014": VERIFIED,   # SPKI modulus parse
    "MAS-SUP-015": VERIFIED,   # .idsig tree/signer cross-check
    "MAS-BIN-002": VERIFIED,   # ELF PT_GNU_STACK / ET_EXEC parse
    "MAS-BIN-003": VERIFIED,
    "MAS-BIN-004": VERIFIED,   # Mach-O MH_PIE parse
    "MAS-BIN-005": VERIFIED,
    "MAS-BIN-007": VERIFIED,   # symbol table parse
    "MAS-BIN-011": VERIFIED,   # PT_GNU_RELRO / DT_BIND_NOW / DT_TEXTREL
    "MAS-BIN-012": VERIFIED,   # iOS CodeDirectory page hashes
    "MAS-BIN-013": VERIFIED,   # dynamic-import byte scan
    "MAS-BIN-014": VERIFIED,
    "MAS-BIN-015": VERIFIED,   # DT_NEEDED graph resolution
    "MAS-BIN-016": VERIFIED,
    "MAS-SCA-001": VERIFIED,   # version parsed from artifact, band check
    "MAS-SCA-002": VERIFIED,
    "MAS-SCA-003": VERIFIED,   # OSV advisory join on parsed versions
    # -- structural: parsed config / structure facts -------------------------
    "MAS-SUP-001": STRUCTURAL,  # signature-scheme structure
    "MAS-SUP-002": STRUCTURAL,
    "MAS-SUP-003": STRUCTURAL,
    "MAS-SUP-005": STRUCTURAL,  # targetSdk from AXML
    "MAS-SUP-007": STRUCTURAL,
    "MAS-SUP-009": STRUCTURAL,  # ZIP layout offsets
    "MAS-BIN-001": STRUCTURAL,  # AXML debuggable flag
    "MAS-BIN-006": STRUCTURAL,  # dex class-name statistics
    "MAS-BIN-008": STRUCTURAL,  # provisioning plist parse
    "MAS-BIN-010": STRUCTURAL,  # LC_CODE_SIGNATURE presence
    "MAS-BIN-017": STRUCTURAL,  # packer signature over file names/pool
    "MAS-AUTH-001": STRUCTURAL,
    "MAS-AUTH-002": STRUCTURAL,
    "MAS-AUTH-003": STRUCTURAL,
    "MAS-AUTH-004": STRUCTURAL,
    "MAS-AUTH-005": STRUCTURAL,
    "MAS-AUTH-006": STRUCTURAL,
    "MAS-NET-001": STRUCTURAL,
    "MAS-NET-002": STRUCTURAL,
    "MAS-NET-003": STRUCTURAL,
    "MAS-NET-004": STRUCTURAL,
    "MAS-NET-007": STRUCTURAL,
    "MAS-NET-008": STRUCTURAL,  # inventory classification (parsed hosts)
    "MAS-NET-009": STRUCTURAL,
    "MAS-MIS-001": STRUCTURAL,
    "MAS-MIS-002": STRUCTURAL,
    "MAS-MIS-003": STRUCTURAL,
    "MAS-MIS-006": STRUCTURAL,
    "MAS-MIS-007": STRUCTURAL,
    "MAS-CRED-008": STRUCTURAL,  # plist key/value walk
    "MAS-STO-002": STRUCTURAL,
}


def tier_for(rule_id: str) -> str:
    """Assurance tier for one rule id (default: heuristic)."""
    return _RULE_ASSURANCE.get(rule_id, HEURISTIC)


def annotate(findings: Iterable) -> int:
    """Stamp the tier onto each finding; returns the number stamped."""
    n = 0
    for f in findings:
        f.assurance = tier_for(f.rule_id)
        n += 1
    return n

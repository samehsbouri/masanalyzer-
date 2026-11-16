"""M10 - Insufficient Cryptography.

Weak / deprecated algorithms, ECB modes, default ciphers, predictable
randomness for security values, static IVs and missing authenticated
encryption — across Java/Kotlin/ObjC/Swift and compiled strings.
"""

from __future__ import annotations

import re
from typing import Iterable, List

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, iter_pool, make_rule, matches_in_text

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
CRITICAL = Severity.CRITICAL

R_MD5_SHA1 = make_rule(
    "MAS-CRY-001",
    "M10",
    "Deprecated hash function (MD5 / SHA-1)",
    "MD5 and SHA-1 are collision-broken; they must not be used for security "
    "decisions (signature, token fingerprint, password digest).",
    MEDIUM,
    "Use SHA-256 or better (or a password KDF like Argon2/PBKDF2 for "
    "verifier material).",
    cwe="CWE-327",
    confidence=Confidence.HIGH,
    cvss=5.5,
)

R_DES_RC4 = make_rule(
    "MAS-CRY-002",
    "M10",
    "Broken or obsolete cipher family",
    "DES/3DES/RC4/Blowfish are deprecated or cryptographically broken; "
    "ciphertext produced today is forgeable/readable with budgeted attacks.",
    HIGH,
    "Move to AES-GCM (or ChaCha20-Poly1305) with 128/256-bit keys.",
    cwe="CWE-327",
    confidence=Confidence.HIGH,
    cvss=7.5,
)

R_ECB = make_rule(
    "MAS-CRY-003",
    "M10",
    "Block cipher used in ECB mode",
    "ECB maps identical plaintext blocks to identical ciphertext blocks and "
    "leaks structure (ECB-penguin); no semantic security.",
    HIGH,
    "Use an authenticated mode (AES-GCM) or CBC with random IV + MAC.",
    cwe="CWE-327",
    confidence=Confidence.HIGH,
    cvss=7.5,
)

R_DEFAULT_CIPHER = make_rule(
    "MAS-CRY-004",
    "M10",
    "Cipher instance without explicit mode",
    'Cipher.getInstance("AES") (or equivalent) selects provider defaults '
    "that can silently degrade to ECB/PKCS5; specify algorithm+mode+padding.",
    HIGH,
    'Write the full transformation, e.g. "AES/GCM/NoPadding".',
    cwe="CWE-327",
    confidence=Confidence.HIGH,
    cvss=7.2,
)

R_PRNG_WEAK = make_rule(
    "MAS-CRY-005",
    "M10",
    "Non-CSPRNG used for security values",
    "java.util.Random / Math.random is seeded (or predictable) and used for "
    "IVs, tokens or nonces rather than SecureRandom.",
    HIGH,
    "Use a cryptographically secure RNG (SecureRandom, SecRandomCopyBytes).",
    cwe="CWE-338",
    confidence=Confidence.HIGH,
    cvss=7.4,
)

R_PRNG_TIME_SEEDED = make_rule(
    "MAS-CRY-006",
    "M10",
    "SecureRandom seeded with predictable entropy",
    "setSeed(<time-derivable value>) replaces the OS entropy pool with a "
    "guessable seed, defeating the generator.",
    HIGH,
    "Remove the explicit seed and rely on the OS entropy source.",
    cwe="CWE-338",
    confidence=Confidence.HIGH,
    cvss=7.2,
)

R_STATIC_IV = make_rule(
    "MAS-CRY-007",
    "M10",
    "Static IV constant shipped with the app",
    "IV bytes appear as literals in the code/pool; fixed IVs with CBC/CTR "
    "leak plaintext structure and enable replay.",
    MEDIUM,
    "Generate a fresh IV per message and prepend it to the ciphertext.",
    cwe="CWE-329",
    confidence=Confidence.MEDIUM,
    cvss=6.5,
)

R_NO_AUTH_ENC = make_rule(
    "MAS-CRY-008",
    "M10",
    "Encryption without message authentication",
    "CBC/PKCS5 usage without a MAC (or AES-GCM not used) allows ciphertext "
    "tampering and padding-oracle style attacks when feedback is available.",
    MEDIUM,
    "Encrypt-then-MAC or move to an AEAD mode.",
    cwe="CWE-327",
    confidence=Confidence.MEDIUM,
)

R_RSA_NO_OAEP = make_rule(
    "MAS-CRY-009",
    "M10",
    "RSA used without OAEP padding",
    'Cipher.getInstance("RSA/.../NoPadding") performs raw RSA: no padding '
    "means deterministic, malleable ciphertext and (for encryption) the "
    "textbook attacks (chosen-ciphertext, common-modulus). RSA must use "
    "OAEP.",
    HIGH,
    'Use "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" (or a hybrid scheme with '
    "AES-GCM for the payload).",
    cwe="CWE-780",
    confidence=Confidence.HIGH,
    cvss=7.4,
)

_RX_MD5_SHA1 = re.compile(r"(?<![\w.])((?:java\.security\.MessageDigest\s*\.\s*getInstance\s*\(\s*[\"\'](MD5|SHA-?1)[\"\'])|(?:CC_?(?:MD5|SHA1))|(?:[\"\'](?:MD5|SHA-1|SHA1)[\"\']))", re.I)
_RX_DES_RC4 = re.compile(r"(?<![\w.])((?:DES|DESede|TripleDES|RC4|Blowfish)(?:/\w+/\w+|[\"\']/?)|kCCAlgorithmDES|kCCAlgorithmBlowfish|kCCAlgorithmRC4)", re.I)
_RX_ECB = re.compile(r"(?<![\w.])((?:\"AES/ECB/[^\"]+\"|\"DES/ECB/[^\"]+\"|kCCOptionECBMode))", re.I)
_RX_DEFAULT_CIPHER = re.compile(r"Cipher\.getInstance\s*\(\s*[\"\'](AES|DES|DESede|Blowfish|RSA)[\"\']", re.I)
_RX_PRNG = re.compile(r"new\s+Random\s*\([^\n]{0,80}\)\s*\.?next(?:Int|Bytes)?[^\n]{0,60}|Math\.random\s*\(\s*\)")
_RX_SEED_TIME = re.compile(r"setSeed\s*\([^)]*(?:System\.currentTimeMillis|Date|currentTime)[^)]*\)", re.I)
_RX_STATIC_IV = re.compile(r"(?:IvParameterSpec\s*\(\s*[\"\'][0-9A-Fa-f]{16,}[\"\']|\bbyte\[\]\s*iv\s*=\s*\{[^}]+\})", re.I)
_RX_CBC_NO_MAC = re.compile(r"[\"\'](?:AES|DES)/CBC/(?:PKCS5|PKCS7|No)[A-Za-z]*[\"\']", re.I)
_RX_RSA_NO_OAEP = re.compile(r"Cipher\.getInstance\s*\(\s*[\"\']RSA/[^\"]{0,48}NoPadding", re.I)


def _hit(finding_rule, sf, lineno, text):
    return finding_rule.finding(
        file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
    )


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []

    # source files -------------------------------------------------------------
    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        if _RX_MD5_SHA1.search(text):
            out.append(_hit(R_MD5_SHA1, sf, lineno, text))
        if _RX_DES_RC4.search(text):
            out.append(_hit(R_DES_RC4, sf, lineno, text))
        if _RX_ECB.search(text):
            out.append(_hit(R_ECB, sf, lineno, text))
        if _RX_DEFAULT_CIPHER.search(text):
            out.append(_hit(R_DEFAULT_CIPHER, sf, lineno, text))
        if _RX_PRNG.search(text):
            out.append(_hit(R_PRNG_WEAK, sf, lineno, text))
        if _RX_SEED_TIME.search(text):
            out.append(_hit(R_PRNG_TIME_SEEDED, sf, lineno, text))
        if _RX_STATIC_IV.search(text):
            out.append(_hit(R_STATIC_IV, sf, lineno, text))
            continue
        if _RX_CBC_NO_MAC.search(text):
            out.append(_hit(R_NO_AUTH_ENC, sf, lineno, text))
        if _RX_RSA_NO_OAEP.search(text):
            out.append(_hit(R_RSA_NO_OAEP, sf, lineno, text))

    # compiled binary strings ---------------------------------------------------
    for rel, value in iter_pool(target, min_len=4):
        if _RX_MD5_SHA1.search(value):
            out.append(R_MD5_SHA1.finding(file=rel, symbol=value[:80]))
        if _RX_DES_RC4.search(value):
            out.append(R_DES_RC4.finding(file=rel, symbol=value[:80]))
        if _RX_ECB.search(value):
            out.append(R_ECB.finding(file=rel, symbol=value[:80]))
        if _RX_STATIC_IV.search(value):
            out.append(R_STATIC_IV.finding(file=rel, symbol=value[:80]))
        if _RX_RSA_NO_OAEP.search(value):
            out.append(
                R_RSA_NO_OAEP.finding(
                    file=rel, symbol=value[:80],
                    note="cipher transformation in the compiled string pool",
                )
            )
    return out

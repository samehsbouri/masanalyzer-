"""Real v1 (JAR) APK signature chain verification - apksig equivalent.

Unlike plain detection ("is there an *.SF/*.RSA pair?"), this module
validates the whole cryptographic chain the way Android's PackageManager
does before it will install a v1-signed package:

1. **PKCS#7** - the ``META-INF/*.RSA`` blob must be a well-formed
   ``SignedData`` whose signature cryptographically verifies over the
   ``META-INF/*.SF`` bytes (RSA PKCS#1 v1.5 or ECDSA P-256; detached
   jarsigner-style signedAttrs also supported).
2. **SF -> manifest** - the ``SHA-256-Digest-Manifest`` (or SHA-1) main
   attribute of the .SF must equal the digest of ``MANIFEST.MF``; per-entry
   ``x-Digest`` attributes inside the .SF are validated too when present.
3. **manifest -> files** - every entry named in the manifest must still
   hash to the recorded ``SHA-256-Digest`` (``SHA1-Digest`` tolerated).
4. **coverage** - every zip entry that is not itself signature material
   must be covered by the manifest directory.

A tampered ``classes.dex`` therefore fails at step 3; a re-signed but
content-mismatched PKCS#7 fails at step 1; a manifest that "forgets" an
injected file fails at step 4.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pkcs7 import verify_pkcs7_signature

#: attributes that digest a whole per-entry payload inside MANIFEST.MF
_DIGEST_ATTRS = {
    "sha-256-digest": "sha256",
    "sha-1-digest": "sha1",
    "sha1-digest": "sha1",
    "md5-digest": "md5",   # weak; validated but flagged by m07 elsewhere
}

#: whole-manifest digest attribute names in the .SF main section
_SF_MANIFEST_DIGESTS = {
    "sha-256-digest-manifest": "sha256",
    "x-sha256-part-digest": None,   # referenced but not used here
    "sha1-digest-manifest": "sha1",
    "sha-1-digest-manifest": "sha1",
}

#: files that belong to the signature itself (exempt from coverage checks)
_SIG_FILES_SUFFIX = (".sf", ".rsa", ".dsa", ".ec", ".mf")


class ManifestError(ValueError):
    """Raised when a JAR manifest/SF cannot be parsed."""


# ---------------------------------------------------------------------------
# JAR manifest parsing (simple, CRLF tolerant, line continuations supported)
# ---------------------------------------------------------------------------
def _parse_attrs(text: str) -> List[Dict[str, str]]:
    """Split a manifest into per-entry attribute dictionaries."""
    # normalise line endings and apply continuation lines (leading space)
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    logical: List[str] = []
    for line in raw:
        if line.startswith(" ") and logical:
            logical[-1] += line[1:]
        else:
            logical.append(line)

    sections: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for line in logical:
        stripped = line.strip()
        if not stripped:
            if current:
                sections.append(current)
                current = {}
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        # JAR attribute names are case-insensitive
        current[key.strip().lower()] = value.strip()
    if current:
        sections.append(current)
    return sections


@dataclass
class V1Verification:
    """Outcome of the full v1 signature chain check."""

    verified: bool
    reasons: List[str] = field(default_factory=list)
    covered_entries: int = 0        # files whose digests were re-checked
    signer_cn: Optional[str] = None
    digest_algorithm: Optional[str] = None

    def describe(self) -> str:
        if self.verified:
            base = (
                f"v1 signature chain verified: {self.covered_entries} "
                f"entry digests + .SF + PKCS#7 all valid"
            )
            if self.signer_cn:
                base += f" (cn: {self.signer_cn})"
            return base
        return "v1 signature verification failed: " + "; ".join(self.reasons[:3])


def _digest_attr_pairs(sections: List[Dict[str, str]]) -> List[Tuple[str, str, str]]:
    """(name, algo, expected_b64) for every per-entry digest attribute."""
    out: List[Tuple[str, str, str]] = []
    for section in sections:
        name = section.get("name")
        if not name:
            continue
        for key, algo in _DIGEST_ATTRS.items():
            if key in section:
                out.append((name, algo, section[key]))
    return out


def _digest_of(data: bytes, algo: str) -> bytes:
    try:
        return hashlib.new(algo, data).digest()
    except ValueError:              # pragma: no cover - unknown algo name
        raise ManifestError(f"unsupported digest algorithm {algo!r}")


def _b64_decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------
def verify_v1_signature(
    zf: zipfile.ZipFile,
    manifest_name: str = "META-INF/MANIFEST.MF",
) -> Tuple[Optional[V1Verification], str]:
    """Run the full v1 verification chain against the open APK.

    Returns ``(result, sf_name)``; ``result`` is ``None`` when the APK has
    no v1 signature material at all.
    """
    # locate the .SF / signature block -------------------------------------
    sf_name = sig_name = None
    for entry in zf.namelist():
        low = entry.lower()
        if not low.startswith("meta-inf/"):
            continue
        if low.endswith(".sf"):
            sf_name = sf_name or entry
        elif low.endswith((".rsa", ".dsa", ".ec")):
            sig_name = sig_name or entry
    if not sf_name or not sig_name:
        return None, ""

    require: List[str] = []      # accumulated failure reasons
    covered = 0
    digest_algo: Optional[str] = None

    # 1. read MANIFEST.MF ----------------------------------------------------
    try:
        manifest_bytes = zf.read(manifest_name)
    except (KeyError, zipfile.BadZipFile, OSError, binascii.Error) as exc:
        return V1Verification(False, [f"unreadable manifest: {exc}"]), sf_name

    digest_algo = "sha256"

    # 2. read binary signature + verify PKCS#7 over the .SF bytes ------------
    try:
        sf_bytes = zf.read(sf_name)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        return V1Verification(False, [f"unreadable {sf_name}: {exc}"]), sf_name

    try:
        sig_bytes = zf.read(sig_name)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        return V1Verification(False, [f"unreadable {sig_name}: {exc}"]), sf_name

    ok, crypto_reasons = verify_pkcs7_signature(sig_bytes, sf_bytes)
    if not ok:
        require.extend(crypto_reasons)

    # 3. SF main section digests the manifest --------------------------------
    try:
        sf_sections = _parse_attrs(sf_bytes.decode("utf-8", "replace"))
    except Exception as exc:                          # pragma: no cover
        return V1Verification(False, [f"unparsable .SF: {exc}"]), sf_name

    manifest_digest_ok = False
    main_sf = sf_sections[0] if sf_sections else {}
    for key, algo in _SF_MANIFEST_DIGESTS.items():
        if algo is None or key not in main_sf:
            continue
        digest_algo = algo
        try:
            expected = _b64_decode(main_sf[key])
            if _digest_of(manifest_bytes, algo) == expected:
                manifest_digest_ok = True
        except (binascii.Error, ManifestError) as exc:
            require.append(f".SF {key}: invalid base64 ({exc})")
    if not manifest_digest_ok:
        require.append(
            ".SF digest over the manifest does not match "
            f"(expected strong attribute of {[k for k in _SF_MANIFEST_DIGESTS if k in main_sf] or 'none'})"
        )

    # 4. per-entry .SF digests ( presence varies by signer ) -----------------
    sf_entry_digests: Dict[str, Tuple[str, str]] = {}
    for name, algo, expected_b64 in _digest_attr_pairs(sf_sections[1:]):
        sf_entry_digests[name] = (algo, expected_b64)

    # 5. manifest per-entry digests vs the actual payload --------------------
    try:
        sections = _parse_attrs(manifest_bytes.decode("utf-8", "replace"))
    except Exception as exc:                          # pragma: no cover
        return V1Verification(False, [f"unparsable manifest: {exc}"]), sf_name

    covered_names: set = set()
    for name, algo, expected_b64 in _digest_attr_pairs(sections):
        covered_names.add(name)
        covered += 1
        try:
            payload = zf.read(name)
        except (KeyError, zipfile.BadZipFile, OSError):
            require.append(f"manifest entry missing in zip: {name}")
            continue
        try:
            expected = _b64_decode(expected_b64)
        except binascii.Error:
            require.append(f"manifest {name}: invalid base64 digest")
            continue
        if _digest_of(payload, algo) != expected:
            require.append(
                f"entry digest mismatch: {name} ({algo}) - file was "
                f"modified after signing"
            )
        # if the .SF also carries a per-entry digest, validate it matches
        sf_pair = sf_entry_digests.get(name)
        if sf_pair is not None:
            sf_algo, sf_b64 = sf_pair
            if sf_algo == algo:
                try:
                    if _b64_decode(sf_b64) != _digest_of(payload, sf_algo):
                        require.append(f".SF entry digest mismatch: {name}")
                except binascii.Error:
                    pass

    # 6. coverage: every non-signature entry must be manifested ---------------
    signature_self = {manifest_name.lower(), sf_name.lower(), sig_name.lower()}
    extras: List[str] = []
    for entry in zf.namelist():
        low = entry.lower()
        if low in signature_self:
            continue
        if low.startswith("meta-inf/") and low.endswith(_SIG_FILES_SUFFIX):
            continue
        if low.endswith("/"):                    # directory entries
            continue
        if entry not in covered_names:
            extras.append(entry)
    if extras:
        require.append(
            f"zip entries not covered by the signed manifest: "
            f"{', '.join(sorted(extras)[:4])}"
            f"{' (+more)' if len(extras) > 4 else ''}"
        )

    verified = not require
    return V1Verification(
        verified=verified,
        reasons=require,
        covered_entries=covered,
        digest_algorithm=digest_algo,
    ), sf_name

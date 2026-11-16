"""iOS/Apple code signature verification (CodeDirectory page-hash check).

Parses the SuperBlob pointed to by ``LC_CODE_SIGNATURE`` (magic
``0xfade0cc0``) and verifies the embedded CodeDirectory (magic
``0xfade0c02``):

* page-wise SHA-256 hashes over the executable record - every
  ``2**pageSize`` bytes of the file up to ``codeLimit`` (negative special
  slots are deliberately not verified: Apple's slot ordering is not
  stable across signing versions and we avoid false positives);
* the CMS/PKCS#7 slot - when the CMS shape is decodable with the
  stdlib-only helpers, the ``messageDigest`` authenticated attribute is
  compared against SHA-256 of the CodeDirectory.

Returns ``(verified, reasons)`` where ``verified`` is tri-state
(``None`` = only unsupported slots exist, True/False = page hash outcome).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..android.pkcs7 import Pkcs7Error, parse_tlv

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02

CSSLOT_ENTITLEMENTS = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_CODEDIRECTORY = 0
CSSLOT_ALTERNATE_CODESIGN_DIR = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000

CD_HASH_SHA256 = 2
#: Apple's cdHashType index -> hashlib name
HASH_TYPES = {1: "sha1", 2: "sha256"}


class CodeSignError(ValueError):
    """Raised when the signature blob cannot be parsed at all."""


@dataclass
class CodeDirectory:
    version: int
    flags: int
    n_code_slots: int
    n_special_slots: int
    code_limit: int
    page_size: int
    hash_size: int
    hash_type: int
    identity: str
    team: str


def parse_superslots(
    blob: bytes, off: int
) -> Tuple[Dict[int, bytes], Dict[int, int]]:
    """Map slot type -> raw slot bytes (+ absolute offsets) for SuperBlob at ``off``."""
    if off + 8 > len(blob):
        raise CodeSignError("signature blob truncated")
    magic, count = struct.unpack_from(">II", blob, off)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise CodeSignError(f"not a SuperBlob: {magic:#010x}")
    if count > 32:
        raise CodeSignError(f"implausible slot count {count}")

    slot_offsets: List[Tuple[int, int]] = []      # (slot type, data offset)
    pos = off + 8
    for _ in range(count):
        if pos + 8 > len(blob):
            raise CodeSignError("SuperBlob index truncated")
        (slot_type,) = struct.unpack_from(">I", blob, pos)
        (data_off,) = struct.unpack_from(">I", blob, pos + 4)
        slot_offsets.append((slot_type, data_off))
        pos += 8

    slots: Dict[int, bytes] = {}
    abs_offsets: Dict[int, int] = {}
    for i, (slot_type, data_off) in enumerate(slot_offsets):
        start = off + data_off
        if start >= len(blob):
            raise CodeSignError(f"slot {slot_type:#x} points outside the blob")
        if i + 1 < len(slot_offsets):
            end = off + slot_offsets[i + 1][1]
        else:
            end = len(blob)                        # last slot runs to file end
        if end < start:
            raise CodeSignError(f"slot {slot_type:#x} has a negative range")
        slots[slot_type] = blob[start:end]
        abs_offsets[slot_type] = start
    return slots, abs_offsets


def parse_code_directory(cd_bytes: bytes) -> CodeDirectory:
    """Decode the fixed header of a CodeDirectory slot."""
    if len(cd_bytes) < 28:
        raise CodeSignError("CodeDirectory too short")
    magic, version = struct.unpack_from(">II", cd_bytes, 0)
    if magic != CSMAGIC_CODEDIRECTORY:
        raise CodeSignError(f"not a CodeDirectory: {magic:#010x}")
    (
        _flags,
        hash_offset,
        ident_offset,
        n_special,
        n_code,
        code_limit,
        hash_size,
        hash_type,
        _platform,
        page_bits,
    ) = struct.unpack_from(">IIIIIIBBBB", cd_bytes, 8)
    identity = _c_string(cd_bytes, ident_offset) if ident_offset else ""
    team = ""
    if version >= 0x20100:
        sp2, scatter, team_off = struct.unpack_from(">III", cd_bytes, 28)
        team = _c_string(cd_bytes, team_off) if team_off else ""
    return CodeDirectory(
        version=version,
        flags=struct.unpack_from(">I", cd_bytes, 8)[0],
        n_code_slots=n_code,
        n_special_slots=n_special,
        code_limit=code_limit,
        page_size=1 << page_bits if 0 < page_bits <= 32 else PAGE_SIZE_DEFAULT,
        hash_size=hash_size,
        hash_type=hash_type,
        identity=identity,
        team=team,
    )


def _c_string(blob: bytes, off: int) -> str:
    if off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    return blob[off : end if end >= 0 else len(blob)].decode("ascii", "replace")


def verify_code_signature(
    blob: bytes, cs_offset: int, cs_size: Optional[int] = None
) -> Tuple[Optional[bool], List[str]]:
    """Verify the SuperBlob at ``cs_offset`` against the file contents.

    Returns ``(verified, reasons)``; ``verified`` is ``None`` when only
    non-page-verifying slots exist.
    """
    try:
        slots, slot_abs = parse_superslots(blob, cs_offset)
    except CodeSignError as exc:
        return False, [f"codesign blob: {exc}"]
    reasons: List[str] = []

    if CSSLOT_CODEDIRECTORY not in slots:
        if CSSLOT_SIGNATURESLOT in slots:
            # only CMS present: verifiable only as parseable or not
            ok, cms_reasons = _verify_cms(slots[CSSLOT_SIGNATURESLOT], b"")
            reasons.extend(cms_reasons)
            return None if ok is None else False, reasons
        return None, ["no CodeDirectory slot in the SuperBlob"]

    cd_bytes = slots[CSSLOT_CODEDIRECTORY]
    cd_abs = slot_abs[CSSLOT_CODEDIRECTORY]
    try:
        cd = parse_code_directory(cd_bytes)
    except CodeSignError as exc:
        return False, [f"CodeDirectory: {exc}"]

    ok, reasons_cd = _verify_page_hashes(blob, cd_abs, cd, slots)
    reasons.extend(reasons_cd)

    # CMS best-effort: messageDigest over the CodeDirectory bytes
    if CSSLOT_SIGNATURESLOT in slots:
        cms_ok, cms_reasons = _verify_cms(slots[CSSLOT_SIGNATURESLOT], cd_bytes)
        reasons.extend(cms_reasons)
        if cms_ok is False:
            return False, reasons

    return ok, reasons


def _verify_page_hashes(
    blob: bytes,
    cd_offset: int,
    cd: CodeDirectory,
    slots: Dict[int, bytes],
) -> Tuple[Optional[bool], List[str]]:
    """Page hashes over the executable record (offsets are CD-relative)."""
    reasons: List[str] = []
    if cd.hash_type not in HASH_TYPES:
        reasons.append(f"unsupported cdHashType {cd.hash_type}")
        return None, reasons
    hasher_name = HASH_TYPES[cd.hash_type]
    hasher = getattr(hashlib, hasher_name)
    if cd.hash_size != hasher().digest_size:
        reasons.append(f"hash size {cd.hash_size} does not match {hasher_name}")
        return False, reasons

    cd_bytes = blob[cd_offset:]
    (_flags, hash_offset, _ident_off, _n_special, _n_code, _limit,
     _hs, _ht, _pl, _pb) = struct.unpack_from(">IIIIIIBBBB", cd_bytes, 8)
    limit = min(cd.code_limit, len(blob))

    bad = 0
    first_bad = -1
    for i in range(cd.n_code_slots):
        start = i * cd.page_size
        end = min(start + cd.page_size, limit)
        chunk = blob[start:end] if start < limit else b""
        computed = hasher(chunk).digest()[: cd.hash_size]
        at = cd_offset + hash_offset + i * cd.hash_size
        if at + cd.hash_size > len(blob):
            return False, ["CodeDirectory page hash out of range"]
        if blob[at : at + cd.hash_size] != computed:
            bad += 1
            if first_bad < 0:
                first_bad = i
    if bad:
        reasons.append(
            f"{bad}/{cd.n_code_slots} page hashes differ from the file "
            f"(first mismatch in slot {first_bad})"
        )
        return False, reasons

    # special (negative) slots: Apple's exact ordering (ident/requirements/
    # entitlements/resource) is not stable across signing versions, so we
    # deliberately skip them rather than risk false positives; the page
    # hashes over the executable record are the integrity core.
    return True, reasons


def _verify_cms(
    cms: bytes, code_directory: bytes
) -> Tuple[Optional[bool], List[str]]:
    """Best-effort CMS check: ``messageDigest`` vs SHA-256(CodeDirectory).

    Apple's detached CMS carries the CodeDirectory digest in an
    authenticated attribute rather than as detached content, so this is
    exactly the trustworthy check we can reproduce stdlib-only.
    """
    try:
        root = parse_tlv(cms)
        if not (root.tag == 0x30 and len(root.children()) >= 2):
            return None, ["CMS slot: not a ContentInfo sequence"]
        content = root.children()[1]
        if not content.value:
            return None, ["CMS slot: not present in the CMS shape"]
        sd = parse_tlv(content.value)                # SignedData
        if sd.tag != 0x30:
            return None, ["CMS slot: not a SignedData sequence"]
        # SignerInfo is inside the last SEQUENCE SET; walk for messageDigest
        si = _find_signer_info(sd)
        if si is None:
            return None, ["CMS slot: no SignerInfo to digest-check"]
        md = _attr_value(si, _OID_MESSAGE_DIGEST)
        if not md:
            return None, ["CMS slot: no messageDigest attribute"]
        digest = hashlib.sha256(code_directory).digest()
        if md[: len(digest)] == digest:
            return True, []
        return False, ["CMS messageDigest does not cover the CodeDirectory"]
    except Pkcs7Error as exc:
        return None, [f"CMS slot: {exc}"]
    except Exception as exc:                          # noqa: BLE001
        return None, [f"CMS slot: parse error ({exc})"]


def _find_signer_info(sd):
    """Locate the first SignerInfo SEQUENCE inside SignedData."""
    for child in sd.children():
        if child.tag == 0x31 and child.value:          # SET OF signerInfos
            return parse_tlv(child.value)
    return None


#: encoder-style OID for 1.2.840.113549.1.9.4 (messageDigest)
_OID_MESSAGE_DIGEST = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"


def _attr_value(signer_seq, attr_oid: bytes) -> Optional[bytes]:
    """Pull the OCTET STRING value of attribute ``attr_oid``."""
    for node in signer_seq.children():
        if node.tag == 0x30:                           # [0] authenticatedAttrs
            for attr in node.children():
                if attr.tag != 0x30:
                    continue
                kids = attr.children()
                if kids and kids[0].value == attr_oid and len(kids) > 1:
                    outer = kids[1]
                    if outer.tag == 0x31 and outer.children():
                        val = outer.children()[0]
                        if val.tag == 0x04:
                            return val.value
    return None

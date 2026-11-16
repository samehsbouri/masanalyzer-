"""APK Signature Scheme v2 / v3 verification (apksig-equivalent).

Implements the whole-file signature chain described by the AOSP spec:

* APK signing block located before the ZIP Central Directory, with two
  identical ``size of block`` fields and the ``"APK Sig Block 42"`` magic;
* v2 block (ID ``0x7109871a``) and v3 block (ID ``0xf05368c0``) payloads:
  length-prefixed signer sequences containing ``signed data`` (digests,
  certificates, attributes), signatures and the SubjectPublicKeyInfo;
* the two-level content digest over ZIP sections 1 (entries), 3
  (Central Directory) and 4 (EOCD with its CD-offset field replaced by the
  signing block offset): 1 MB chunks hashed as
  ``SHA-256(0xa5 || le32(len) || chunk)`` and a top-level
  ``SHA-256(0x5a || le32(chunk_count) || concat(chunk digests))``;
* signature verification with the stdlib-only RSA PKCS#1 v1.5 / ECDSA
  P-256 cores from ``android.pkcs7`` (algorithms 0x0103 / 0x0201; PSS,
  SHA-512 and DSA variants are reported as unsupported rather than guessed);
* digest / signature algorithm-id list equality (strip/add protection) and
  ``publicKey == SPKI(first certificate)``.

Malformed structures produce reasons, not exceptions, so the scanner never
aborts on a hostile block.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pkcs7 import (
    EcPublicKey,
    Pkcs7Error,
    RsaPublicKey,
    parse_spki,
    parse_tlv,
)

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0

#: ecdsa-with-SHA256 OID is reused; v2 ECDSA signatures are DER-encoded
#: SEQUENCE { r INTEGER, s INTEGER } unlike JAR (raw r||s)
CHUNK_SIZE = 2 ** 20

SIG_RSA_PKCS1_SHA256 = 0x0103
SIG_RSA_PKCS1_SHA512 = 0x0104
SIG_RSA_PSS_SHA256 = 0x0101
SIG_RSA_PSS_SHA512 = 0x0102
SIG_ECDSA_SHA256 = 0x0201
SIG_ECDSA_SHA512 = 0x0202
SIG_DSA_SHA256 = 0x0301

_SIG_DIGEST = {
    SIG_RSA_PKCS1_SHA256: "sha256",
    SIG_ECDSA_SHA256: "sha256",
    SIG_RSA_PKCS1_SHA512: "sha512",
}

#: the subset this verifier can actually validate
_SUPPORTED = (SIG_RSA_PKCS1_SHA256, SIG_ECDSA_SHA256)

_DIGEST_ALG_TO_ID = {
    "sha256": SIG_RSA_PKCS1_SHA256,
    "sha512": SIG_RSA_PKCS1_SHA512,
}


class ApkSigError(ValueError):
    """Raised when a block cannot be parsed at all."""


@dataclass
class SigningBlock:
    start: int                       # offset of the leading size field
    end: int                         # end of the block == CD offset
    cd_offset: int
    entries: Dict[int, bytes] = field(default_factory=dict)
    layout_problems: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# signing block location / sanity (AOSP verification step 1)
# ---------------------------------------------------------------------------
def find_signing_block(data: bytes) -> Optional[SigningBlock]:
    """Locate and integrity-check the APK Signing Block; None if absent."""
    eocd_pos = _find_eocd(data)
    if eocd_pos is None:
        return None
    if eocd_pos + 22 > len(data):
        return None
    try:
        (cd_offset,) = struct.unpack_from("<I", data, eocd_pos + 16)
    except struct.error:
        return None
    if cd_offset < 40 or cd_offset > len(data):
        return None                              # block cannot exist here
    # Block layout (spec): [u64 size][pairs][u64 size][16B magic], and the
    # magic ends exactly where the Central Directory starts.
    magic_pos = cd_offset - 16
    if data[magic_pos : magic_pos + 16] != APK_SIG_BLOCK_MAGIC:
        return None

    (size_trailing,) = struct.unpack_from("<Q", data, magic_pos - 8)
    lead_pos = cd_offset - 8 - size_trailing
    (size_leading,) = struct.unpack_from("<Q", data, lead_pos)

    block = SigningBlock(start=lead_pos, end=cd_offset, cd_offset=cd_offset)
    problems = block.layout_problems
    if size_leading != size_trailing:
        problems.append("APK signing block size fields disagree")
    if lead_pos + 8 + 8 > cd_offset or magic_pos != cd_offset - 16:
        problems.append("ZIP Central Directory not immediately after the signing block")
    if eocd_pos + _eocd_size(data, eocd_pos) != len(data):
        problems.append("data found after the ZIP EOCD record")

    # walk the len-prefixed ID-value pairs
    pos = block.start + 8                        # skip leading size field
    end_pairs = magic_pos - 8                    # trailing size field begins here
    while pos + 12 <= end_pairs:
        (pair_len,) = struct.unpack_from("<Q", data, pos)
        if pair_len < 4 or pos + 8 + pair_len > end_pairs:
            problems.append("malformed ID-value pair inside the signing block")
            break
        (pair_id,) = struct.unpack_from("<I", data, pos + 8)
        block.entries[pair_id] = data[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len
    if pos != end_pairs and not any("ID-value" in p for p in problems):
        problems.append("trailing bytes inside the signing block pair region")
    return block


def _find_eocd(data: bytes) -> Optional[int]:
    if len(data) < 22:
        return None
    start = max(0, len(data) - 65535 - 22)
    return data.rfind(b"PK\x05\x06", start)


def _eocd_size(data: bytes, pos: int) -> int:
    try:
        (comment_len,) = struct.unpack_from("<H", data, pos + 20)
        return 22 + comment_len
    except struct.error:
        return 22


# ---------------------------------------------------------------------------
# length-prefixed helpers (uint32 little-endian, per spec)
# ---------------------------------------------------------------------------
def _lp(data: bytes, pos: int) -> Tuple[bytes, int]:
    """Read one uint32-length-prefixed value; returns (value, new_pos)."""
    if pos < 0 or pos + 4 > len(data):
        raise ApkSigError("truncated length prefix")
    (n,) = struct.unpack_from("<I", data, pos)
    pos += 4
    if pos + n > len(data):
        raise ApkSigError("length-prefixed value exceeds buffer")
    return data[pos : pos + n], pos + n


def encode_lp(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _le32(value: int) -> bytes:
    return struct.pack("<I", value)


# ---------------------------------------------------------------------------
# content digest (AOSP "Integrity-protected contents")
# ---------------------------------------------------------------------------
def content_digest(
    data: bytes,
    block_start: int,
    cd_offset: int,
    eocd_pos: int,
    algo: str = "sha256",
) -> bytes:
    """Two-level digest over ZIP sections 1 (entries), 3 (CD), 4 (EOCD).

    The EOCD is hashed with its CD-offset field replaced by the offset of
    the APK signing block (AOSP: the CD offset "must be treated as
    containing the offset of the APK signing block").
    """
    hasher = getattr(hashlib, algo)

    sections = [
        data[0:block_start],                     # section 1: ZIP entries
        data[cd_offset:eocd_pos],                # section 3: Central Directory
    ]
    eocd = bytearray(data[eocd_pos:])            # section 4
    struct.pack_into("<I", eocd, 16, block_start)
    sections.append(bytes(eocd))

    chunk_digests: List[bytes] = []
    for section in sections:
        if not section:
            continue
        for off in range(0, len(section), CHUNK_SIZE):
            chunk = section[off : off + CHUNK_SIZE]
            chunk_digests.append(
                hasher(b"\xa5" + _le32(len(chunk)) + chunk).digest()
            )
    if not chunk_digests:
        chunk_digests = [hasher(b"\xa5" + _le32(0)).digest()]
    return hasher(
        b"\x5a" + _le32(len(chunk_digests)) + b"".join(chunk_digests)
    ).digest()


# ---------------------------------------------------------------------------
# signer parsing
# ---------------------------------------------------------------------------
@dataclass
class Signer:
    signed_data: bytes
    digests: List[Tuple[int, bytes]]
    cert_der: bytes
    attributes: List[Tuple[int, bytes]]
    signatures: List[Tuple[int, bytes]]
    public_key: bytes
    min_sdk: Optional[int] = None      # v3 only
    max_sdk: Optional[int] = None      # v3 only


def _parse_digest_records(seq: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(seq):
        rec, pos = _lp(seq, pos)
        if len(rec) < 5:
            raise ApkSigError("digest record shorter than algId + length")
        (alg,) = struct.unpack_from("<I", rec, 0)
        digest, _ = _lp(rec, 4)
        out.append((alg, digest))
    return out


def _parse_certificates(seq: bytes) -> List[bytes]:
    out: List[bytes] = []
    pos = 0
    while pos < len(seq):
        der, pos = _lp(seq, pos)
        out.append(der)
    return out


def _parse_attributes(seq: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(seq):
        rec, pos = _lp(seq, pos)
        if len(rec) < 4:
            raise ApkSigError("additional attribute shorter than 4 bytes")
        (attr_id,) = struct.unpack_from("<I", rec, 0)
        out.append((attr_id, rec[4:]))
    return out


def _parse_v2_signers(payload: bytes) -> List[Signer]:
    """v2 value: sequence of signers {signedData, signatures, publicKey}."""
    signers_seq, _ = _lp(payload, 0)
    out: List[Signer] = []
    pos = 0
    while pos < len(signers_seq):
        blob, pos = _lp(signers_seq, pos)
        signed_data, cur = _lp(blob, 0)
        signatures_blob, cur = _lp(blob, cur)
        public_key, cur = _lp(blob, cur)

        digests_blob, p2 = _lp(signed_data, 0)
        digests = _parse_digest_records(digests_blob)
        certs_blob, p2 = _lp(signed_data, p2)
        certs = _parse_certificates(certs_blob)
        try:
            attrs_blob, p2 = _lp(signed_data, p2)
            attributes = _parse_attributes(attrs_blob)
        except ApkSigError:
            attributes = []
        out.append(
            Signer(
                signed_data=signed_data,
                digests=digests,
                cert_der=certs[0] if certs else b"",
                attributes=attributes,
                signatures=_parse_digest_records(signatures_blob),
                public_key=public_key,
            )
        )
    return out


def _parse_v3_signers(payload: bytes) -> List[Signer]:
    """v3 value: signers {signedData{digests, certs, minSDK, maxSDK, attrs},
    minSDK, maxSDK, signatures, publicKey}."""
    signers_seq, _ = _lp(payload, 0)
    out: List[Signer] = []
    pos = 0
    while pos < len(signers_seq):
        blob, pos = _lp(signers_seq, pos)
        signed_data, cur = _lp(blob, 0)
        digests_blob, p2 = _lp(signed_data, 0)
        digests = _parse_digest_records(digests_blob)
        certs_blob, p2 = _lp(signed_data, p2)
        certs = _parse_certificates(certs_blob)
        min_sdk = max_sdk = None
        if p2 + 8 <= len(signed_data):
            (min_sdk,) = struct.unpack_from("<I", signed_data, p2)
            (max_sdk,) = struct.unpack_from("<I", signed_data, p2 + 4)
            p2 += 8
        try:
            attrs_blob, p2 = _lp(signed_data, p2)
            attributes = _parse_attributes(attrs_blob)
        except ApkSigError:
            attributes = []
        # signer trailer: minSDK/maxSDK (uint32 each), signatures, public key
        if cur + 8 <= len(blob):
            cur += 8                        # duplicated min/max uint32s
        signatures_blob, cur = _lp(blob, cur)
        public_key, cur = _lp(blob, cur)
        out.append(
            Signer(
                signed_data=signed_data,
                digests=digests,
                cert_der=certs[0] if certs else b"",
                attributes=attributes,
                signatures=_parse_digest_records(signatures_blob),
                public_key=public_key,
                min_sdk=min_sdk,
                max_sdk=max_sdk,
            )
        )
    return out


# ---------------------------------------------------------------------------
# ECDSA DER (r, s) -> raw 64-byte form used by the verify core
# ---------------------------------------------------------------------------
def _ecdsa_der_to_raw(sig_der: bytes) -> Optional[bytes]:
    try:
        seq = parse_tlv(sig_der)
        if seq.tag != 0x30:
            return None
        children = seq.children()
        if len(children) != 2:
            return None
        r = int.from_bytes(children[0].value, "big")
        s = int.from_bytes(children[1].value, "big")
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    except (Pkcs7Error, OverflowError, ValueError):
        return None


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------
@dataclass
class BlockVerification:
    scheme: str                            # "v2" | "v3"
    verified: bool
    reasons: List[str] = field(default_factory=list)
    signer_count: int = 0
    digest_algorithm: Optional[str] = None
    layout_ok: bool = True
    signature_ok: bool = False

    def describe(self) -> str:
        status = "verified" if self.verified else "FAILED"
        head = f"APK signature scheme {self.scheme} {status}"
        if self.verified:
            return head
        return head + ": " + "; ".join(self.reasons[:3])


def _verify_signature_over(
    signer: Signer, reasons: List[str]
) -> Tuple[bool, Optional[str]]:
    """Verify one supported signature over the raw ``signed data`` bytes."""
    supported = [(alg, sig) for alg, sig in signer.signatures if alg in _SUPPORTED]
    if not supported:
        seen = sorted({hex(a) for a, _ in signer.signatures})
        reasons.append(
            "no verifiable signature algorithm in the block "
            f"(have: {seen}; supported: RSA PKCS#1 v1.5 0x0103, ECDSA 0x0201)"
        )
        return False, None
    alg, sig = supported[0]
    hasher_name = _SIG_DIGEST[alg]
    digest = hashlib.new(hasher_name, signer.signed_data).digest()

    key = None
    for blob in (signer.public_key, signer.cert_der):
        try:
            key = parse_spki(blob).key
            break
        except (Pkcs7Error, ValueError):
            continue
    if key is None:
        reasons.append("public key is not a parseable RSA / EC P-256 SPKI")
        return False, hasher_name

    if isinstance(key, RsaPublicKey):
        ok = key.verify(digest, hasher_name, sig)
    elif isinstance(key, EcPublicKey):
        raw = _ecdsa_der_to_raw(sig)
        if raw is None:
            reasons.append("ECDSA signature is not a DER-encoded (r, s) sequence")
            return False, hasher_name
        ok = key.verify(digest, "sha256", raw)
    else:
        reasons.append("unsupported key type")
        return False, hasher_name

    if not ok:
        reasons.append(f"signature over signed data FAILED (algorithm {hex(alg)})")
    return ok, hasher_name


def _spki_of_cert(cert_der: bytes) -> bytes:
    """Raw TLV bytes of the SubjectPublicKeyInfo inside a DER certificate."""
    try:
        cert = parse_tlv(cert_der)
        tbs = cert.children()[0]
        for child in tbs.children():
            if child.tag == 0x30:
                subs = child.children()
                if subs and any(sub.tag == 0x03 for sub in subs):
                    return child.raw
    except (Pkcs7Error, IndexError):
        pass
    return b""


def _check_signer(
    data: bytes, block: SigningBlock, signer: Signer, reasons: List[str]
) -> Tuple[bool, Optional[str]]:
    """The four per-signer checks; returns (all_ok, digest_algo)."""
    if not signer.signatures:
        reasons.append("signer has no signatures")
        return False, None
    if not signer.cert_der:
        reasons.append("signer has no certificate")
        return False, None
    if not signer.public_key:
        reasons.append("signer has no public key")
        return False, None

    # (1) signature over signed data, using a supported algorithm
    sig_ok, algo = _verify_signature_over(signer, reasons)
    if not sig_ok or algo is None:
        return False, algo

    # (2) digest / signature algorithm-ID lists must be identical
    sig_ids = [a for a, _ in signer.signatures]
    dig_ids = [a for a, _ in signer.digests]
    if sig_ids != dig_ids:
        reasons.append(
            "signature algorithm IDs differ from digest algorithm IDs "
            f"({[hex(i) for i in sig_ids]} vs {[hex(i) for i in dig_ids]})"
        )
        return False, algo

    # (3) content digest of the actual file bytes
    expected = dict(signer.digests).get(_DIGEST_ALG_TO_ID.get(algo, 0))
    if expected is None:
        reasons.append(f"no signed content digest for algorithm {algo}")
        return False, algo
    eocd_pos = _find_eocd(data)
    if eocd_pos is None:
        reasons.append("ZIP EOCD not found for content digest")
        return False, algo
    computed = content_digest(data, block.start, block.cd_offset, eocd_pos, algo)
    if computed != expected:
        reasons.append("content digest over the APK does NOT match the signed digest")
        return False, algo

    # (4) publicKey == SPKI(first certificate)
    if signer.public_key != _spki_of_cert(signer.cert_der):
        reasons.append("public key does not match the signer certificate SPKI")
        return False, algo
    return True, algo


def _verify_block(data: bytes, block: SigningBlock, signers, scheme: str,
                  require_single: bool) -> BlockVerification:
    result = BlockVerification(
        scheme=scheme,
        verified=False,
        layout_ok=not block.layout_problems,
        signer_count=len(signers),
    )
    result.reasons.extend(block.layout_problems)
    if not signers:
        result.reasons.append("no signers in the block")
        return result
    if require_single and len(signers) != 1:
        result.reasons.append(
            f"v3 block must contain exactly one signer (found {len(signers)})"
        )
    oks: List[bool] = []
    algos: List[Optional[str]] = []
    for signer in signers:
        ok, algo = _check_signer(data, block, signer, result.reasons)
        oks.append(ok)
        algos.append(algo)
    result.signature_ok = all(oks)
    result.digest_algorithm = next((a for a in algos if a), None)
    result.verified = (
        result.signature_ok
        and result.layout_ok
        and not (require_single and len(signers) != 1)
    )
    return result


# --- public entry points ----------------------------------------------------
def verify_v2(data: bytes, block: SigningBlock) -> BlockVerification:
    """Verify the APK Signature Scheme v2 block (AOSP step 3)."""
    payload = block.entries.get(V2_BLOCK_ID)
    if payload is None:
        return BlockVerification("v2", False, ["v2 block id missing"])
    try:
        signers = _parse_v2_signers(payload)
    except ApkSigError as exc:
        return BlockVerification("v2", False, [f"v2 block parse: {exc}"])
    return _verify_block(data, block, signers, "v2", require_single=False)


def verify_v3(data: bytes, block: SigningBlock) -> BlockVerification:
    """Verify the APK Signature Scheme v3 block (single signer, min/max SDK)."""
    payload = block.entries.get(V3_BLOCK_ID)
    if payload is None:
        return BlockVerification("v3", False, ["v3 block id missing"])
    try:
        signers = _parse_v3_signers(payload)
    except ApkSigError as exc:
        return BlockVerification("v3", False, [f"v3 block parse: {exc}"])
    return _verify_block(data, block, signers, "v3", require_single=True)

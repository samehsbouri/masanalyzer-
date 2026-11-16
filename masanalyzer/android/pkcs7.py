"""Minimal, stdlib-only PKCS#7 / X.509 parsing plus the real signature
verification cores (RSA PKCS#1 v1.5 and ECDSA P-256).

Why hand-rolled DER parsing: the project must stay dependency-free, and the
v1 (JAR) APK signature travels inside a PKCS#7/CMS ``SignedData`` blob that
must be unpacked to reach the certificate, digest hints and the raw
signature bytes.

Supported:

* DER TLV (definite lengths; DER is canonical by definition)
* ``SignedData`` (1.2.840.113549.1.7.2) + ``SignerInfo``
* SubjectPublicKeyInfo: RSA (1.2.840.113549.1.1.1), EC P-256
  (1.2.840.10045.2.1 + curve 1.2.840.10045.3.1.7)
* verification primitives: RSA PKCS#1 v1.5 over SHA-256/SHA-1 (public-key
  modexp), ECDSA over P-256 (pure-python Jacobian point arithmetic)

Malformed input raises :class:`Pkcs7Error`; callers treat that as "cannot
verify", matching apksig behaviour.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class Pkcs7Error(ValueError):
    """Raised when a blob is not the DER structure we expect."""


# ---------------------------------------------------------------------------
# DER walker / writer
# ---------------------------------------------------------------------------
@dataclass
class Node:
    tag: int
    header: int   # bytes in the tag+len header
    length: int   # content length
    raw: bytes    # the complete TLV bytes

    @property
    def value(self) -> bytes:
        return self.raw[self.header : self.header + self.length]

    def children(self) -> List["Node"]:
        """Parse the value as a concatenation of TLVs (constructed form)."""
        out: List[Node] = []
        pos, end = 0, len(self.value)
        while pos + 2 <= end:
            child = parse_tlv(self.value, pos)
            out.append(child)
            pos += child.header + child.length
        if pos != end:
            raise Pkcs7Error("trailing garbage inside constructed node")
        return out


def parse_tlv(data: bytes, offset: int = 0) -> Node:
    """Parse the first TLV in ``data[offset:]``."""
    n = len(data)
    if offset < 0 or offset + 2 > n:
        raise Pkcs7Error("short DER (no room for header)")
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        hdr, length = 2, first
    elif first == 0x80:
        raise Pkcs7Error("indefinite length is not DER")
    else:
        count = first & 0x7F
        if count > 4 or offset + 2 + count > n:
            raise Pkcs7Error("bad long-form DER length")
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        hdr = 2 + count
    if offset + hdr + length > n:
        raise Pkcs7Error("DER content beyond buffer")
    return Node(tag=tag, header=hdr, length=length, raw=data[offset : offset + hdr + length])


# --- OIDs -------------------------------------------------------------------
OID_RSA = bytes.fromhex("2a864886f70d010101")
OID_RSA_SHA256 = bytes.fromhex("2a864886f70d01010b")
OID_RSA_SHA1 = bytes.fromhex("2a864886f70d010105")
OID_EC_P256 = bytes.fromhex("2a8648ce3d0201")
OID_CURVE_P256 = bytes.fromhex("2a8648ce3d030107")
OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
OID_DATA = bytes.fromhex("2a864886f70d010701")
OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
OID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
OID_SIGNING_TIME = bytes.fromhex("2a864886f70d010905")
OID_SHA256 = bytes.fromhex("608648016503040201")
OID_SHA1 = bytes.fromhex("2b0e03021a")
OID_CN = bytes.fromhex("550403")               # 2.5.4.3 commonName (X.520)

_DIGEST_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}

# --- DER writer used by the fixture builder ---------------------------------
def encode_der(tag: int, payload: bytes) -> bytes:
    n = len(payload)
    if n < 0x80:
        header = bytes([tag, n])
    else:
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(size)]) + size
    return header + payload


encode_oid = lambda oid: encode_der(0x06, oid)
encode_octet = lambda payload: encode_der(0x04, payload)
encode_seq = lambda payload: encode_der(0x30, payload)
encode_set = lambda payload: encode_der(0x31, payload)
encode_context = lambda tag, payload: encode_der(tag | 0xA0, payload)
encode_bitstring = lambda payload: encode_der(0x03, b"\x00" + payload)
encode_int = lambda value: encode_der(0x02, _int_payload(value))

def _int_payload(value: int) -> bytes:
    if value <= 0:
        return b"\x00"
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b"\x00" + body if body[0] & 0x80 else body


# ---------------------------------------------------------------------------
# verification cores
# ---------------------------------------------------------------------------
@dataclass
class RsaPublicKey:
    modulus: int
    exponent: int

    def verify(self, digest: bytes, digest_name: str, signature: bytes) -> bool:
        """PKCS#1 v1.5 with EMSA-PKCS1-v1_5 encoding."""
        prefix = _DIGEST_PREFIX.get(digest_name)
        if prefix is None:
            return False
        k = (self.modulus.bit_length() + 7) // 8
        if len(signature) != k or len(digest) + len(prefix) + 11 > k:
            return False
        sig_int = int.from_bytes(signature, "big")
        if sig_int >= self.modulus:
            return False
        em = pow(sig_int, self.exponent, self.modulus).to_bytes(k, "big")
        padding = b"\xff" * (k - len(prefix) - len(digest) - 3)
        expected = b"\x00\x01" + padding + b"\x00" + prefix + digest
        return em == expected


class EcPublicKey:
    """P-256 public point (x, y) with ECDSA verification."""

    P = (2**256) - 2**224 + 2**192 + 2**96 - 1
    A = P - 3
    B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    def __init__(self, x: int, y: int) -> None:
        if not (0 <= x < self.P and 0 <= y < self.P):
            raise Pkcs7Error("EC point out of field range")
        # reject points not on the curve
        lhs = (y * y) % self.P
        rhs = (x * x * x - 3 * x + self.B) % self.P
        if lhs != rhs:
            raise Pkcs7Error("EC point not on P-256 curve")
        self.x, self.y = x, y

    # -- Jacobian helpers ---------------------------------------------------
    @classmethod
    def _inf(cls) -> Tuple[int, int, int]:
        return (0, 1, 0)

    @classmethod
    def _double(cls, pt):
        X, Y, Z = pt
        if Z == 0 or Y == 0:
            return cls._inf()
        p, a = cls.P, cls.A
        S = (4 * X * Y * Y) % p
        M = (3 * X * X + a * Z * Z * Z * Z) % p
        X3 = (M * M - 2 * S) % p
        Y3 = (M * (S - X3) - 8 * Y * Y * Y * Z * Z) % p
        Z3 = (2 * Y * Z) % p
        if Y3 < 0:
            Y3 %= p
        return (X3, Y3, Z3)

    @classmethod
    def _add(cls, p1, p2):
        if p1[2] == 0:
            return p2
        if p2[2] == 0:
            return p1
        X1, Y1, Z1 = p1
        X2, Y2, Z2 = p2
        p = cls.P
        zz2 = (Z2 * Z2) % p
        zz1 = (Z1 * Z1) % p
        u1 = (X1 * zz2) % p
        u2 = (X2 * zz1) % p
        s1 = (Y1 * Z2 * zz2) % p
        s2 = (Y2 * Z1 * zz1) % p
        if u1 == u2:
            if s1 != s2:
                return cls._inf()
            return cls._double(p1)
        h = (u2 - u1) % p
        r = (2 * (s2 - s1)) % p
        hh = (h * h) % p
        v = (u1 * hh) % p
        X3 = (r * r - v - 2 * v) % p
        Y3 = (r * (v - X3) - s1 * h * hh) % p
        Z3 = (2 * h * Z1 * Z2) % p
        return (X3, Y3, Z3)

    @classmethod
    def _mul(cls, scalar: int, point):
        result = cls._inf()
        addend = point
        while scalar:
            if scalar & 1:
                result = cls._add(result, addend)
            addend = cls._double(addend)
            scalar >>= 1
        return result

    def _to_affine(self, pt):
        p = self.P
        if pt[2] == 0:
            return None
        z_inv = pow(pt[2], p - 2, p)
        z2 = (z_inv * z_inv) % p
        return ((pt[0] * z2) % p, (pt[1] * z2 * z_inv) % p)

    # -- signature -------------------------------------------------------------
    def verify(self, digest: bytes, digest_name: str, signature: bytes) -> bool:
        if digest_name != "sha256" or len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        n = self.N
        if not (1 <= r < n and 1 <= s < n):
            return False
        h = int.from_bytes(digest, "big") % n
        w = pow(s, n - 2, n)          # s^-1 mod n
        u1 = (h * w) % n
        u2 = (r * w) % n
        point = self._add(self._mul(u1, (self.GX, self.GY, 1)), self._mul(u2, (self.x, self.y, 1)))
        affine = self._to_affine(point)
        if affine is None:
            return False
        x = affine[0]
        return x % n == r


# --- subject public key -----------------------------------------------------
@dataclass
class SubjectPublicKey:
    algorithm: str   # "rsa" | "ec"
    key: object
    modulus_bits: int = 0


@dataclass
class X509CertInfo:
    """The certificate facts our trust checks need (std-libs only)."""

    subject: str                       # first CN of the subject RDN ("" if none)
    issuer: str
    not_before: object                 # datetime.utc iso strings downstream
    not_after: object
    key_algorithm: str                 # "rsa" | "ec"
    key_bits: int                      # RSA modulus bits / EC bit-length estimate
    self_signed: bool
    serial_hex: str
    #: tbsCertificate signature algorithm, e.g. "sha384WithRSAEncryption"
    signature_algorithm: str = ""
    #: the digest inside that signature algorithm, e.g. "sha384"
    hash_algorithm: str = ""


#: signature-algorithm OIDs -> (signature algorithm, digest) names.  Only the
#: algorithms Android code-signers actually emit are mapped; unknown OIDs stay
#: empty strings (a fact we cannot name is not asserted).
_SIG_ALG_NAMES: Dict[bytes, Tuple[str, str]] = {
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": ("sha1WithRSAEncryption", "sha1"),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": ("sha256WithRSAEncryption", "sha256"),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": ("sha384WithRSAEncryption", "sha384"),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": ("sha512WithRSAEncryption", "sha512"),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04": ("md5WithRSAEncryption", "md5"),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e": ("sha224WithRSAEncryption", "sha224"),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x02": ("ecdsa-with-SHA256", "sha256"),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x03": ("ecdsa-with-SHA384", "sha384"),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x04": ("ecdsa-with-SHA512", "sha512"),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x01": ("ecdsa-with-SHA1", "sha1"),
    b"\x2a\x86\x48\xce\x38\x04\x03": ("dsa-with-sha1", "sha1"),
    b"\x60\x86\x48\x01\x65\x03\x04\x03\x02": ("dsa-with-sha256", "sha256"),
}


def _sig_alg_name(oid: bytes) -> Tuple[str, str]:
    """Friendly (signature algorithm, hash algorithm) for a signature OID."""
    return _SIG_ALG_NAMES.get(oid, ("", ""))


def _der_time(node: Node) -> "datetime.datetime":
    """Decode UTCTime (0x17) or GeneralizedTime (0x18) to a datetime.

    Only the Z-terminated ``[YY]YYMMDDHHMM[SS][Z]`` shapes are accepted;
    seconds are optional per ASN.1-1988.
    """
    import datetime as _dt

    raw = node.value
    if node.tag not in (0x17, 0x18):
        raise Pkcs7Error("validity is not a TIME value")
    text = raw.decode("ascii", "strict")
    if text.endswith(("z", "Z")):
        text = text[:-1]
    digits = "".join(c for c in text if c.isdigit())
    if node.tag == 0x17:                       # UTCTime: YY MM DD
        year = int(digits[0:2])
        year += 2000 if year < 50 else 1900
        rest = digits[2:]
    else:                                      # GeneralizedTime: YYYY MM DD
        year = int(digits[0:4])
        rest = digits[4:]
    try:
        month = int(rest[0:2])
        day = int(rest[2:4])
        hour = int(rest[4:6]) if len(rest) >= 6 else 0
        minute = int(rest[6:8]) if len(rest) >= 8 else 0
        second = int(rest[8:10]) if len(rest) >= 10 else 0
        return _dt.datetime(year, month, day, hour, minute, second)
    except ValueError as exc:
        raise Pkcs7Error(f"invalid validity date: {exc}") from exc


def _rdn_cn(name_node: Node) -> str:
    """First commonName attribute value of an RDNSequence (Name)."""
    for rdn in name_node.children():
        if rdn.tag != 0x31:
            continue
        for attr in rdn.children():
            if attr.tag != 0x30:
                continue
            parts = attr.children()
            if parts and parts[0].value == b"\x55\x04\x03" and len(parts) > 1:
                val = parts[1]
                if val.tag in (0x0C, 0x13, 0x14, 0x16, 0x1E):
                    return val.value.decode("utf-8", "replace")
    return ""


def parse_certificate(cert_der: bytes) -> X509CertInfo:
    """Parse an X.509 certificate (v3):
    tbsCertificate  ::= [0] version, serialNumber, signature AlgId,
                        issuer Name, validity, subject Name, SPKI, …
    """
    import datetime as _dt

    cert = parse_tlv(cert_der)
    if cert.tag != 0x30:
        raise Pkcs7Error("certificate must be a SEQUENCE")
    tbs = cert.children()[0]
    tbs_parts = tbs.children()
    idx = 0
    if tbs_parts and tbs_parts[idx].tag == 0xA0:      # [0] EXPLICIT version
        idx += 1
    if not len(tbs_parts) > idx or tbs_parts[idx].tag != 0x02:
        raise Pkcs7Error("certificate serialNumber missing")
    serial_int = int.from_bytes(tbs_parts[idx].value, "big")
    idx += 1
    sig_alg_name, hash_alg_name = "", ""
    if idx < len(tbs_parts) and tbs_parts[idx].tag == 0x30:
        # tbsCertificate.signature AlgorithmIdentifier
        try:
            sig_parts = tbs_parts[idx].children()
            if sig_parts:
                sig_alg_name, hash_alg_name = _sig_alg_name(sig_parts[0].value)
        except (Pkcs7Error, IndexError):
            pass
        idx += 1                                          # signature AlgorithmIdentifier

    # Name nodes: SEQ containing SET(s); validity: 0x17/0x18 pair inside.
    names: List[Node] = []
    validity: List[Node] = []
    spki: Optional[Node] = None
    for child in tbs_parts[idx:]:
        if child.tag == 0x30:
            subs = child.children()
            if any(s.tag == 0x03 for s in subs) and any(
                s.tag == 0x30 for s in subs[:1]
            ):
                spki = child                          # SEQ(alg, BIT STRING)
            elif any(s.tag in (0x17, 0x18) for s in subs):
                validity.extend(s for s in subs if s.tag in (0x17, 0x18))
            elif any(s.tag == 0x31 for s in subs):
                names.append(child)                   # SEQ-of-SETs (Name)
    if spki is None:
        raise Pkcs7Error("certificate has no SubjectPublicKeyInfo")
    if not names:
        raise Pkcs7Error("certificate has no issuer/subject names")
    issuer, subject = _ordered_names(names)
    if len(validity) < 2:
        raise Pkcs7Error("certificate validity needs two TIME values")

    spki_info = parse_spki(cert_der)
    subject_cn = _rdn_cn(subject)
    issuer_cn = _rdn_cn(issuer)
    not_before = _der_time(validity[0])
    not_after = _der_time(validity[1])
    return X509CertInfo(
        subject=subject_cn,
        issuer=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        key_algorithm=spki_info.algorithm,
        key_bits=spki_info.modulus_bits,
        self_signed=subject.raw == issuer.raw,
        serial_hex=f"{serial_int:x}",
        signature_algorithm=sig_alg_name,
        hash_algorithm=hash_alg_name,
    )


def _ordered_names(names: List[Node]) -> Tuple[Node, Node]:
    """(issuer, subject): first Name encountered, then the last one."""
    if len(names) == 1:
        return names[0], names[0]
    return names[0], names[-1]


def _bits_payload(node: Node) -> bytes:
    """DER BIT STRING payload with zero unused bits -> raw bytes."""
    value = node.value
    if not value:
        raise Pkcs7Error("empty BIT STRING")
    if value[0] != 0:
        raise Pkcs7Error("non-aligned BIT STRING")
    return value[1:]


def parse_spki(cert_der: bytes) -> SubjectPublicKey:
    """Extract the SubjectPublicKeyInfo of a DER X.509 certificate."""
    cert = parse_tlv(cert_der)
    if cert.tag != 0x30:
        raise Pkcs7Error("certificate must be a SEQUENCE")
    tbs = cert.children()[0]          # tbsCertificate
    tbs_parts = tbs.children()
    # SubjectPublicKeyInfo is the [6th] field; find the outer BIT STRING
    # that holds the SPKI directly among the TBS children.
    # Locate the SubjectPublicKeyInfo: the SEQUENCE among the TBS children
    # that itself contains a BIT STRING (subjectPublicKey).
    spki = None
    for child in tbs_parts:
        if child.tag == 0x30:
            subs = child.children()
            if subs and any(sub.tag == 0x03 for sub in subs):
                spki = child
                break
    if spki is None:
        raise Pkcs7Error("certificate has no SubjectPublicKeyInfo")
    parts = spki.children()
    if len(parts) != 2 or parts[1].tag != 0x03:
        raise Pkcs7Error("SPKI is not (algorithm, subjectPublicKey)")
    alg_parts = parts[0].children()
    if not alg_parts:
        raise Pkcs7Error("empty AlgorithmIdentifier")
    oid = alg_parts[0].value
    key_material = _bits_payload(parts[1])
    if oid == OID_RSA:
        rsa_seq = parse_tlv(key_material)
        ints = rsa_seq.children()
        if len(ints) < 2:
            raise Pkcs7Error("RSAPublicKey needs (modulus, exponent)")
        modulus = int.from_bytes(ints[0].value, "big")
        exponent = int.from_bytes(ints[1].value, "big")
        if modulus % 2 == 0 or modulus < 3:
            raise Pkcs7Error("implausible RSA modulus")
        return SubjectPublicKey(
            algorithm="rsa", key=RsaPublicKey(modulus, exponent),
            modulus_bits=modulus.bit_length(),
        )
    if oid == OID_EC_P256:
        if len(alg_parts) < 2 or alg_parts[1].value != OID_CURVE_P256:
            raise Pkcs7Error("unsupported EC curve (want P-256)")
        if len(key_material) != 65 or key_material[0] != 0x04:
            raise Pkcs7Error("unsupported EC key encoding (want 0x04 x|y)")
        x = int.from_bytes(key_material[1:33], "big")
        y = int.from_bytes(key_material[33:65], "big")
        return SubjectPublicKey(algorithm="ec", key=EcPublicKey(x, y))
    raise Pkcs7Error("unsupported public-key algorithm")


def parse_algorithm_identifier(seq: Node) -> bytes:
    """OID of the first AlgorithmIdentifier in ``seq``."""
    parts = seq.children()
    if not parts:
        raise Pkcs7Error("empty AlgorithmIdentifier")
    return parts[0].value


# ---------------------------------------------------------------------------
# SignedData / SignerInfo
# ---------------------------------------------------------------------------
@dataclass
class SignerInfo:
    digest_name: str                       # "sha256" | "sha1"
    signature_algorithm: bytes
    signature: bytes
    authenticated_attrs: Optional[bytes] = None   # raw [0]-wrapped attrs
    message_digest_attr: Optional[bytes] = None


@dataclass
class SignedData:
    content_oid: bytes = OID_DATA
    content: Optional[bytes] = None        # eContent when attached
    cert_der: Optional[bytes] = None
    signer: Optional[SignerInfo] = None
    digest_algorithms: List[bytes] = None


def parse_signed_data(der: bytes) -> SignedData:
    """Parse DER ``ContentInfo { contentType=signedData, [0] }``."""
    ci = parse_tlv(der)
    if ci.tag != 0x30:
        raise Pkcs7Error("ContentInfo must be a SEQUENCE")
    parts = ci.children()
    if not parts or parts[0].value != OID_SIGNED_DATA:
        raise Pkcs7Error("not a PKCS#7 SignedData (wrong contentType)")
    if len(parts) < 2 or parts[1].tag != 0xA0:
        raise Pkcs7Error("SignedData [0] content wrapper missing")
    sd_node = parse_tlv(parts[1].value)
    sp = sd_node.children()
    out = SignedData(digest_algorithms=[])
    idx = 0
    if idx < len(sp) and sp[idx].tag == 0x02:
        idx += 1                                        # version INTEGER
    if idx < len(sp) and sp[idx].tag == 0x31:          # digestAlgorithms
        out.digest_algorithms = [
            parse_algorithm_identifier(c) for c in sp[idx].children()
        ]
        idx += 1
    if idx < len(sp) and sp[idx].tag == 0x30:          # contentInfo
        ci_parts = sp[idx].children()
        if ci_parts:
            out.content_oid = ci_parts[0].value
        if len(ci_parts) > 1 and ci_parts[1].tag == 0xA0:
            inner = ci_parts[1].children()[0]
            out.content = inner.value if inner.tag == 0x04 else inner.raw
        idx += 1
    while idx < len(sp) and sp[idx].tag in (0xA0, 0xA1, 0xA2):
        # certificates [0]/crls [1]-like sets - grab the first Certificate
        for child in sp[idx].children():
            if child.tag == 0x30:
                try:
                    parse_tlv(child.raw)          # sanity: a real SEQUENCE
                    out.cert_der = child.raw
                except Pkcs7Error:
                    out.cert_der = None
                break
        idx += 1
        break                                        # only one such set expected
    if idx < len(sp) and sp[idx].tag == 0x31:        # signerInfos
        infos = sp[idx].children()
        if not infos:
            raise Pkcs7Error("SignerInfos is empty - no signer")
        out.signer = _parse_signer_info(infos[0])
    else:
        raise Pkcs7Error("SignerInfos missing")
    return out


def _parse_signer_info(si: Node) -> SignerInfo:
    parts = si.children()
    idx = 0
    if parts and parts[0].tag == 0x02:
        idx = 1                                       # version INTEGER
    # SignerIdentifier: IssuerAndSerialNumber (SEQUENCE) or [0] subjectKeyId.
    # Distinguish from the digest AlgorithmIdentifier that follows by its
    # first child: an OID means we are already at digestAlgorithm.
    if idx < len(parts) and parts[idx].tag == 0x30:
        head = parts[idx].children()[0] if parts[idx].children() else None
        if head is not None and head.tag != 0x06:
            idx += 1                                  # sid consumed
    elif idx < len(parts) and parts[idx].tag in (0x80, 0xA0):
        idx += 1                                      # sid (subjectKeyIdentifier)
    if idx >= len(parts) or parts[idx].tag != 0x30:
        raise Pkcs7Error("SignerInfo: digestAlgorithm missing")
    digest_oid = parse_algorithm_identifier(parts[idx])
    idx += 1
    digest_name = _digest_label(digest_oid)

    auth_attrs: Optional[bytes] = None
    message_digest_attr: Optional[bytes] = None
    if idx < len(parts) and parts[idx].tag == 0xA0:   # signedAttrs [0] IMPLICIT SET
        auth_attrs = parts[idx].raw                   # signature input per CMS
        for attr in parts[idx].children():
            ap = attr.children()
            if len(ap) < 2:
                continue
            oid = ap[0].value
            if oid == OID_MESSAGE_DIGEST:
                inner = ap[1].children()[0] if ap[1].tag == 0x31 else ap[1]
                message_digest_attr = inner.value
        idx += 1

    if idx >= len(parts) or parts[idx].tag != 0x30:
        raise Pkcs7Error("SignerInfo: signatureAlgorithm missing")
    alg_parts = parts[idx].children()
    sig_alg = alg_parts[0].value if alg_parts else OID_RSA
    idx += 1

    signature = b""
    if idx < len(parts):
        sig_node = parts[idx]
        if sig_node.tag == 0x04:
            signature = sig_node.value
        elif sig_node.tag == 0x03:
            signature = _bits_payload(sig_node)
        elif sig_node.tag == 0x31:                    # der-encoded after BER? accept
            signature = sig_node.value
        else:
            raise Pkcs7Error("SignerInfo: signature is not an OCTET STRING")
    else:
        raise Pkcs7Error("SignerInfo: signature missing")

    return SignerInfo(
        digest_name=digest_name,
        signature_algorithm=sig_alg,
        signature=signature,
        authenticated_attrs=auth_attrs,
        message_digest_attr=message_digest_attr,
    )


def _digest_label(oid: bytes) -> str:
    if oid in (OID_RSA_SHA1, OID_SHA1):
        return "sha1"
    if oid in (OID_RSA_SHA256, OID_SHA256):
        return "sha256"
    # default to sha256 which is what modern signers emit
    return "sha256"


# ---------------------------------------------------------------------------
# combined verification
# ---------------------------------------------------------------------------
def verify_pkcs7_signature(der: bytes, signed_bytes: bytes) -> Tuple[bool, List[str]]:
    """Verify one PKCS#7 signature over ``signed_bytes`` (the .SF content).

    Handles both attached (eContent present) and detached (signedAttrs with
    a messageDigest attribute) CMS shapes used by JAR signers.  Returns
    ``(ok, reasons)``.
    """
    reasons: List[str] = []
    try:
        sd = parse_signed_data(der)
    except Pkcs7Error as exc:
        return False, [f"pkcs7 parse: {exc}"]
    signer = sd.signer
    if signer is None:
        return False, ["pkcs7: no signer"]
    if not signer.signature:
        return False, ["pkcs7: empty signature"]
    if sd.cert_der is None:
        return False, ["pkcs7: no signer certificate"]

    # which blob does the signature cover? ----------------------------------
    if signer.authenticated_attrs is not None:
        if signer.message_digest_attr is not None:
            algo = hashlib.sha256 if signer.digest_name == "sha256" else hashlib.sha1
            if algo(signed_bytes).digest() != signer.message_digest_attr:
                reasons.append(
                    f"pkcs7: messageDigest attr ({signer.digest_name}) does not "
                    f"match the content digest"
                )
        signature_input = signer.authenticated_attrs
    elif sd.content is not None:
        if sd.content != signed_bytes:
            return False, ["pkcs7: attached content differs from the artifact"]
        signature_input = sd.content
    else:
        signature_input = signed_bytes

    try:
        key = parse_spki(sd.cert_der).key
    except Pkcs7Error as exc:
        return False, reasons + [f"pkcs7 spki: {exc}"]

    hasher = hashlib.sha256 if signer.digest_name == "sha256" else hashlib.sha1
    digest = hasher(signature_input).digest()

    ok = False
    if isinstance(key, RsaPublicKey):
        alg_name = signer.signature_algorithm
        name = signer.digest_name
        if alg_name == OID_RSA_SHA256:
            name = "sha256"
        elif alg_name == OID_RSA_SHA1:
            name = "sha1"
        ok = key.verify(digest, name, signer.signature)
    elif isinstance(key, EcPublicKey):
        ok = key.verify(digest, "sha256", signer.signature)
    else:
        reasons.append("pkcs7: unsupported key type")

    if not ok:
        reasons.append("pkcs7: cryptographic signature verification FAILED")
    return ok, reasons

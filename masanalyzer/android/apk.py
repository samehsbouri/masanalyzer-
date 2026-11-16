"""APK container handling: unpacking + signing information.

Security relevant items decoded here:

* the ZIP inventory (manifest, dex, resources, native libs, ``META-INF``)
* **v1** JAR signatures (``META-INF/*.SF`` + ``*.RSA/.DSA/.EC``) with the
  signer Common Name extracted by a tiny DER walker
* the **APK Signing Block** (``APK Sig Block 42``) located by reading the End
  Of Central Directory record; used to report **v2** (``0x7109871a``) and
  **v3/v3.1/v3.2** (``0xf05368c0`` / ``0x1b93ad61`` / ``0x70e1c89f``)
  signatures
* the mapping between numeric resource ids (e.g. ``@res/0x7f0a0001`` inside
  the manifest) and human readable resource names from ``resources.arsc``

Everything is stdlib-only and tolerant of malformed archives.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# APK Signing Block value types (ids from AOSP apksig).
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
# v3.1 = 0x1b93ad61 (AOSP V3SchemeConstants; 0x3ba06f8c is the
# PROOF_OF_ROTATION *attribute* id, not a block id)
V31_BLOCK_ID = 0x1B93AD61
# v3.2 hybrid block (Android 17): parsed for presence + certificates; the
# ML-DSA half is not verifiable with the stdlib, so no verified claim.
V32_BLOCK_ID = 0x70E1C89F
V3X_IDS = (V3_BLOCK_ID, V31_BLOCK_ID, V32_BLOCK_ID)
ZIP_EOCD_MIN_SIZE = 22
# EOCD has this magic, ZIP64 terminator 16 bytes longer.
_ZIP_EOCD_MAGIC = b"PK\x05\x06"


class ApkError(Exception):
    """Raised when the container cannot be interpreted."""


# --------------------------------------------------------------------------
# DER helper - smallest possible ASN.1 TLV walker
# --------------------------------------------------------------------------
def _der_len(data: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, header_len, content_len) of the TLV starting at ``pos``."""
    if pos + 2 > len(data):
        raise ValueError("short DER")
    tag = data[pos]
    byte = data[pos + 1]
    if byte < 0x80:
        return tag, 2, byte
    n = byte & 0x7F
    if n == 0 or n > 4 or pos + 2 + n > len(data):
        raise ValueError("bad DER length")
    (length,) = struct.unpack_from(">I", data[pos + 2 : pos + 2 + n].ljust(4, b"\x00"))
    return tag, 2 + n, length


_OID_CN = b"\x55\x04\x03"          # 2.5.4.3 (commonName)
_UTF8_STR = 0x0C
_PRINTABLE_STR = 0x13


def common_names_from_der(data: bytes) -> List[str]:
    """Extract Common Name attribute values from a DER certificate (lazy).

    Walks all UTF8String/PrintableString values that directly follow a
    ``2.5.4.3`` OID inside RDN sequences.  Good enough for debug-vs-production
    classification and far simpler than a full PKCS7/CMS parser.
    """
    names: List[str] = []

    def visit(pos: int, depth: int = 0) -> None:
        if depth > 14 or pos + 2 > len(data):
            return
        try:
            tag, hdr, length = _der_len(data, pos)
        except ValueError:
            return
        content_end = min(pos + hdr + length, len(data))
        if not (0x30 <= tag <= 0x3F) and tag & 0x20 == 0:
            # primitive leaf, nothing to walk
            return
        prev = None
        cur = pos + hdr
        while cur + 2 <= content_end:
            try:
                ctag, chdr, clen = _der_len(data, cur)
            except ValueError:
                return
            # CN OID followed by a string value?
            if prev is not None and data[prev + _der_len(data, prev)[1] : cur] == _OID_CN:
                if ctag in (_UTF8_STR, _PRINTABLE_STR):
                    names.append(data[cur + chdr : cur + chdr + clen].decode("utf-8", "replace"))
            if ctag & 0x20 or 0x30 <= ctag <= 0x3F:
                visit(cur, depth + 1)
            prev = cur
            cur += chdr + clen

    visit(0)
    return names


# --------------------------------------------------------------------------
# APK model
# --------------------------------------------------------------------------
@dataclass
class ApkSigner:
    scheme: str                       # "v1" | "v2" | "v3" | "v3.1"
    names: List[str] = field(default_factory=list)
    blob: bytes = field(default_factory=bytes)
    # leaf signing certificate identity (empty/None when unrecoverable)
    cert_sha256: str = ""
    cert_info: Optional[Dict[str, Any]] = None

    @property
    def debug(self) -> bool:
        return any(
            n for n in self.names
            if n and ("debug" in n.lower() or "test" in n.lower())
        )


@dataclass
class ApkInfo:
    path: str
    name: str
    size: int = 0
    entries: List[str] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    res_entries: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    manifest_entry: Optional[str] = None
    resources_arsc: bool = False
    sf_entry: Optional[str] = None
    sig_entry: Optional[str] = None
    v1: Optional[ApkSigner] = None
    v2: Optional[ApkSigner] = None
    v3: List[ApkSigner] = field(default_factory=list)
    debug_signed: bool = False
    # real cryptographic chain verification (android.apkverify); tri-state:
    # None = no v1 signature to verify, True/False = verification outcome
    v1_verified: Optional[bool] = None
    v1_reasons: List[str] = field(default_factory=list)
    v1_covered_entries: int = 0
    # whole-file scheme verification (android.apksigv2); tri-state as above
    v2_verified: Optional[bool] = None
    v2_reasons: List[str] = field(default_factory=list)
    v3_verified: Optional[bool] = None
    v3_reasons: List[str] = field(default_factory=list)
    # rollback protection: for v1+v2 APKs the .SF must carry
    # "X-Android-APK-Signed: 2 ..." (True = banner present); None = n/a
    rollback_protected: Optional[bool] = None
    # Janus evidence: central-directory entries whose local-header offsets do
    # not point at a local file header signature ("PK\x03\x04")
    zip_layout_anomalies: List[str] = field(default_factory=list)
    # SHA-256 fingerprints (hex) of the signing certificates; the identity
    # gate (--verify-identity) compares these against a release fingerprint
    signer_fingerprints: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # -- queries -----------------------------------------------------------
    @property
    def signed(self) -> bool:
        return self.v1 is not None or self.v2 is not None or bool(self.v3)

    @property
    def signing_scheme(self) -> str:
        parts = []
        if self.v1 is not None:
            parts.append("v1")
        if self.v2 is not None:
            parts.append("v2")
        schemes = sorted({s.scheme for s in self.v3})
        if schemes:
            parts.append("/".join(schemes))
        return "/".join(parts) or "none"

    def summary(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "size": self.size,
            "entries": len(self.entries),
            "dex_files": len(self.dex_files),
            "native_libs": len(self.native_libs),
            "resources_arsc": self.resources_arsc,
            "signing": self.signing_scheme,
            "signer_names": self.all_signer_names(),
            "signer_fingerprints": self.signer_fingerprints,
            "debug_signed": self.debug_signed,
            "v1_verified": self.v1_verified,
            "v2_verified": self.v2_verified,
            "v3_verified": self.v3_verified,
            "rollback_protected": self.rollback_protected,
        }

    def all_signer_names(self) -> List[str]:
        names: List[str] = []
        for signer in [self.v1, self.v2, *self.v3]:
            if signer:
                names.extend(n for n in signer.names if n)
        seen, out = set(), []
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def signers(self) -> List[Tuple[str, "ApkSigner"]]:
        """Every signer as ``(scheme, signer)``; v1 first, then v2, then v3."""
        out: List[Tuple[str, ApkSigner]] = []
        if self.v1 is not None:
            out.append(("v1", self.v1))
        if self.v2 is not None:
            out.append(("v2", self.v2))
        for s in self.v3:
            out.append((s.scheme, s))
        return out


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def _find_eocd(data: bytes) -> int:
    """Locate the End Of Central Directory record (scan max comment + 64KB)."""
    scan_start = max(0, len(data) - 65535 - ZIP_EOCD_MIN_SIZE)
    pos = data.rfind(_ZIP_EOCD_MAGIC, scan_start)
    if pos < 0:
        raise ApkError("no ZIP EOCD record")
    return pos


def _signing_block(data: bytes, cd_offset: int) -> Optional[Tuple[int, Dict[int, bytes]]]:
    """Deprecated shim — superseded by apksigv2.find_signing_block."""
    from .apksigv2 import find_signing_block

    block = find_signing_block(data)
    if block is None:
        return None
    return block.start, block.entries


def _cert_metadata(cert_der: bytes) -> Tuple[str, Optional[Dict[str, Any]]]:
    """(sha256 fingerprint, quality dict) for one DER certificate.

    ``None`` infos are fine — the fingerprint is still trustworthy since it
    hashes the raw DER bytes; quality attributes just stay unknown.
    """
    fp = hashlib.sha256(cert_der).hexdigest()
    try:
        from .pkcs7 import parse_certificate

        cert = parse_certificate(cert_der)
    except Exception:                                  # noqa: BLE001 - best effort
        return fp, None
    return fp, {
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "key_algorithm": cert.key_algorithm,
        "key_bits": cert.key_bits,
        "self_signed": cert.self_signed,
        "serial": cert.serial_hex,
        # signature/hash algorithms of the certificate itself (parsed facts,
        # "" when the OID is not one we can name)
        "signature_algorithm": cert.signature_algorithm,
        "hash_algorithm": cert.hash_algorithm,
        # content fingerprints of the DER certificate itself
        "md5": hashlib.md5(cert_der).hexdigest(),
        "sha1": hashlib.sha1(cert_der).hexdigest(),
        "sha512": hashlib.sha512(cert_der).hexdigest(),
    }


def _apply_signer_cert(signer: "ApkSigner", cert_der: Optional[bytes]) -> None:
    """Fill ``cert_sha256`` / ``cert_info`` (and names as a fallback)."""
    if not cert_der:
        return
    fp, info = _cert_metadata(cert_der)
    signer.cert_sha256 = fp
    signer.cert_info = info


def _v23_certs(payload: bytes, want_v3: bool) -> List[bytes]:
    """Leaf certificate DER list from a v2/v3 signing-block value."""
    try:
        from .apksigv2 import _parse_v2_signers, _parse_v3_signers

        parse = _parse_v3_signers if want_v3 else _parse_v2_signers
        return [s.cert_der for s in parse(payload) if s.cert_der]
    except Exception:                                  # noqa: BLE001 - best effort
        return []


def _v2_signer_names(payload: bytes) -> Tuple[List[str], bool]:
    """Pull certificate CNs + debug marker out of an ``apk-signer`` block.

    Structure (AOSP ``signer`` entry):
      <length-prefixed sequence>
        signed-data (len-prefixed),
        signatures (len-prefixed),
        public-key (len-prefixed),
        certificates (len-prefixed of len-prefixed DER certs)
    We only need the certificates list; the DER walker handles the rest.
    """
    names: List[str] = []
    try:
        (seq_len,) = struct.unpack_from("<I", payload, 0)
        seq = payload[4 : 4 + seq_len]
        # signed-data ------------------------------------------------------
        (sd_len,) = struct.unpack_from("<I", seq, 0)
        cur = 4 + sd_len
        # signatures -------------------------------------------------------
        (sig_len,) = struct.unpack_from("<I", seq, cur)
        cur += 4 + sig_len
        # public key -------------------------------------------------------
        (pk_len,) = struct.unpack_from("<I", seq, cur)
        cur += 4 + pk_len
        # certificates -----------------------------------------------------
        (certs_len,) = struct.unpack_from("<I", seq, cur)
        certs_end = min(cur + 4 + certs_len, len(seq))
        cur += 4
        while cur + 4 <= certs_end:
            (der_len,) = struct.unpack_from("<I", seq, cur)
            if der_len <= 0 or cur + 4 + der_len > seq_len:
                break
            der = seq[cur + 4 : cur + 4 + der_len]
            names.extend(common_names_from_der(der))
            cur += 4 + der_len
    except (struct.error, IndexError):
        pass
    return names, False


def _v1_signer(sf_name: Optional[str], rsa_name: Optional[str], zf: zipfile.ZipFile) -> Optional[ApkSigner]:
    if not rsa_name:
        return None
    try:
        raw = zf.read(rsa_name)
    except (KeyError, zipfile.BadZipFile, OSError):
        return None
    signer = ApkSigner(scheme="v1", names=common_names_from_der(raw), blob=raw)
    # recover the embedded X.509 leaf for fingerprint / quality checks
    try:
        from .pkcs7 import parse_signed_data

        cert_der = parse_signed_data(raw).cert_der
        if cert_der:
            signer.cert_sha256, signer.cert_info = _cert_metadata(cert_der)
    except Exception:                                  # noqa: BLE001 - best effort
        pass
    return signer


def load_apk(path: str) -> ApkInfo:
    """Read structural + signing information without unpacking."""
    import os

    with open(path, "rb") as fh:
        head = fh.read(4)
    base = os.path.basename(path)

    info = ApkInfo(
        path=path,
        name=base,
        size=_safe_size(path),
    )
    try:
        with zipfile.ZipFile(path, "r") as zf:
            info.entries = zf.namelist()
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        info.warnings.append(f"cannot open zip: {exc}")
        return info

    for entry in info.entries:
        low = entry.lower()
        if low == "androidmanifest.xml":
            info.manifest_entry = entry
        elif low.startswith("meta-inf/") and low.endswith((".sf", ".rsa", ".dsa", ".ec")):
            if low.endswith(".sf"):
                info.sf_entry = entry
            else:
                info.sig_entry = entry
        elif low.endswith(".dex"):
            info.dex_files.append(entry)
        elif "/lib/" in low and low.endswith(".so"):
            info.native_libs.append(entry)
        elif low.startswith("res/") or low.startswith("r/"):
            info.res_entries.append(entry)
        elif low.startswith("assets/"):
            info.assets.append(entry)
    info.resources_arsc = "resources.arsc" in (e.lower() for e in info.entries)

    try:
        with zipfile.ZipFile(path, "r") as zf:
            if info.sf_entry or info.sig_entry:
                info.v1 = _v1_signer(info.sf_entry, info.sig_entry, zf)
                # real cryptographic chain verification (signature -> .SF ->
                # MANIFEST.MF -> per-entry digests -> coverage)
                from .apkverify import verify_v1_signature

                result, _sf = verify_v1_signature(zf)
                if result is not None:
                    info.v1_verified = result.verified
                    info.v1_reasons = result.reasons
                    info.v1_covered_entries = result.covered_entries
    except (zipfile.BadZipFile, OSError):  # pragma: no cover
        pass

    # signing block ------------------------------------------------------
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        from .apksigv2 import (
            V2_BLOCK_ID,
            V3_BLOCK_ID,
            find_signing_block,
            verify_v2,
            verify_v3,
        )

        block = find_signing_block(data)
        if block is not None:
            for problem in block.layout_problems:
                info.warnings.append(f"signing block: {problem}")
            entries = block.entries
            if V2_BLOCK_ID in entries:
                certs = _v23_certs(entries[V2_BLOCK_ID], want_v3=False)
                names = [n for c in certs for n in common_names_from_der(c)]
                names = names or _v2_signer_names(entries[V2_BLOCK_ID])[0]
                info.v2 = ApkSigner(scheme="v2", names=names, blob=entries[V2_BLOCK_ID])
                res = verify_v2(data, block)
                info.v2_verified = res.verified
                info.v2_reasons = res.reasons
                _apply_signer_cert(info.v2, certs[0] if certs else None)
            for vid in V3X_IDS:
                if vid in entries:
                    certs = _v23_certs(entries[vid], want_v3=True)
                    names = [n for c in certs for n in common_names_from_der(c)]
                    names = names or _v2_signer_names(entries[vid])[0]
                    scheme = {
                        V3_BLOCK_ID: "v3",
                        V31_BLOCK_ID: "v3.1",
                        V32_BLOCK_ID: "v3.2",
                    }[vid]
                    signer = ApkSigner(
                        scheme=scheme,
                        names=names,
                        blob=entries[vid],
                    )
                    _apply_signer_cert(signer, certs[0] if certs else None)
                    info.v3.append(signer)
            if info.v2 or info.v3:
                res = verify_v3(data, block)
                # only trust the outcome when a v3 block actually exists
                info.v3_verified = res.verified if any(
                    v.scheme == "v3" for v in info.v3
                ) else None
                if info.v3_verified is not None:
                    info.v3_reasons = res.reasons
            # rollback protection banner in the v1 .SF ("X-Android-APK-Signed")
            if info.v1 is not None and (info.v2 is not None or info.v3):
                info.rollback_protected = _sf_rollback_banner(path, info.sf_entry)
            # Janus layout check: every central-directory entry's local-header
            # offset must point at a real local file header signature
            eocd = _find_eocd(data)
            info.zip_layout_anomalies = _zip_layout_anomalies(data, eocd)
    except (ApkError, OSError, struct.error) as exc:
        info.warnings.append(f"signing block: {exc}")

    names = info.all_signer_names()
    info.debug_signed = any("debug" in n.lower() for n in names)
    info.signer_fingerprints = sorted(
        {
            s.cert_sha256
            for _, s in info.signers()
            if s.cert_sha256
        }
    )
    return info


def _sf_rollback_banner(path: str, sf_entry: Optional[str]) -> bool:
    """True when the v1 ``.SF`` declares the whole-file scheme banner.

    Android (apksig) writes ``X-Android-APK-Signed: 2 ...`` into the .SF
    main section when a whole-file scheme also protects the APK. Its
    absence on a v1+v2 APK is the classic rollback vector.
    """
    try:
        with zipfile.ZipFile(path, "r") as zf:
            if sf_entry is None:
                return False
            sf_bytes = zf.read(sf_entry)
        text = sf_bytes.decode("utf-8", "replace")
    except (zipfile.BadZipFile, KeyError, OSError):
        return False
    for chunk in text.split("\r"):
        for line in chunk.split("\n"):
            line = line.strip()
            if line.upper().startswith("X-ANDROID-APK-SIGNED:"):
                value = line.split(":", 1)[1].strip()
                ids = {t.strip() for t in value.split(",")}
                return "2" in ids or "3" in ids or "3.1" in ids
    return False


def _zip_layout_anomalies(data: bytes, eocd_pos: int, max_report: int = 4) -> List[str]:
    """Point out central-directory entries whose local header is misplaced.

    In a genuine ZIP each central-directory record's ``local header offset``
    must select the bytes ``PK\\x03\\x04``. Janus-class tampering glues an
    extra executable header on top of a section of entry data and repoints
    the central directory, which surfaces here.
    """
    if eocd_pos < 24 or eocd_pos + 22 > len(data):
        return []
    try:
        (cd_offset,) = struct.unpack_from("<I", data, eocd_pos + 16)
        (entry_count,) = struct.unpack_from("<H", data, eocd_pos + 10)
    except struct.error:
        return []
    if cd_offset < 4 or cd_offset > len(data) - 46:
        return []
    anomalies: List[str] = []
    pos = cd_offset
    for i in range(min(entry_count, 65535)):
        if pos + 46 > len(data) or data[pos : pos + 4] not in (b"PK\x01\x02",):
            break                                  # ran into the signing block / junk
        try:
            (name_len,) = struct.unpack_from("<H", data, pos + 28)
            (extra_len,) = struct.unpack_from("<H", data, pos + 30)
            (comment_len,) = struct.unpack_from("<H", data, pos + 32)
            (local_off,) = struct.unpack_from("<I", data, pos + 42)
        except struct.error:
            break
        name_bytes = data[pos + 46 : pos + 46 + name_len]
        try:
            name = name_bytes.decode("utf-8", "replace")
        except Exception:  # pragma: no cover - decode with replace never raises
            name = name_bytes.hex()
        if 0 <= local_off < len(data):
            if data[local_off : local_off + 4] != b"PK\x03\x04":
                anomalies.append(
                    f"entry {name!r}: local header offset {local_off} "
                    "does not point at a local file header"
                )
        else:
            anomalies.append(
                f"entry {name!r}: local header offset {local_off} "
                "lies outside the archive"
            )
        if len(anomalies) >= max_report:
            return anomalies
        pos += 46 + name_len + extra_len + comment_len
    return anomalies


def _safe_size(path: str) -> int:
    try:
        import os
        return os.path.getsize(path)
    except OSError:  # pragma: no cover
        return 0


def unpack_apk(path: str, dest: str) -> ApkInfo:
    """Extract the APK into ``dest`` (which is created if missing)."""
    import os
    import shutil

    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    info = load_apk(path)
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                zf.extract(member, dest)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        info.warnings.append(f"unpack: {exc}")
    return info

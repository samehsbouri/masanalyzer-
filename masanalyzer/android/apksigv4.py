"""APK v4 signature sidecar (``.idsig``) parsing + signer cross-check.

APK v4 signs the verity Merkle hash tree of the APK contents and ships it
next to the APK as ``<apk-name>.idsig`` alongside incremental install
metadata.  The file embeds the *signing certificate*, which lets us answer
questions nobody else tools:

* is the sidecar actually signed by the same key as the APK's v1/v2/v3
  signers?  A mismatched or stale ``.idsig`` is exactly what happens when
  someone rebuilds the APK but ships yesterday's sidecar - an incremental
  install would reject the update.
* do the declared tree/digest shape (chunk size, expected leaf count)
  match the APK size for which the sidecar was generated?

Wire format handled here (header fields are tolerant):

    magic  "APKV" (4B) followed by u32 version (the v4 sidecar scheme)
    u32    version
    u32    chunk_size           (leaf block size, typically 4096)
    u32    digest_size          (bytes per digest, typically 32 = SHA-256)
    u32    tree_offset, tree_size
    u32    digest_offset, digest_size
    u32    signer_offset, signer_size
    u32    cert_offset, cert_size      (DER X.509 leaf)
    u32    key_hint_offset, key_hint_size
Followed by the binary sections; the header is fixed-width so offsets are
absolute file offsets.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAGIC = b"APKV"          # 4-byte magic (the "APKV4" scheme, little/big end)
_KNOWN_VERSIONS = {1}
DEFAULT_CHUNK_SIZE = 4096
DEFAULT_DIGEST_SIZE = 32


class IdsigError(Exception):
    pass


@dataclass
class IdsigInfo:
    """Parsed ``.idsig`` sidecar contents."""

    path: str
    apk_size: int = 0
    version: int = 1
    chunk_size: int = DEFAULT_CHUNK_SIZE
    digest_size: int = DEFAULT_DIGEST_SIZE
    tree_offset: int = 0
    tree_size: int = 0
    digest_offset: int = 0
    digest_size_field: int = 0
    signer_offset: int = 0
    signer_size: int = 0
    cert_offset: int = 0
    cert_size: int = 0
    cert_der: Optional[bytes] = None
    cert_sha256: str = ""
    warnings: List[str] = field(default_factory=list)
    # set by cross_check(): certificate matches the APK's signers
    signer_match: Optional[bool] = None
    # structural sanity: tree size >= expected leaf-level bytes for apk_size
    tree_shape_ok: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": os.path.basename(self.path),
            "version": self.version,
            "chunk_size": self.chunk_size,
            "digest_size": self.digest_size,
            "cert_sha256": self.cert_sha256,
            "signer_match": self.signer_match,
            "tree_shape_ok": self.tree_shape_ok,
            "warnings": list(self.warnings),
        }


_HEADER_UNPACK = ">4sI"


def parse_idsig(path: str, apk_size: int = 0) -> IdsigInfo:
    """Parse an ``.idsig`` file (tolerant header, best-effort cert extract)."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 60:
        raise IdsigError("idsig too short")
    magic, version = struct.unpack_from(">4sI", blob, 0)
    if magic != MAGIC:
        raise IdsigError(f"bad magic {magic!r} (expected {MAGIC!r})")
    if version not in _KNOWN_VERSIONS:
        raise IdsigError(f"unsupported idsig version {version}")

    fields = struct.unpack_from(">10I", blob, 8)
    (
        chunk_size, digest_size,
        tree_offset, tree_size,
        digest_offset, digest_bytes,
        signer_offset, signer_size,
        cert_offset, cert_size,
    ) = fields
    info = IdsigInfo(
        path=path,
        apk_size=apk_size,
        version=version,
        chunk_size=chunk_size or DEFAULT_CHUNK_SIZE,
        digest_size=digest_size or DEFAULT_DIGEST_SIZE,
        tree_offset=tree_offset,
        tree_size=tree_size,
        digest_offset=digest_offset,
        digest_size_field=digest_bytes,
        signer_offset=signer_offset,
        signer_size=signer_size,
        cert_offset=cert_offset,
        cert_size=cert_size,
    )
    if cert_offset and cert_size and cert_offset + cert_size <= len(blob):
        info.cert_der = blob[cert_offset : cert_offset + cert_size]
        info.cert_sha256 = hashlib.sha256(info.cert_der).hexdigest()
    else:  # pragma: no cover - tolerated
        info.warnings.append("certificate section missing or out of bounds")
    info.tree_shape_ok = _tree_shape_ok(info)
    return info


def _tree_shape_ok(info: IdsigInfo) -> Optional[bool]:
    """Tree must be at least the leaf level for the declared apk size."""
    if not info.tree_size or not info.apk_size:
        return None
    leaves = (info.apk_size + info.chunk_size - 1) // info.chunk_size
    return info.tree_size >= leaves * info.digest_size


def find_idsig_path(apk_path: str) -> Optional[str]:
    """Common sidecar names: ``app.apk.idsig``."""
    candidates = [apk_path + ".idsig"]
    root, _ext = os.path.splitext(apk_path)
    candidates.append(root + ".idsig")
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def cross_check(info: IdsigInfo, signer_fingerprints: List[str]) -> IdsigInfo:
    """Compare the sidecar's cert fingerprint against the APK signers."""
    norm: set = {f.lower() for f in signer_fingerprints if f}
    if not info.cert_sha256 or not norm:
        info.signer_match = None
    elif info.cert_sha256.lower() in norm:
        info.signer_match = True
    else:
        info.signer_match = False
        info.warnings.append(
            "sidecar certificate does not match any APK signing certificate"
        )
    return info

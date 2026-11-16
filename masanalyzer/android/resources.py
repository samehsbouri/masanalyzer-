"""Android resource layer.

Two things live here:

1. A minimal ``resources.arsc`` reader.  The table format starts with a
   ``RES_TABLE_TYPE`` header, a global string pool, then package chunks - we
   only keep the *global string pool* and the package names, which is exactly
   what analyzers need to hunt endpoints / secrets in compiled resources.

2. The ``network_security_config.xml`` model.  This is a normal XML file
   stored (compiled) in ``res/xml/``.  It controls cleartext traffic,
   trust anchors for user-added CAs and certificate pinning - all of which
   are prime OWASP M5/M8 material - so it gets a typed model the analyzers
   can reason about.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .axml import (
    RES_STRING_POOL_TYPE,
    RES_TABLE_TYPE,
    StringPool,
    XmlNode,
    parse_xml_any,
)


# --------------------------------------------------------------------------
# resources.arsc
# --------------------------------------------------------------------------
@dataclass
class ResourceTable:
    strings: List[str] = field(default_factory=list)
    package_names: List[str] = field(default_factory=list)
    string_count: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def has_strings(self) -> bool:
        return bool(self.strings)

    def summary(self) -> Dict[str, Any]:
        return {
            "strings": self.string_count,
            "packages": list(self.package_names),
        }


def parse_resource_table(data: bytes) -> ResourceTable:
    """Parse the header + global string pool of ``resources.arsc``."""
    return _parse(data)


def _parse(data: bytes) -> ResourceTable:
    table = ResourceTable()
    if len(data) < 12:
        table.warnings.append("resources.arsc too small")
        return table

    (chunk_type, header_size, chunk_size) = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_TABLE_TYPE:
        table.warnings.append(f"unexpected arsc chunk type 0x{chunk_type:04x}")
        return table
    (package_count,) = struct.unpack_from("<I", data, 8)

    pos = header_size
    parsed = 0
    while pos + 8 <= len(data) and parsed < package_count + 4:
        (ctype, cheader, csize) = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > len(data) + 8:
            break
        if ctype == RES_STRING_POOL_TYPE:
            try:
                pool = StringPool(data, pos)
                table.strings = [
                    pool.get(i) for i in range(pool.string_count) if pool.get(i)
                ]
                table.string_count = pool.string_count
            except Exception as exc:  # pragma: no cover - fuzz tolerance
                table.warnings.append(f"string pool: {exc}")
            pos += csize
            continue
        if ctype == 0x0200:  # RES_TABLE_PACKAGE_TYPE
            (pid,) = struct.unpack_from("<I", data, pos + 8)
            # name: 256-byte UTF-16 field
            raw_name = data[pos + 12 : pos + 12 + 256]
            name = raw_name.decode("utf-16-le", "ignore").split("\x00")[0]
            if name:
                table.package_names.append(name)
            pos += csize
            continue
        pos += max(csize, 8)
        parsed += 1
    return table


#: RES_TABLE_TYPE value types
RES_VALUE_STRING = 0x03
#: RES_TABLE_TYPE (type-chunk) entry flags: 0x0001 = COMPLEX (no raw value)
_ENTRY_COMPLEX = 0x0001


#: RES_VALUE data types that carry an ARGB colour
_COLOR_TYPES = (0x1C, 0x1D, 0x1E, 0x1F)


def resource_strings(data: bytes) -> Dict[int, str]:
    """Map full resource ids (``0x7f14006b``) to their string values.

    Walks the ``RES_TABLE_PACKAGE`` chunks and, inside them, every
    ``RES_TABLE_TYPE`` (0x0201) chunk: simple entries whose value type is
    STRING point at the global string pool, and
    ``id = package << 24 | type << 16 | entry`` identifies the resource.
    Only *default-config* style entries are kept (first occurrence wins),
    which is exactly what app labels need.  Best-effort by design:
    malformed or sparse tables resolve to ``{}`` and never raise.
    """
    return _collect(data)[0]


def resource_colors(data: bytes) -> Dict[int, int]:
    """Map resource ids to ARGB colour values (``0xAARRGGBB``).

    Adaptive icons often name a colour resource for their background layer;
    this is the only way to recover it without a full ``aapt``.
    """
    return _collect(data)[1]


def _collect(
        data: bytes) -> Tuple[Dict[int, str], Dict[int, int]]:
    """One pass over the table: ``(string values, colour values)``."""
    strings_out: Dict[int, str] = {}
    colors_out: Dict[int, int] = {}
    try:
        strings = parse_resource_table(data).strings or []
        (chunk_type, header_size, chunk_size) = struct.unpack_from(
            "<HHI", data, 0)
        pos = header_size
        end = min(len(data), chunk_size) if chunk_size else len(data)
        while pos + 8 <= end:
            (ctype, cheader, csize) = struct.unpack_from("<HHI", data, pos)
            if csize < 8:
                break
            if ctype == 0x0200:  # RES_TABLE_PACKAGE_TYPE
                _walk_package(data, pos, csize, strings, strings_out,
                              colors_out)
            if pos + csize <= pos:  # safety: never stall
                break
            pos += csize
    except Exception:  # noqa: BLE001 - resolver is best-effort
        return strings_out, colors_out
    return strings_out, colors_out


def _walk_package(
    data: bytes,
    pkg_pos: int,
    pkg_size: int,
    strings: List[str],
    out: Dict[int, str],
    colors: Optional[Dict[int, int]] = None,
) -> None:
    """Collect string-valued entries from one package chunk."""
    (package_id,) = struct.unpack_from("<I", data, pkg_pos + 8)
    # sub-chunks begin at the type-string pool (ResTable_package header is
    # 12 bytes + 256-byte name + 4 u32 fields = 284, aapt standard)
    (type_strings_off,) = struct.unpack_from("<I", data, pkg_pos + 268)
    pos = pkg_pos + (type_strings_off if type_strings_off else 284)
    pkg_end = pkg_pos + pkg_size
    # Some packers/obfuscators overstate chunk sizes; the loop stays bounded
    # by min(pkg_end, len(data)) and _walk_type_chunk re-validates offsets.
    while pos + 8 <= min(pkg_end, len(data)):
        (ctype, cheader, csize) = struct.unpack_from("<HHI", data, pos)
        if csize < 8:
            break
        if ctype == 0x0201:  # RES_TABLE_TYPE
            _walk_type_chunk(
                data, pos, csize, package_id, strings, out, colors)
        pos += csize


def _walk_type_chunk(
    data: bytes,
    pos: int,
    csize: int,
    package_id: int,
    strings: List[str],
    out: Dict[int, str],
    colors: Optional[Dict[int, int]] = None,
) -> None:
    """One RES_TABLE_TYPE chunk: entries -> global string pool."""
    type_id = data[pos + 8]
    (entry_count,) = struct.unpack_from("<I", data, pos + 12)
    (entries_start,) = struct.unpack_from("<I", data, pos + 16)
    (_ctype, header_size, _csize) = struct.unpack_from("<HHI", data, pos)
    offsets_base = pos + header_size
    entries_base = pos + entries_start
    if entry_count > 100000 or entries_base >= pos + csize:
        return  # implausible — corrupt table, bail silently
    for i in range(entry_count):
        try:
            (offset,) = struct.unpack_from("<I", data, offsets_base + 4 * i)
        except struct.error:
            return
        if offset == 0xFFFFFFFF:
            continue  # NO_ENTRY marker; offset 0 is a real (first) entry
        entry_pos = entries_base + offset
        if entry_pos + 8 > len(data):
            continue
        try:
            (_esize, eflags) = struct.unpack_from("<HH", data, entry_pos)
            if eflags & _ENTRY_COMPLEX:
                continue
            # entry header: size(2) flags(2) key(4); the raw value follows it
            value_pos = entry_pos + (max(_esize, 8))
            (_vsize, _res0, data_type) = struct.unpack_from("<HBB", data,
                                                            value_pos)
            (raw,) = struct.unpack_from("<I", data, value_pos + 4)
        except struct.error:
            continue
        res_id = (package_id << 24) | (type_id << 16) | i
        if data_type == RES_VALUE_STRING:
            if 0 <= raw < len(strings):
                out.setdefault(res_id, strings[raw])
        elif colors is not None and data_type in _COLOR_TYPES:
            colors.setdefault(res_id, raw)


# --------------------------------------------------------------------------
# Network Security Config (res/xml/network_security_config.xml)
# --------------------------------------------------------------------------
@dataclass
class TrustAnchor:
    source: str = ""                    # "system" | "user" | file path
    override_pins: bool = False


@dataclass
class DomainConfig:
    domains: List[str] = field(default_factory=list)
    cleartext: Optional[bool] = None
    trust_anchors: List[TrustAnchor] = field(default_factory=list)
    pins: List[str] = field(default_factory=list)

    @property
    def allows_user_certs(self) -> bool:
        return any(a.source == "user" for a in self.trust_anchors)

    @property
    def no_pins(self) -> bool:
        return not self.pins

    def summary(self) -> Dict[str, Any]:
        return {
            "domains": list(self.domains),
            "cleartext": self.cleartext,
            "trust_anchors": [a.source for a in self.trust_anchors],
            "pins": len(self.pins),
        }


@dataclass
class NetworkSecurityConfig:
    cleartext_permitted: Optional[bool] = None
    trust_anchors: List[TrustAnchor] = field(default_factory=list)
    domains: List[DomainConfig] = field(default_factory=list)
    pins: List[str] = field(default_factory=list)
    present: bool = False
    path: Optional[str] = None

    @property
    def allows_user_certs(self) -> bool:
        return any(a.source == "user" for a in self.trust_anchors) or any(
            d.allows_user_certs for d in self.domains
        )

    @property
    def has_pins(self) -> bool:
        return bool(self.pins) or any(d.pins for d in self.domains)

    def allows_cleartext(self) -> bool:
        if self.cleartext_permitted is True:
            return True
        return any(d.cleartext is True for d in self.domains)

    def summary(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "cleartext_permitted": self.cleartext_permitted,
            "allows_user_certs": self.allows_user_certs,
            "has_pins": self.has_pins,
            "base_trust_anchors": [a.source for a in self.trust_anchors],
            "domains": [d.summary() for d in self.domains],
        }

    @classmethod
    def parse(cls, data: bytes, path: Optional[str] = None) -> "NetworkSecurityConfig":
        root = parse_xml_any(data)
        if root is None:
            raise ValueError("network security config not decodable")
        node = root if root.tag == "network-security-config" else _find(root)
        conf = cls(present=node is not None, path=path)
        if node is None:
            return conf
        conf._load(node)
        return conf

    def _load(self, node: XmlNode) -> None:
        for tag in node.children:
            if tag.tag == "base-config":
                self._load_base(tag)
            elif tag.tag == "domain-config":
                self.domains.append(self._load_domain(tag))
            elif tag.tag == "debug-overrides":
                for anchor in tag.find_all("trust-anchors"):
                    for cert in anchor.children:
                        src = str(cert.get("src", "") or "")
                        if src == "user":
                            self.trust_anchors.append(TrustAnchor(source="user", override_pins=True))

    def _load_base(self, base: XmlNode) -> None:
        ctp = base.get("cleartextTrafficPermitted")
        if ctp is not None:
            self.cleartext_permitted = str(ctp).strip().lower() in ("true", "1")
        for ta in base.find_all("trust-anchors"):
            for cert in ta.children:
                self.trust_anchors.append(
                    TrustAnchor(
                        source=str(cert.get("src", "") or ""),
                        override_pins=str(cert.get("overridePins", "false")).lower() == "true",
                    )
                )

    def _load_domain(self, node: XmlNode) -> DomainConfig:
        cfg = DomainConfig()
        val = node.get("cleartextTrafficPermitted")
        if val is not None:
            cfg.cleartext = str(val).strip().lower() in ("true", "1")
        for child in node.children:
            if child.tag == "domain":
                cfg.domains.append(str(child.get("name", "") or ""))
            elif child.tag == "trust-anchors":
                for cert in child.children:
                    cfg.trust_anchors.append(
                        TrustAnchor(
                            source=str(cert.get("src", "") or ""),
                            override_pins=str(cert.get("overridePins", "false")).lower() == "true",
                        )
                    )
            elif child.tag == "pin-set":
                for pin in child.find_all("pin"):
                    digest = str(pin.get("digest") or "")
                    value = str(pin.get("value") or "")
                    cfg.pins.append(f"{digest}={value[:24]}")
        return cfg


def _find(root: XmlNode) -> Optional[XmlNode]:
    for n in root.iter():
        if n.tag == "network-security-config":
            return n
    return None


# --------------------------------------------------------------------------
# misc helpers used by packaging/scanner
# --------------------------------------------------------------------------
def string_resources(arsc_path: str) -> List[str]:
    """All string values compiled into ``resources.arsc``."""
    with open(arsc_path, "rb") as fh:
        return parse_resource_table(fh.read()).strings

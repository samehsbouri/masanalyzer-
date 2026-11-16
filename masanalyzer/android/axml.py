"""Pure-Python parser for Android's *binary* XML (AXML) format.

``AndroidManifest.xml`` inside an APK is not text: it is a compiled resource
chunk stream. Commercial pipelines usually shell out to ``apktool`` or
``aapt2`` to read it. This module implements the format directly so the
analyzer still works when the Java toolchain is missing (very common on CI
images and on locked down workstations).

Layout of an AXML document::

    <chunk> RES_XML_TYPE (0x0003)
      <chunk> RES_STRING_POOL_TYPE (0x0001)   # all strings/URIs/attr names
      [<chunk> RES_XML_RESOURCE_MAP_TYPE(0x0180)]
      <chunk> RES_XML_START_NAMESPACE_TYPE (0x0100)
      <chunk> RES_XML_START_TAG_TYPE (0x0102)  # ...
      <chunk> RES_XML_END_TAG_TYPE  (0x0103)
      ...

Every chunk starts with ``(u16 type, u16 header_size, u32 chunk_size)``.

Reference (AOSP): frameworks/base/libs/androidfw/ResourceTypes.cpp
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

# chunk types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_TAG_TYPE = 0x0102
RES_XML_END_TAG_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# string pool flags
SORTED_FLAG = 1 << 0
UTF8_FLAG = 1 << 8

# attribute value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB8 = 0x1D
TYPE_INT_COLOR_ARGB4 = 0x1E
TYPE_INT_COLOR_RGB4 = 0x1F

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AXmlError(Exception):
    """Raised when a binary XML document cannot be decoded."""


# --------------------------------------------------------------------------
# String pool
# --------------------------------------------------------------------------
class StringPool:
    """The RES_STRING_POOL_TYPE chunk."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        (self.chunk_type, self.header_size, self.chunk_size) = struct.unpack_from(
            "<HHI", data, offset
        )
        if self.chunk_type != RES_STRING_POOL_TYPE:
            raise AXmlError(f"expected string pool chunk, got 0x{self.chunk_type:04x}")

        (
            self.string_count,
            self.style_count,
            self.flags,
            self.strings_start,
            self.styles_start,
        ) = struct.unpack_from("<IIIII", data, offset + 8)

        self.utf8 = bool(self.flags & UTF8_FLAG)
        self._data = data
        self._base = offset
        off_base = offset + self.header_size
        self.offsets: List[int] = list(
            struct.unpack_from("<%dI" % self.string_count, data, off_base)
        ) if self.string_count else []
        self._cache: Dict[int, Optional[str]] = {}

    # -- raw decoding -----------------------------------------------------
    @staticmethod
    def _decode_length(data: bytes, pos: int) -> Tuple[int, int]:
        """Decode the AOSP ``decodeLength`` escape (values >= 0x8000)."""
        (length,) = struct.unpack_from("<H", data, pos)
        pos += 2
        if length & 0x8000:
            (hi,) = struct.unpack_from("<H", data, pos)
            pos += 2
            length = ((length & 0x7FFF) << 16) | hi
        return length, pos

    def _read(self, index: int) -> Optional[str]:
        if index >= self.string_count:
            return None
        pos = self._base + self.strings_start + self.offsets[index]
        data = self._data
        if not self.utf8:
            length, pos = self._decode_length(data, pos)
            raw = data[pos : pos + length * 2]
            try:
                return raw.decode("utf-16-le", "replace")
            except Exception:  # pragma: no cover
                return None
        # UTF-8 pools store a character count followed by a byte count. Some
        # obfuscated/rewritten resources only carry the character count and
        # terminate with NUL, so both encodings are attempted.
        try:
            _char_len, pos2 = self._decode_length(data, pos)
            byte_len, pos3 = self._decode_length(data, pos2)
            if byte_len and byte_len < len(data):
                candidate = data[pos3 : pos3 + byte_len]
                if b"\x00" not in candidate.rstrip(b"\x00"):
                    return candidate.decode("utf-8", "replace")
        except struct.error:  # pragma: no cover - truncated
            pass
        try:
            length, pos2 = self._decode_length(data, pos)
            end = data.find(b"\x00", pos2)
            if end < 0:
                end = len(data)
            return data[pos2:end].decode("utf-8", "replace")
        except struct.error:  # pragma: no cover
            return None

    def get(self, index: int) -> Optional[str]:
        if index in self._cache:
            return self._cache[index]
        value = self._read(index)
        self._cache[index] = value
        return value

    def __len__(self) -> int:
        return self.string_count


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------
@dataclass
class XmlAttribute:
    ns: Optional[str]
    name: str
    value: Any
    raw_value: Optional[str] = None
    value_type: int = TYPE_STRING

    @property
    def full_name(self) -> str:
        return f"{self.ns}:{self.name}" if self.ns else self.name

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"{self.full_name}={self.value!r}"


@dataclass
class XmlNode:
    """A decoded XML element."""

    tag: str
    ns: Optional[str] = None
    attributes: Dict[str, XmlAttribute] = field(default_factory=dict)
    children: List["XmlNode"] = field(default_factory=list)
    text: Optional[str] = None
    line: int = 0

    # -- navigation -------------------------------------------------------
    def children_of(self, tag: str) -> List["XmlNode"]:
        return [c for c in self.children if c.tag == tag]

    def child(self, tag: str) -> Optional["XmlNode"]:
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def iter(self) -> Iterator["XmlNode"]:
        yield self
        for c in self.children:
            yield from c.iter()

    def find_all(self, tag: str) -> List["XmlNode"]:
        return list(self.iter()) if tag == "*" else [n for n in self.iter() if n.tag == tag]

    def get(self, name: str, default: Any = None) -> Any:
        """Read an attribute, accepting ``name`` or ``android:name``."""
        if name in self.attributes:
            return self.attributes[name].value
        for suffix in ("android", ""):
            key = f"{suffix}:{name}" if suffix else name
            if key in self.attributes:
                return self.attributes[key].value
        return default

    def has_attr(self, name: str) -> bool:
        return name in self.attributes or f"android:{name}" in self.attributes

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<XmlNode {self.tag} attrs={list(self.attributes)}>"


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
class AXmlParser:
    """Decodes a binary XML buffer into an :class:`XmlNode` tree."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pool: Optional[StringPool] = None
        self.resource_map: List[int] = []
        self.namespaces: Dict[int, Tuple[str, str]] = {}   # id -> (prefix, uri)
        self._ns_stack: List[Tuple[int, int]] = []
        self.root: Optional[XmlNode] = None
        self.warnings: List[str] = []

    # -- helpers ----------------------------------------------------------
    def _string(self, index: int) -> Optional[str]:
        if self.pool is None:
            return None
        if index == 0xFFFFFFFF:
            return None
        return self.pool.get(index)

    def _prefix_for_uri(self, uri: Optional[str]) -> Optional[str]:
        if not uri:
            return None
        if uri == ANDROID_NS:
            return "android"
        for _id, (prefix, mapped) in self.namespaces.items():
            if mapped == uri:
                return prefix
        return None

    # -- chunk handlers ---------------------------------------------------
    def _parse_string_pool(self, offset: int) -> int:
        self.pool = StringPool(self.data, offset)
        return self.pool.chunk_size

    def _parse_resource_map(self, offset: int) -> int:
        (_t, header_size, size) = struct.unpack_from("<HHI", self.data, offset)
        count = (size - header_size) // 4
        self.resource_map = list(struct.unpack_from("<%dI" % count, self.data, offset + header_size))
        return size

    def _parse_namespace(self, offset: int, end: bool) -> int:
        (_t, _hs, size) = struct.unpack_from("<HHI", self.data, offset)
        (line, _comment, prefix_idx, uri_idx) = struct.unpack_from("<IIII", self.data, offset + 8)
        prefix = self._string(prefix_idx)
        uri = self._string(uri_idx)
        if not end and uri:
            ns_id = self._next_ns_id()
            self.namespaces[ns_id] = (prefix or "", uri)
            self._ns_stack.append((ns_id, line))
        elif end and self._ns_stack:
            self._ns_stack.pop()
        return size

    def _next_ns_id(self) -> int:
        return max(self.namespaces.keys(), default=0) + 1

    def _parse_start_tag(self, offset: int) -> Tuple[int, XmlNode]:
        (_t, header_size, size) = struct.unpack_from("<HHI", self.data, offset)
        line = struct.unpack_from("<I", self.data, offset + 8)[0]
        (ns_idx, name_idx, attr_start, _attr_size, attr_count, _id, _class, _style) = (
            struct.unpack_from("<IIHHHHHH", self.data, offset + 16)
        )
        name = self._string(name_idx) or "?"
        ns_uri = self._string(ns_idx)
        node = XmlNode(tag=name, ns=ns_uri, line=line)

        # attribute_start is relative to the start of attrExt, which sits at
        # offset + header_size (after the 16-byte node header).  AAPT/AAPT2
        # always emit attribute_start == 20 == sizeof(attrExt).  Some rewritten
        # AXML files treat it as relative to the chunk start instead, so probe
        # candidates until one of them yields a structurally valid attribute
        # (every real attribute has v_size == 8).
        candidates = [
            offset + header_size + attr_start,  # AOSP convention
            offset + attr_start,                # "relative to chunk start"
        ]
        pos = None
        for cand in candidates:
            if attr_count and cand + 20 <= len(self.data) and cand >= 0:
                (probe_vsize,) = struct.unpack_from("<H", self.data, cand + 12)
                if probe_vsize == 8:
                    pos = cand
                    break
        if pos is None:
            pos = offset + header_size + attr_start
        for _ in range(attr_count):
            if pos + 20 > len(self.data):
                break
            (a_ns, a_name, a_raw, v_size, _res0, v_type, v_data) = struct.unpack_from(
                "<IIIHBBI", self.data, pos
            )
            pos += 20
            attr_name = self._string(a_name) or ""
            attr_ns_uri = self._string(a_ns)
            raw = self._string(a_raw)
            value: Any = None
            if v_type == TYPE_STRING:
                value = self._string(v_data)
            elif v_type == TYPE_INT_BOOLEAN:
                value = v_data != 0
            elif v_type == TYPE_NULL:
                value = None
            elif v_type in (TYPE_REFERENCE, TYPE_ATTRIBUTE, TYPE_DYNAMIC_REFERENCE):
                value = f"@res/0x{v_data:08x}"
            elif v_type == TYPE_FLOAT:
                value = struct.unpack("<f", struct.pack("<I", v_data))[0]
            else:
                value = v_data
            if value is None and raw is not None:
                value = raw
            prefix = self._prefix_for_uri(attr_ns_uri)
            full = f"{prefix}:{attr_name}" if prefix else attr_name
            node.attributes[full] = XmlAttribute(
                ns=prefix, name=attr_name, value=value, raw_value=raw, value_type=v_type
            )
            # also expose the name without prefix for convenience
            node.attributes.setdefault(
                attr_name,
                XmlAttribute(ns=prefix, name=attr_name, value=value, raw_value=raw, value_type=v_type),
            )
        return size, node

    # -- main loop --------------------------------------------------------
    def parse(self) -> Optional[XmlNode]:
        data = self.data
        if len(data) < 8:
            raise AXmlError("truncated AXML document")
        (top_type, top_header, top_size) = struct.unpack_from("<HHI", data, 0)
        if top_type != RES_XML_TYPE:
            raise AXmlError(f"not an XML chunk (type=0x{top_type:04x})")

        pos = top_header
        end = min(top_size if top_size else len(data), len(data))
        stack: List[XmlNode] = []
        root: Optional[XmlNode] = None

        while pos + 8 <= end:
            (ctype, cheader, csize) = struct.unpack_from("<HHI", data, pos)
            if csize == 0:
                break
            try:
                if ctype == RES_STRING_POOL_TYPE:
                    pos += self._parse_string_pool(pos)
                    continue
                if ctype == RES_XML_RESOURCE_MAP_TYPE:
                    pos += self._parse_resource_map(pos)
                    continue
                if ctype == RES_XML_START_NAMESPACE_TYPE:
                    pos += self._parse_namespace(pos, end=False)
                    continue
                if ctype == RES_XML_END_NAMESPACE_TYPE:
                    pos += self._parse_namespace(pos, end=True)
                    continue
                if ctype == RES_XML_START_TAG_TYPE:
                    consumed, node = self._parse_start_tag(pos)
                    if stack:
                        stack[-1].children.append(node)
                    elif root is None:
                        root = node
                    stack.append(node)
                    pos += consumed
                    continue
                if ctype == RES_XML_END_TAG_TYPE:
                    if stack:
                        stack.pop()
                    pos += csize
                    continue
                if ctype == RES_XML_CDATA_TYPE:
                    (_t, hs, size) = struct.unpack_from("<HHI", data, pos)
                    (idx, _sz, _res0, _dtype, _d) = struct.unpack_from("<IIHBI", data, pos + 8)
                    text = self._string(idx)
                    if stack and text:
                        stack[-1].text = (stack[-1].text or "") + text
                    pos += size
                    continue
            except (struct.error, IndexError, AXmlError) as exc:
                self.warnings.append(f"AXML parse stopped at 0x{pos:x}: {exc}")
                break
            # unknown chunk: skip it
            pos += csize if csize > 0 else 8

        self.root = root
        return root


def parse_axml(data: bytes) -> Optional[XmlNode]:
    """Parse binary AXML bytes into an :class:`XmlNode` tree."""
    return AXmlParser(data).parse()


def parse_xml_any(data: bytes) -> Optional[XmlNode]:
    """Parse either a plain text XML or a compiled AXML document."""
    head = data[:8]
    if head[:4] == b"\x03\x00\x08\x00" or b"\x03\x00\x08\x00" in head[:16]:
        return parse_axml(data)
    return parse_plain_xml(data)


def parse_plain_xml(data: bytes) -> Optional[XmlNode]:
    """Fallback for already-decoded (text) XML using the stdlib."""
    import re
    import xml.etree.ElementTree as ET

    text = data.decode("utf-8", "replace")
    _NS_DECLS = {
        "android": "http://schemas.android.com/apk/res/android",
        "tools": "http://schemas.android.com/tools",
    }
    # Manifest snippets are frequently stripped of their xmlns declarations;
    # ElementTree refuses unbound prefixes, so re-add them to the root tag.
    m = re.search(r"<([A-Za-z][\w.\-]*)", text)
    if m:
        close = text.find(">", m.start())
        if close != -1:
            open_tag = text[m.start():close]
            additions = ""
            for prefix, uri in _NS_DECLS.items():
                if f"xmlns:{prefix}=" not in text and re.search(
                    rf"(?<![\w.\-]){prefix}:", text
                ):
                    additions += f' xmlns:{prefix}="{uri}"'
            if additions:
                text = text[:close] + additions + text[close:]

    try:
        elem = ET.fromstring(text)
    except Exception as exc:  # pragma: no cover - malformed input
        raise AXmlError(f"cannot parse plain XML: {exc}") from exc

    def convert(e: ET.Element) -> XmlNode:
        tag = e.tag.split("}")[-1]
        node = XmlNode(tag=tag)
        for k, v in e.attrib.items():
            short = k.split("}")[-1]
            prefix = "android" if k.startswith("{http://schemas.android.com") else None
            node.attributes[short] = XmlAttribute(ns=prefix, name=short, value=v)
            if prefix:
                node.attributes[f"{prefix}:{short}"] = node.attributes[short]
        if e.text and e.text.strip():
            node.text = e.text.strip()
        for child in list(e):
            node.children.append(convert(child))
        return node

    return convert(elem)


def to_xml_text(node: XmlNode, indent: int = 0) -> str:
    """Pretty-print a node tree (useful for debugging and reports)."""
    pad = "  " * indent
    attrs = " ".join(
        f'{a.full_name}="{a.value}"' for a in node.attributes.values() if not a.full_name.endswith(":")
        or a.full_name.startswith("android:")
    )
    # de-duplicate attributes that were stored under two keys
    seen = set()
    parts = []
    for a in node.attributes.values():
        key = a.full_name
        if key in seen:
            continue
        seen.add(key)
        parts.append(f'{key}="{a.value}"')
    attrs = " ".join(parts)
    head = f"{pad}<{node.tag}{' ' + attrs if attrs else ''}>"
    if not node.children and node.text is None:
        return head.replace(">", " />")
    lines = [head]
    if node.text:
        lines.append(f"{pad}  {node.text}")
    lines.extend(to_xml_text(c, indent + 1) for c in node.children)
    lines.append(f"{pad}</{node.tag}>")
    return "\n".join(lines)

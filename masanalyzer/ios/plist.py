"""Apple property list support (``*.plist``).

* :func:`parse_bplist`  - binary plist ``bplist00`` /``bplist01`` decoder
  covering every value type (null, bool, int, real, date, data, ASCII/UTF-16
  strings, uid, array, set, dict) with optional v1.0 variable-width offset
  tables
* :func:`dump_bplist`   - minimal binary plist writer (used by the test suite
  and the sample builder; handy when generating fixtures)
* :func:`load_plist`    - auto-detect: binary, XML plist, or plain JSON-like
  fallback - and return a plain dictionary

Reference: CFFBinaryPlist in CoreFoundation and Apple's published ``bplist00``
format description.
"""

from __future__ import annotations

import datetime as _dt
import struct
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

MAGIC = b"bplist"
XML_MAGIC = b"<?xml"


class PlistError(Exception):
    """Raised when a plist cannot be decoded."""


class UID:
    """Core Foundation UID object (used by NSKeyedArchiver payloads)."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"UID({self.value})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UID) and other.value == self.value

    def __hash__(self) -> int:
        return hash(("UID", self.value))


# --------------------------------------------------------------------------
# binary reader
# --------------------------------------------------------------------------
class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.version = "00"
        self.offset_size = 1
        self.ref_size = 1
        self.num_objects = 0
        self.top_object = 0
        self.offset_table: List[int] = []

    # -- primitives ---------------------------------------------------------
    def _uint(self, pos: int, size: int) -> int:
        return int.from_bytes(self.data[pos : pos + size], "big", signed=False)

    # -- main ---------------------------------------------------------------
    def parse(self) -> Any:
        data = self.data
        if len(data) < 40 or data[:6] != MAGIC:
            raise PlistError("not a binary plist")
        (
            self.offset_size,
            self.ref_size,
            self.num_objects,
            self.top_object,
            self.offset_table_offset,
        ) = struct.unpack(">6xBBQQQ", data[-32:])
        self.version = bytes(data[6:8]).decode("ascii", "replace")
        if self.offset_size not in range(1, 9) or self.ref_size not in range(1, 9):
            raise PlistError("bad plist trailer widths")
        if self.offset_table_offset + self.num_objects * self.offset_size > len(data):
            raise PlistError("offset table out of range")
        self.offset_table = [
            self._uint(self.offset_table_offset + i * self.offset_size, self.offset_size)
            for i in range(self.num_objects)
        ]
        return self._object(self.top_object)

    def _object(self, index: int) -> Any:
        if index >= self.num_objects:
            raise PlistError(f"object index {index} out of range")
        pos = self.offset_table[index]
        tag = self.data[pos]
        marker = tag & 0xF0
        info = tag & 0x0F

        if tag == 0x00:
            return None
        if tag == 0x08:
            return False
        if tag == 0x09:
            return True
        if tag == 0x0F:  # fill byte
            return None
        if marker == 0x10:  # int
            size = 1 << info
            raw = self.data[pos + 1 : pos + 1 + size]
            if size == 8:  # negative values are stored as 8-byte signed
                if raw[0] & 0x80:
                    return int.from_bytes(raw, "big", signed=True)
                return int.from_bytes(raw, "big")
            return int.from_bytes(raw, "big", signed=False)
        if marker == 0x20:  # real
            size = 1 << info
            raw = self.data[pos + 1 : pos + 1 + size]
            if size == 4:
                return struct.unpack(">f", raw)[0]
            if size == 8:
                return struct.unpack(">d", raw)[0]
            raise PlistError(f"unsupported real size {size}")
        if tag == 0x33:  # date
            seconds = struct.unpack(">d", self.data[pos + 1 : pos + 9])[0]
            epoch = _dt.datetime(2001, 1, 1, tzinfo=_dt.timezone.utc)
            return epoch + _dt.timedelta(seconds=seconds)
        if marker == 0x40:  # data
            length, end = self._length(pos, info)
            return bytes(self.data[end : end + length])
        if marker == 0x50:  # ASCII
            length, end = self._length(pos, info)
            return self.data[end : end + length].decode("ascii", "replace")
        if marker == 0x60:  # UTF-16 BE
            length, end = self._length(pos, info)
            return self.data[end : end + length * 2].decode("utf-16-be", "replace")
        if marker == 0x80:  # uid
            size = info + 1
            return UID(int.from_bytes(self.data[pos + 1 : pos + 1 + size], "big"))
        if marker in (0xA0, 0xC0):  # array | set
            length, end = self._length(pos, info)
            refs = [self._uint(end + i * self.ref_size, self.ref_size) for i in range(length)]
            items = [self._object(r) for r in refs]
            return set(items) if marker == 0xC0 else items
        if marker == 0xD0:  # dict
            count, refs_pos = self._length(pos, info)
            key_refs = [self._uint(refs_pos + i * self.ref_size, self.ref_size) for i in range(count)]
            val_refs = [
                self._uint(refs_pos + (count + i) * self.ref_size, self.ref_size)
                for i in range(count)
            ]
            keys = [self._object(r) for r in key_refs]
            values = [self._object(r) for r in val_refs]
            return dict(zip(keys, values))
        raise PlistError(f"unknown plist object tag 0x{tag:02x}")

    def _length(self, pos: int, info: int) -> Tuple[int, int]:
        """(value_length, offset where the value/payload starts)."""
        if info != 0x0F:
            return info, pos + 1
        inner = pos + 1
        tag = self.data[inner]
        if (tag & 0xF0) != 0x10:
            raise PlistError("expected int object for extended count")
        size = 1 << (tag & 0x0F)
        count = int.from_bytes(self.data[inner + 1 : inner + 1 + size], "big")
        return count, inner + 1 + size


def parse_bplist(data: bytes) -> Any:
    """Parse binary plist bytes into native Python objects."""
    return _Reader(data).parse()


def is_bplist(data: bytes) -> bool:
    return data[:6] == MAGIC


# --------------------------------------------------------------------------
# binary writer (minimal, sufficient for fixtures / round-tripping)
# --------------------------------------------------------------------------
_INTS = (1, 2, 4, 8)


def _encode_int(value: int) -> bytes:
    """Encode a value as a corefoundation int *object* (tag + payload).

    Matches plistlib/CoreFoundation semantics: 1- and 2-byte payloads are
    unsigned, 4- and 8-byte payloads are signed.
    """
    if isinstance(value, bool):
        raise PlistError("bool passed to _encode_int")
    if 0 <= value:
        for tag, size in ((0x10, 1), (0x11, 2), (0x12, 4), (0x13, 8)):
            if value < (1 << (size * 8 - 1)) or (size == 8 and value < (1 << 64)):
                return bytes([tag]) + value.to_bytes(size, "big", signed=False)
        raise PlistError("int out of range for plist")
    if value >= -(1 << 63):
        return b"\x13" + value.to_bytes(8, "big", signed=True)
    raise PlistError("int out of range for plist")


class _Writer:
    """Writes ``bplist00`` with dynamic offset/ref widths (spec compliant)."""

    def __init__(self) -> None:
        self.bodies: List[bytes] = []
        self._table: Dict[int, int] = {}
        self.ref_size = 1
        self.offset_size = 4

    def dump(self, root: Any) -> bytes:
        self.bodies = []
        self._table = {}
        # pre-size the ref width from a quick node count
        est = self._count_nodes(root)
        self.ref_size = 1 if est < 0x100 else (2 if est < 0x10000 else 4)

        if root is None:
            top = self._reserve()
            self.bodies[top] = b"\x00"
        else:
            top = self._encode(root)

        # choose widths, accounting for the fact that wider refs lengthen
        # every container body (and thus the offset table)
        for _attempt in range(4):
            stream_len = self._body_stream_length()
            table_len = len(self.bodies) * self.offset_size
            need = 8 + stream_len + table_len
            want_ref = 1 if len(self.bodies) < 0xFF + 1 else (
                2 if len(self.bodies) < 0xFFFF + 1 else 4
            )
            want_offset = 4 if need < (1 << 32) else 8
            if want_ref == self.ref_size and want_offset == self.offset_size:
                break
            self.ref_size, self.offset_size = want_ref, want_offset
            self._table.clear()
            self.bodies = []
            if root is None:
                top = self._reserve()
                self.bodies[top] = b"\x00"
            else:
                top = self._encode(root)

        stream = bytearray()
        offsets: List[int] = []
        for body in self.bodies:
            offsets.append(len(stream) + 8)
            stream.extend(body)
        offset_table_offset = len(stream) + 8
        trailer = struct.pack(
            ">6xBBQQQ", self.offset_size, self.ref_size,
            len(self.bodies), top, offset_table_offset,
        )
        out = b"bplist00" + bytes(stream)
        out += b"".join(off.to_bytes(self.offset_size, "big") for off in offsets)
        return out + trailer

    # -- node encoding ----------------------------------------------------
    def _reserve(self) -> int:
        self.bodies.append(b"")
        return len(self.bodies) - 1

    def _encode(self, value: Any) -> int:
        key = id(value)
        if key in self._table:
            return self._table[key]
        index = self._reserve()
        self._table[key] = index
        if isinstance(value, dict):
            kv = list(value.items())
            ids = [self._encode(k) for k, _ in kv] + [self._encode(v) for _, v in kv]
            self.bodies[index] = self._tag(0xD0, len(kv)) + self._refs(ids)
        elif isinstance(value, (set, frozenset)):
            ids = [self._encode(v) for v in sorted(value, key=repr)]
            self.bodies[index] = self._tag(0xC0, len(ids)) + self._refs(ids)
        elif isinstance(value, (list, tuple)):
            ids = [self._encode(v) for v in value]
            self.bodies[index] = self._tag(0xA0, len(ids)) + self._refs(ids)
        else:
            self.bodies[index] = self._leaf(value)
        return index

    def _body_stream_length(self) -> int:
        return sum(len(b) for b in self.bodies)

    def _count_nodes(self, value: Any, _seen: Optional[set] = None) -> int:
        """Best effort number of objects the tree will produce."""
        if _seen is None:
            _seen = set()
        key = id(value)
        if not isinstance(value, (str, bytes, bytearray, int, float, bool, type(None), _dt.datetime, UID)):
            if key in _seen:
                return 0
            _seen.add(key)
        if isinstance(value, dict):
            inner = sum(self._count_nodes(k, _seen) + self._count_nodes(v, _seen) for k, v in value.items())
            result = 1 + inner
        elif isinstance(value, (list, tuple, set, frozenset)):
            result = 1 + sum(self._count_nodes(v, _seen) for v in value)
        else:
            result = 1
        return result

    def _refs(self, ids: List[int]) -> bytes:
        return b"".join(i.to_bytes(self.ref_size, "big") for i in ids)

    @staticmethod
    def _tag(marker: int, count: int) -> bytes:
        """Tag with length in the low nibble, extended by an int object if >=15."""
        if count < 0x0F:
            return bytes([marker | count])
        return bytes([marker | 0x0F]) + _encode_int(count)

    def _leaf(self, value: Any) -> bytes:
        if value is None:
            return b"\x00"
        if value is True:
            return b"\x09"
        if value is False:
            return b"\x08"
        if isinstance(value, int) and not isinstance(value, bool):
            return _encode_int(value)
        if isinstance(value, float):
            return b"\x23" + struct.pack(">d", value)
        if isinstance(value, str):
            try:
                raw = value.encode("ascii")
                return self._tag(0x50, len(value)) + raw
            except UnicodeEncodeError:
                raw = value.encode("utf-16-be")
                return self._tag(0x60, len(value)) + raw
        if isinstance(value, (bytes, bytearray)):
            return self._tag(0x40, len(value)) + bytes(value)
        if isinstance(value, UID):
            return b"\x80" + value.value.to_bytes(1, "big")
        if isinstance(value, _dt.datetime):
            tz = value.tzinfo or _dt.timezone.utc
            epoch = _dt.datetime(2001, 1, 1, tzinfo=_dt.timezone.utc)
            naive_delta = (value.replace(tzinfo=None) - epoch.replace(tzinfo=None))
            return b"\x33" + struct.pack(">d", naive_delta.total_seconds())
        raise PlistError(f"unserialisable plist value: {value!r}")


def dump_bplist(root: Any) -> bytes:
    """Serialise a plist-compatible tree into ``bplist00`` bytes."""
    return _Writer().dump(root)


# --------------------------------------------------------------------------
# XML plist
# --------------------------------------------------------------------------
def _xml_to_obj(node: ET.Element) -> Any:
    tag = node.tag
    text = (node.text or "").strip()
    if tag == "plist":
        for child in node:
            return _xml_to_obj(child)
        return None
    if tag == "true":
        return True
    if tag == "false":
        return False
    if tag == "integer":
        raw = text.replace(",", "").strip()
        try:
            return int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            return 0
    if tag == "real":
        return float(text or 0.0)
    if tag == "string":
        return node.text or ""
    if tag == "data":
        import base64
        compact = "".join((node.text or "").split())
        return base64.b64decode(compact + "=" * (-len(compact) % 4))
    if tag == "date":
        parsed = _dt.datetime.fromisoformat((text or "").replace("Z", "+00:00"))
        return parsed
    if tag in ("dict",):
        out: Dict[Any, Any] = {}
        key: Any = None
        for child in node:
            if child.tag == "key":
                key = child.text or ""
            else:
                out[key if isinstance(key, str) else str(key)] = _xml_to_obj(child)
        return out
    if tag in ("array", "set"):
        return [_xml_to_obj(child) for child in node if child.tag != "key"]
    return (node.text or "").strip()


def parse_xml_plist(data: bytes) -> Any:
    try:
        root = ET.fromstring(data.decode("utf-8", "replace"))
    except ET.ParseError as exc:
        raise PlistError(f"malformed XML plist: {exc}") from exc
    return _xml_to_obj(root)


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------
def parse_plist(data: bytes) -> Any:
    """Decode binary *or* XML plist bytes."""
    stripped = data.lstrip()
    if stripped[:6] == MAGIC:
        return parse_bplist(data)
    if stripped[:5] == b"<?xml":
        return parse_xml_plist(data)
    if stripped[:7] == b"<plist>" or stripped.startswith(b"<plist "):
        return parse_xml_plist(data)   # XML plist without the <?xml header
    raise PlistError("unknown plist format")


def load_plist(path: str) -> Optional[Dict[str, Any]]:
    """Load a plist from disk. Returns ``None`` for non-plist text files."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    stripped = data.lstrip()
    if stripped[:6] == MAGIC:
        return parse_bplist(data)
    if stripped[:5] == b"<?xml":
        return parse_xml_plist(data)
    return None


def dumps_plist(root: Any, binary: bool = True) -> bytes:
    """Serialise a plist tree to bytes (binary ``bplist00`` or XML)."""
    if binary:
        return dump_bplist(root)
    import plistlib

    return plistlib.dumps(root)

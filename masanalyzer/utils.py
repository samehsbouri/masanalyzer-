"""Small helpers shared across the package (entropy, hashing, paths)."""

from __future__ import annotations

import hashlib
import math
import os
import re
import string
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

PRINTABLE = set(string.printable)
CONTROL = {c for c in range(0x20)} | {0x7F}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def charset_of(value: str) -> str:
    """Coarse character-class signature used to classify candidate secrets."""
    sig = []
    if any(c.islower() for c in value):
        sig.append("lower")
    if any(c.isupper() for c in value):
        sig.append("upper")
    if any(c.isdigit() for c in value):
        sig.append("digit")
    if any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?|\\`~" for c in value):
        sig.append("special")
    if any(c in "+/=" for c in value):
        sig.append("b64")
    return "+".join(sig) or "unknown"


BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def looks_like_base64(value: str, min_len: int = 16) -> bool:
    v = value.strip()
    return len(v) >= min_len and BASE64_RE.match(v) is not None


def looks_like_hex(value: str, min_len: int = 16) -> bool:
    v = value.strip()
    return len(v) >= min_len and HEX_RE.match(v) is not None


def extract_printable_strings(
    data: bytes, min_len: int = 5, limit: int = 20000
) -> Iterator[Tuple[int, str]]:
    """Yield ``(offset, ascii_string)`` pairs from raw bytes.

    Mimics the behaviour of the Unix ``strings`` utility for printable ASCII
    so the tool keeps working when radare2/binutils are unavailable.
    """
    produced = 0
    start = None
    buf = bytearray()
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if start is None:
                start = i
            buf.append(b)
        else:
            if start is not None and len(buf) >= min_len:
                yield start, buf.decode("ascii", "replace")
                produced += 1
                if produced >= limit:
                    return
            start = None
            buf.clear()
    if start is not None and len(buf) >= min_len:
        yield start, buf.decode("ascii", "replace")


def utf16_strings(data: bytes, min_len: int = 5, limit: int = 5000) -> Iterator[Tuple[int, str]]:
    """Yield UTF-16LE printable strings (common in .NET/Java resources)."""
    produced = 0
    try:
        text = data.decode("utf-16-le", "ignore")
    except Exception:  # pragma: no cover - defensive
        return
    start = None
    buf: List[str] = []
    for idx, ch in enumerate(text):
        if ch in PRINTABLE and ch not in "\n\r\t":
            if start is None:
                start = idx * 2
            buf.append(ch)
        else:
            if start is not None and len(buf) >= min_len:
                yield start, "".join(buf)
                produced += 1
                if produced >= limit:
                    return
            start = None
            buf = []
    if start is not None and len(buf) >= min_len:
        yield start, "".join(buf)


def chunked(seq: Sequence, size: int) -> Iterator[Sequence]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def safe_relpath(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:  # pragma: no cover - different drives on Windows
        return os.path.basename(path)


def read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    """Read an unsigned LEB128 value (used by DEX)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result & 0xFFFFFFFF, pos


def read_sleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= 1 << shift
            break
    return result, pos


def is_probably_binary(data: bytes, sample: int = 4096) -> bool:
    head = data[:sample]
    if b"\x00" in head:
        return True
    if not head:
        return False
    readable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return readable / len(head) < 0.85


def unique(items: Iterable) -> List:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}TB"


def truncate(text: str, limit: int = 200) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."

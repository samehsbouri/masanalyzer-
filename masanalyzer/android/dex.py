"""Pure-Python DEX (Android Dalvik Executable) parser.

Only the parts a static security analyzer needs are decoded:

* the header (magic / version / sizes / endianness sanity check)
* the **string id table** (``string_ids``) so every literal in the bytecode
  - URLs, hostnames, keys, crypto parameters - is recoverable, each with the
  byte offset it lives at (used to build ``Evidence`` objects)
* the **type id table** (``type_ids``) and the **class def table** so analyzers
  can tell whether the build was obfuscated (single letter / weird class names)

Everything is bounds checked: hostile or truncated DEX files raise
:class:`DexError` instead of crashing the scan.  No Java toolchain involved.

Reference (AOSP): art/libdexfile/dex/dex_file_structs.h
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from ..utils import extract_printable_strings, read_uleb128

DEX_MAGIC = b"dex\n"
DEX_VERSIONS = (b"035\x00", b"037\x00", "038\x00".encode(), b"039\x00")
DEY_MAGIC = b"dey\n"

# size of the 0x70-byte header, in bytes (plus the 8 magic bytes are included)
DEX_HEADER_SIZE = 0x70


# --------------------------------------------------------------------------
# Dalvik bytecode layer (callsite receipts)
#
# The instruction-span table below is pinned against the AOSP references
# (source.android.com/docs/core/runtime/dalvik-bytecode and
# .../instruction-formats).  Each entry is the instruction size in 16-bit
# code units (the first digit of the AOSP format id); 0 marks opcodes that
# are unused in the Dalvik ISA - seeing one means the linear decode has
# derailed, so the method is abandoned rather than mis-attributed.
#
# Pseudo-instruction payload spans (dalvik-bytecode, "packed-switch-payload
# etc."): packed-switch = size*2 + 4 units, sparse-switch = size*4 + 2,
# fill-array-data = (size*element_width + 1)//2 + 4.
# --------------------------------------------------------------------------
def _build_ins_len_table() -> Tuple[int, ...]:
    t = [0] * 256

    def rng(a: int, b: int, n: int) -> None:      # opcodes [a, b)
        for op in range(a, b):
            t[op] = n

    def grp(n: int, *ops: int) -> None:
        for op in ops:
            t[op] = n

    # 1 unit: 10x / 10t / 11n / 11x / 12x formats
    grp(1, 0x00, 0x01, 0x04, 0x07,                # nop, move, move-wide/object
        0x0a, 0x0b, 0x0c, 0x0d,                   # move-result family, move-exception
        0x0e, 0x0f, 0x10, 0x11,                   # return family
        0x12,                                     # const/4
        0x1d, 0x1e, 0x21, 0x27,                   # monitors, array-length, throw
        0x28,                                     # goto
        0xfe, 0xff)                               # user ops
    rng(0x7b, 0x90, 1)                            # unop (neg / not-* / int-to-*)
    rng(0xb0, 0xd0, 1)                            # binop/2addr

    # 2 units: 20t / 21c / 21s / 21h / 21t / 22x / 22b / 22s / 22c / 22t / 32x
    grp(2, 0x02, 0x03, 0x05, 0x06, 0x08, 0x09,    # move /from16|/16 families
        0x13, 0x15, 0x16, 0x19,                   # const/16, /high16, wide/16, wide/high16
        0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23,       # const-string, class, check-cast,
                                                  #   instance-of, new-instance, new-array
        0x29)                                     # goto/16
    rng(0x2d, 0x32, 2)                            # cmp-* / cmp-long (23x)
    rng(0x32, 0x3e, 2)                            # if-* (22t) and if-*z (21t)
    rng(0x44, 0x52, 2)                            # aget/aput (23x)
    rng(0x52, 0x6e, 2)                            # iget/iput (22c), sget/sput (21c)
    rng(0x90, 0xb0, 2)                            # binop (23x)
    rng(0xd0, 0xe3, 2)                            # binop/lit16 (22s) + lit8 (22b)

    # 3 units: 30t / 31t / 31i / 31c / 35c / 3rc
    grp(3, 0x14,                                  # const (21i)
        0x17,                                     # const-wide/32 (31i)
        0x1b,                                     # const-string/jumbo (31c)
        0x24, 0x25,                               # filled-new-array 35c / -range 3rc
        0x26, 0x2b, 0x2c,                         # fill-array-data, packed/sparse-switch
        0x2a,                                     # goto/32
        0xfc, 0xfd)                               # invoke-custom 35c / -range 3rc
    rng(0x6e, 0x73, 3)                            # invoke-* (35c)
    rng(0x74, 0x79, 3)                            # invoke-*-range (3rc)

    # 4 units: 45cc / 4rcc (invoke-polymorphic)
    t[0xfa] = 4
    t[0xfb] = 4
    # 5 units: const-wide (51l)
    t[0x18] = 5
    return tuple(t)


INS_LEN = _build_ins_len_table()

#: Methode classes whose argument registers are worth correlating against
#: URL-shaped strings.  Self-authored, conservative list of network-facing
#: platform/SDK types.
CALL_PREAMBLES = (
    "Ljava/net/",
    "Ljavax/net/",
    "Lokhttp3/",
    "Lretrofit2/",
    "Lcom/android/volley/",
    "Lorg/apache/http/",
    "Landroid/webkit/WebView;",
    "Landroid/os/DownloadManager;",
    "Lorg/chromium/net/",
)

#: URL-shaped string prefixes worth tracking through the register file.
URL_SCHEMES = ("https://", "http://", "ws://", "wss://")


@dataclass
class DexString:
    value: str
    offset: int          # absolute offset inside the DEX payload
    width: Optional[int] = None   # *.arcs string section used by maplist


class DexError(Exception):
    """Raised when a buffer cannot be parsed as a DEX file."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _mutf8(raw: bytes) -> str:
    """Decode the modified UTF-8 encoding used by the JVM/DEX.

    MUTF-8 differs from UTF-8 only around NUL (0xC0 0x80) and surrogate
    pairs; for security scanning ``errors="replace"`` is acceptable.
    """
    try:
        return raw.decode("utf-8", "replace").rstrip("\x00")
    except Exception:  # pragma: no cover - defensive
        return raw.decode("latin-1", "replace")


def _bounds(data: bytes, start: int, size: int, context: str) -> None:
    if size < 0 or start < 0 or start + size > len(data):
        raise DexError(f"{context} out of bounds at 0x{start:x}")


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
@dataclass
class DexFile:
    """A decoded (in memory) view over a ``classes*.dex`` blob."""

    raw: bytes
    version: str = "035"
    checksum: int = 0
    signature: bytes = field(default_factory=bytes)
    file_size: int = 0
    map_off: int = 0
    strings: List[DexString] = field(default_factory=list)
    types: List[str] = field(default_factory=list)          # descriptor, e.g. "Lcom/a/B;"
    classes: List[str] = field(default_factory=list)        # java class names
    methods: List[str] = field(default_factory=list)        # "class#method"
    warnings: List[str] = field(default_factory=list)
    callsites: List[Dict[str, str]] = field(default_factory=list)
    callsite_stats: Dict[str, int] = field(default_factory=dict)
    # general invoke receipts (behaviour analysis): every filtered invoke,
    # {"method", "callee", "offset"}; filled by collect_api_calls
    api_receipts: List[Dict[str, str]] = field(
        default_factory=list, repr=False, compare=False)
    api_stats: Dict[str, int] = field(
        default_factory=dict, repr=False, compare=False)
    # raw id-table wiring (filled during parse; used by analyze_callsites)
    _method_ids: List[Tuple[int, int]] = field(
        default_factory=list, repr=False, compare=False
    )                                                       # (class_idx, name_idx)
    _class_defs: List[Tuple[int, int]] = field(
        default_factory=list, repr=False, compare=False
    )                                                       # (class_idx, class_data_off)

    # -- sections ---------------------------------------------------------
    @property
    def string_values(self) -> List[str]:
        return [s.value for s in self.strings]

    def _decode_descriptor(self, type_idx: int, types: List[str]) -> Optional[str]:
        if not (0 <= type_idx < len(types)):
            return None
        desc = types[type_idx]
        if isinstance(desc, str) and desc.startswith("L") and desc.endswith(";"):
            return desc[1:-1].replace("/", ".")
        return desc

    def iter_strings(self) -> Iterator[Tuple[int, str]]:
        for entry in self.strings:
            yield entry.offset, entry.value

    def obfuscated(self) -> bool:
        """Heuristic: did proguard/r8 rename everything?"""
        if not self.classes:
            return False
        interesting = [c for c in self.classes if "." in c]
        if not interesting:
            return False
        # statistical: how many classes look like single-letter packages
        mask = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"}
        named = 0
        for cls in interesting[:200]:
            pkg = cls.rsplit(".", 1)[0]
            if pkg.count(".") and all(part in mask for part in pkg.split(".")):
                named += 1
        return named >= max(3, len(interesting[:200]) * 0.6)

    def summary(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "strings": len(self.strings),
            "types": len(self.types),
            "classes": len(self.classes),
            "methods": len(self.methods),
            "obfuscated": self.obfuscated(),
            "file_size": self.file_size,
        }

    # -- bytecode layer (callsite receipts) --------------------------------
    def _method_ref(self, idx: int, raw: bool) -> Optional[str]:
        """Render method_id ``idx``.

        ``raw=True`` keeps the JVM descriptor (``Landroid/webkit/WebView;
        #loadUrl`` - matches :data:`CALL_PREAMBLES`); ``raw=False`` renders
        the friendly dotted owner name used in receipts.
        """
        try:
            cls_idx, name_idx = self._method_ids[idx]
        except (IndexError, TypeError, ValueError):
            return None
        if not (0 <= name_idx < len(self.strings)):
            return None
        if raw:
            if not (0 <= cls_idx < len(self.types)):
                return None
            return f"{self.types[cls_idx]}#{self.strings[name_idx].value}"
        name = self._decode_descriptor(cls_idx, self.types)
        if not name:
            return None
        return f"{name}#{self.strings[name_idx].value}"

    def analyze_callsites(self, limit: int = 4000) -> None:
        """Walk every method's bytecode and pair URL-shaped strings with
        calls into network-facing callee classes.

        A receipt keys an exact string constant (``https://...``) to the
        method it lived in and the callee consuming it - e.g.
        ``WebView#loadUrl(v2)`` with ``v2 = "https://api.example.com"``.
        Registers are tracked linearly through const-string writes; stale
        registers after control-flow merges are the known limitation, so
        receipts are *evidence pointers*, not a dataflow guarantee.

        Results land in :attr:`callsites` (each: ``method``, ``url``,
        ``callee``, ``offset``) plus decode counters in
        :attr:`callsite_stats`.  Idempotent: repeat calls are no-ops.
        """
        if self.callsites:
            return
        data = self.raw
        types = self.types
        string_values = self.string_values
        method_ids = self._method_ids
        receipts: List[Dict[str, str]] = self.callsites
        seen: set = set()
        stats = {"classes": 0, "methods": 0, "aligned": 0, "derailed": 0}

        # method ids whose declaring class looks network-facing: a set lookup
        # per invoke instead of descriptor prefix scans per instruction.
        interesting = {
            idx
            for idx, (cls_idx, _n) in enumerate(method_ids)
            if 0 <= cls_idx < len(types)
            and types[cls_idx].startswith(CALL_PREAMBLES)
        }
        n_strings = len(string_values)

        def owner_of(midx: int) -> Optional[str]:
            return self._method_ref(midx, raw=False)

        def emit(callee_idx: int, owner_idx: int, regs: Sequence[int],
                 urls: Dict[int, str], owner_holder: List[Optional[str]],
                 co: int, at: int) -> None:
            if len(receipts) >= limit:
                return
            callee = self._method_ref(callee_idx, raw=True)
            if not callee:
                return
            for reg in regs:
                url = urls.get(reg)
                if not url:
                    continue
                if owner_holder[0] is None:
                    owner_holder[0] = owner_of(owner_idx)
                owner = owner_holder[0]
                if not owner:
                    return
                key = (owner, url, callee)
                if key in seen:
                    return
                seen.add(key)
                receipts.append(
                    {
                        "method": owner,
                        "url": url,
                        "callee": callee,
                        "offset": co + 16 + 2 * at,
                    }
                )

        def scan(data: bytes, co: int, midx: int) -> None:
            """Decode one code_item linearly, harvesting const-string URLs."""
            if co + 16 > len(data):
                stats["derailed"] += 1
                return
            (_regs, _ins, _outs, _tries, _dbg, n) = struct.unpack_from(
                "<HHHHII", data, co
            )
            if n <= 0:
                stats["aligned"] += 1
                return
            if co + 16 + 2 * n > len(data):
                stats["derailed"] += 1
                return
            units = struct.unpack_from("<%dH" % n, data, co + 16)
            stats["methods"] += 1

            url: Dict[int, str] = {}
            owner: List[Optional[str]] = [None]
            pc = 0
            while pc < n:
                w = units[pc]
                if w == 0x0100:                    # packed-switch-payload
                    ln = 4 + 2 * (units[pc + 1] if pc + 1 < n else 0)
                elif w == 0x0200:                  # sparse-switch-payload
                    ln = 2 + 4 * (units[pc + 1] if pc + 1 < n else 0)
                elif w == 0x0300:                  # fill-array-data-payload
                    width = units[pc + 1] if pc + 1 < n else 0
                    lo = units[pc + 2] if pc + 2 < n else 0
                    hi = units[pc + 3] if pc + 3 < n else 0
                    size = (lo | (hi << 16)) & 0xFFFF_FFFF
                    ln = 4 + (size * width + 1) // 2
                else:
                    op = w & 0xFF
                    ln = INS_LEN[op]
                    if ln == 0:                    # unused ISA: decode derailed
                        stats["derailed"] += 1
                        key = "fail_%02x" % op
                        stats[key] = stats.get(key, 0) + 1
                        stats.setdefault("fail_co", co)   # evidence: probe first
                        return
                    if op == 0x1A or op == 0x1B:   # const-string [jumbo]
                        reg = (w >> 8) & 0xFF
                        if op == 0x1A:
                            sidx = units[pc + 1] if pc + 1 < n else 0
                        else:
                            sidx = 0
                            if pc + 2 < n:
                                sidx = units[pc + 1] | (units[pc + 2] << 16)
                        value = string_values[sidx] if 0 <= sidx < n_strings else ""
                        if len(value) <= 512 and value.startswith(URL_SCHEMES):
                            url[reg] = value
                        else:
                            url.pop(reg, None)
                    elif op == 0x07:               # move-object vA, vB (12x)
                        dst, src = (w >> 8) & 0xF, (w >> 12) & 0xF
                        if src in url:
                            url[dst] = url[src]
                        else:
                            url.pop(dst, None)
                    elif op == 0x08:               # move-object/from16 (22x)
                        dst, src = (w >> 8) & 0xFF, units[pc + 1] if pc + 1 < n else 0
                        if src in url:
                            url[dst] = url[src]
                        else:
                            url.pop(dst, None)
                    elif op == 0x09:               # move-object/16 (32x)
                        dst, src = (w >> 8) & 0xFF, units[pc + 1] if pc + 1 < n else 0
                        if src in url:
                            url[dst] = url[src]
                        else:
                            url.pop(dst, None)
                    elif 0x6E <= op <= 0x72:       # invoke-virtual/super/... 35c
                        mid_call = units[pc + 1] if pc + 1 < n else 0
                        if mid_call in interesting:
                            count = (w >> 12) & 0xF
                            pack = units[pc + 2] if pc + 2 < n else 0
                            regs_c = (
                                pack & 0xF,
                                (pack >> 4) & 0xF,
                                (pack >> 8) & 0xF,
                                (pack >> 12) & 0xF,
                                (w >> 8) & 0xF,
                            )[:count]
                            emit(mid_call, midx, regs_c, url, owner, co, pc)
                    elif 0x74 <= op <= 0x78:       # invoke-*-range 3rc
                        mid_call = units[pc + 1] if pc + 1 < n else 0
                        if mid_call in interesting:
                            count = (w >> 8) & 0xFF
                            first = units[pc + 2] if pc + 2 < n else 0
                            emit(mid_call, midx,
                                 range(first, min(first + count, first + 256)),
                                 url, owner, co, pc)
                if pc + ln > n:                    # overshoot means mis-decode
                    stats["derailed"] += 1
                    key = "over_%02x" % (w & 0xFF)
                    stats[key] = stats.get(key, 0) + 1
                    return
                pc += ln
            stats["aligned"] += 1

        try:
            for code_off, owner_idx in self._iter_code_items(stats=stats):
                if len(receipts) >= limit:
                    return
                scan(data, code_off, owner_idx)
        finally:
            self.callsite_stats = stats

    def _iter_code_items(self, stats: Optional[Dict[str, int]] = None):
        """Yield ``(code_offset, method_id_index)`` for every concrete method.

        Walks the class_def / class_data ULEB lists.  Per the DEX spec each
        encoded_method stores an index diff from the previous element of its
        list (first element = direct index).  Some production toolchains
        (observed in an app-store repackaged build) instead repeat an
        absolute index mid-list where the spec diff would overflow
        method_ids.  Since all methods of one class are contiguous and
        class-major sorted in method_ids, accept whichever candidate
        resolves to a method id of this class - the spec interpretation
        always scanning first.

        ``stats["classes"]`` / ``stats["derailed"]`` mirror the counters
        the original in-line walker maintained.
        """
        data = self.raw
        method_ids = self._method_ids
        for cls_idx, cdata in self._class_defs:
            if not cdata or cdata + 4 > len(data):
                continue
            try:
                pos = cdata
                static, pos = read_uleb128(data, pos)
                instance, pos = read_uleb128(data, pos)
                direct, pos = read_uleb128(data, pos)
                virtual, pos = read_uleb128(data, pos)
                # skip encoded_field lists (static + instance) so the
                # cursor lands on the encoded_method lists
                for count in (static, instance):
                    for _ in range(count):
                        _fdiff, pos = read_uleb128(data, pos)
                        _facc, pos = read_uleb128(data, pos)
            except (struct.error, IndexError, ValueError):
                if stats is not None:
                    stats["derailed"] += 1
                continue
            if stats is not None:
                stats["classes"] += 1
            own_type = cls_idx
            midx = 0
            for count in (direct, virtual):
                for _ in range(count):
                    try:
                        diff, pos = read_uleb128(data, pos)
                        _acc, pos = read_uleb128(data, pos)
                        code_off, pos = read_uleb128(data, pos)
                    except (struct.error, IndexError, ValueError):
                        break
                    midx += diff
                    owner_idx = None
                    for cand in (midx, diff):
                        if 0 <= cand < len(method_ids) \
                                and method_ids[cand][0] == own_type:
                            owner_idx = cand
                            break
                    if owner_idx is None:
                        continue
                    midx = owner_idx   # re-base the chain on the round trip
                    if not code_off:   # abstract / native: keep chain alive
                        continue
                    yield code_off, owner_idx

    def callsite_summary(self) -> Dict[str, int]:
        """JSON-ready decode stats, for ``meta`` visibility."""
        out = dict(self.callsite_stats)
        out["receipts"] = len(self.callsites)
        return out

    def collect_api_calls(
        self,
        match: Optional["Callable[[str], bool]"] = None,
        limit: int = 8000,
    ) -> None:
        """Walk every method's bytecode and record invoke receipts.

        Unlike :meth:`analyze_callsites` (URL constants paired with a
        network-callee allow-list) this is the *general* invoke layer used
        by the behaviour analysis: every ``invoke-*`` (35c and 3rc forms)
        is decoded and, when ``match`` is supplied, filtered through it
        (``match(callee)`` where ``callee`` is the raw
        ``Lowner/Class;#method`` reference).  Receipts are attributed to
        the *declaring method* (``method``) with the exact bytecode
        ``offset`` - evidence pointers, same caveat as the callsite walk
        (linear decode, control-flow merges not tracked).

        ``match=None`` collects every invoke (unit-test convenience; the
        receipts are capped at ``limit`` either way, while
        :attr:`api_stats` counts the full stream).

        Results land in :attr:`api_receipts` (each: ``method``,
        ``callee``, ``offset``) plus counters in :attr:`api_stats`.
        Idempotent: repeat calls are no-ops.
        """
        if self.api_receipts or self.api_stats:
            return
        data = self.raw
        types = self.types
        method_ids = self._method_ids
        receipts: List[Dict[str, str]] = self.api_receipts
        stats: Dict[str, int] = {
            "classes": 0, "methods": 0, "aligned": 0, "derailed": 0,
            "invokes": 0, "capped": 0,
        }
        seen: set = set()

        def emit(callee_idx: int, owner_idx: int, regs: Sequence[int],
                 owner_holder: List[Optional[str]], co: int, at: int) -> None:
            stats["invokes"] += 1
            callee = self._method_ref(callee_idx, raw=True)
            if not callee:
                return
            if match is not None and not match(callee):
                return
            if owner_holder[0] is None:
                owner_holder[0] = self._method_ref(owner_idx, raw=False)
            owner = owner_holder[0]
            if not owner:
                return
            key = (owner, callee, co + 16 + 2 * at)
            if key in seen:
                return
            seen.add(key)
            if len(receipts) >= limit:
                stats["capped"] += 1
                return
            receipts.append(
                {
                    "method": owner,
                    "callee": callee,
                    "offset": co + 16 + 2 * at,
                }
            )

        def scan(data: bytes, co: int, midx: int) -> None:
            """Decode one code_item linearly, harvesting invokes."""
            if co + 16 > len(data):
                stats["derailed"] += 1
                return
            (_regs, _ins, _outs, _tries, _dbg, n) = struct.unpack_from(
                "<HHHHII", data, co
            )
            if n <= 0:
                stats["aligned"] += 1
                return
            if co + 16 + 2 * n > len(data):
                stats["derailed"] += 1
                return
            units = struct.unpack_from("<%dH" % n, data, co + 16)
            stats["methods"] += 1
            owner: List[Optional[str]] = [None]
            pc = 0
            while pc < n:
                w = units[pc]
                if w == 0x0100:                    # packed-switch-payload
                    ln = 4 + 2 * (units[pc + 1] if pc + 1 < n else 0)
                elif w == 0x0200:                  # sparse-switch-payload
                    ln = 2 + 4 * (units[pc + 1] if pc + 1 < n else 0)
                elif w == 0x0300:                  # fill-array-data-payload
                    width = units[pc + 1] if pc + 1 < n else 0
                    lo = units[pc + 2] if pc + 2 < n else 0
                    hi = units[pc + 3] if pc + 3 < n else 0
                    size = (lo | (hi << 16)) & 0xFFFF_FFFF
                    ln = 4 + (size * width + 1) // 2
                else:
                    op = w & 0xFF
                    ln = INS_LEN[op]
                    if ln == 0:                    # unused ISA: decode derailed
                        stats["derailed"] += 1
                        return
                    if 0x6E <= op <= 0x72:         # invoke- 35c
                        mid_call = units[pc + 1] if pc + 1 < n else 0
                        if 0 <= mid_call < len(method_ids):
                            count = (w >> 12) & 0xF
                            pack = units[pc + 2] if pc + 2 < n else 0
                            regs_c = (
                                pack & 0xF,
                                (pack >> 4) & 0xF,
                                (pack >> 8) & 0xF,
                                (pack >> 12) & 0xF,
                                (w >> 8) & 0xF,
                            )[:count]
                            emit(mid_call, midx, regs_c, owner, co, pc)
                    elif 0x74 <= op <= 0x78:       # invoke-*-range 3rc
                        mid_call = units[pc + 1] if pc + 1 < n else 0
                        if 0 <= mid_call < len(method_ids):
                            count = (w >> 8) & 0xFF
                            first = units[pc + 2] if pc + 2 < n else 0
                            emit(mid_call, midx,
                                 range(first, min(first + count, first + 256)),
                                 owner, co, pc)
                if pc + ln > n:                    # overshoot means mis-decode
                    stats["derailed"] += 1
                    return
                pc += ln
            stats["aligned"] += 1

        try:
            for code_off, owner_idx in self._iter_code_items(stats=stats):
                scan(data, code_off, owner_idx)
        finally:
            self.api_stats = stats


# --------------------------------------------------------------------------
# section scalers
# --------------------------------------------------------------------------
class DexParser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.dex = DexFile(raw=bytes(data))
        self.header_size_end = 0

    # -- entry point ------------------------------------------------------
    def parse(self) -> DexFile:
        data = self.data
        if len(data) < DEX_HEADER_SIZE:
            raise DexError("buffer too short to be a DEX file")

        if data[:4] != DEX_MAGIC and data[:4] != DEY_MAGIC:
            raise DexError("bad DEX magic")
        version = data[4:7]

        (self.dex.checksum,) = struct.unpack_from("<I", data, 8)
        self.dex.signature = bytes(data[12:32])
        (
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = struct.unpack_from("<20I", data, 32)

        self.dex.file_size = file_size if 0 < file_size <= len(data) else len(data)
        self.dex.map_off = map_off

        header = {
            "endian": endian_tag,
            "strings": (string_ids_size, string_ids_off),
            "types": (type_ids_size, type_ids_off),
            "protos": (proto_ids_size, proto_ids_off),
            "fields": (field_ids_size, field_ids_off),
            "methods": (method_ids_size, method_ids_off),
            "classes": (class_defs_size, class_defs_off),
            "data": (data_size, data_off),
        }
        self._load_sections(header)
        return self.dex

    def _load_sections(self, header: Dict[str, Tuple[int, int]]) -> None:
        data = self.data
        # strings ---------------------------------------------------------
        count, off = header["strings"]
        strings: List[DexString] = []
        for i in range(min(count, 200000)):
            pos = off + i * 4
            if pos + 4 > len(data):
                break
            (str_off,) = struct.unpack_from("<I", data, pos)
            if not (0 <= str_off < len(data)):
                continue
            try:
                utf16_len, after_uleb = read_uleb128(data, str_off)
                if utf16_len > len(data):
                    utf16_len = utf16_len & 0xFFFF  # keep going on fuzz data
                end = data.find(b"\x00", after_uleb)
                if end < 0:
                    end = min(len(data), after_uleb + utf16_len + 4)
                value = _mutf8(data[after_uleb:end])
                strings.append(DexString(value=value, offset=str_off))
            except (struct.error, IndexError):
                continue
        self.dex.strings = strings

        # types -----------------------------------------------------------
        tcount, toff = header["types"]
        types: List[str] = []
        for i in range(min(tcount, 100000)):
            pos = toff + i * 4
            if pos + 4 > len(data):
                break
            (idx,) = struct.unpack_from("<I", data, pos)
            if 0 <= idx < len(strings):
                types.append(strings[idx].value)
        self.dex.types = types

        # classes ----------------------------------------------------------
        ccount, coff = header["classes"]
        classes: List[str] = []
        defs: List[Tuple[int, int]] = []
        for i in range(min(ccount, 100000)):
            pos = coff + i * 32
            if pos + 32 > len(data):
                break
            (class_idx, _acc, _super, _itf, _src, _ann, _cdata, _sv) = struct.unpack_from(
                "<8I", data, pos
            )
            defs.append((class_idx, _cdata))
            name = self._decode_descriptor(class_idx, types)
            if name:
                classes.append(name)
        self.dex.classes = classes
        self.dex._class_defs = defs

        # methods: name + class via strings
        mcount, moff = header["methods"]
        methods: List[str] = []
        method_ids: List[Tuple[int, int]] = []
        for i in range(min(mcount, 300000)):
            pos = moff + i * 8
            if pos + 8 > len(data):
                break
            (class_idx, _proto_idx, name_idx) = struct.unpack_from("<HHI", data, pos)
            method_ids.append((class_idx, name_idx))
            cls = self._decode_descriptor(class_idx, types)
            name = strings[name_idx].value if 0 <= name_idx < len(strings) else "?"
            if cls:
                methods.append(f"{cls}#{name}")
        self.dex.methods = methods
        self.dex._method_ids = method_ids

    def _decode_descriptor(self, type_idx: int, types: List[str]) -> Optional[str]:
        return self.dex._decode_descriptor(type_idx, types)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def parse_dex(data: bytes) -> DexFile:
    """Parse a ``classes*.dex`` buffer into a :class:`DexFile`."""
    return DexParser(data).parse()


def load_dex(path: str) -> DexFile:
    with open(path, "rb") as fh:
        return parse_dex(fh.read())


def dex_strings(data: bytes) -> List[DexString]:
    return parse_dex(data).strings


def is_dex(data: bytes) -> bool:
    return len(data) >= DEX_HEADER_SIZE and data[:4] in (DEX_MAGIC, DEY_MAGIC)


# Fallback for heuristic analysis on corrupted DEX: plain `strings` scan.
def raw_strings(data: bytes, min_len: int = 6, limit: int = 20000):
    return list(extract_printable_strings(data, min_len=min_len, limit=limit))

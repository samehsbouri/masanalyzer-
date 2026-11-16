"""Pure-Python Mach-O (and universal/fat) image parser.

The analyzer only needs the parts OWASP M7 ("Insufficient Binary
Protections") cares about:

* cpu type / architecture slice, endianness, magic sanity
* the MH_* flags, specifically ``MH_PIE`` (is the binary position independent?)
* load commands: dynamic libraries linked (LC_LOAD_DYLIB / weak / upward),
  entry point (LC_MAIN), code signature (LC_CODE_SIGNATURE), the object UUID
* segments/sections, notably ``__TEXT.__info_plist`` (older apps)
* LC_SYMTAB: exported/local symbol names - debug and non-stripped builds are
  easy to spot from this

Reference: Apple ``mach-o/loader.h``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# -- magic -----------------------------------------------------------------
MH_MAGIC = 0xFEEDFACE          # 32-bit, big-endian
MH_CIGAM = 0xCEFAEDFE          # 32-bit, little-endian
MH_MAGIC_64 = 0xFEEDFACF       # 64-bit, big-endian
MH_CIGAM_64 = 0xCFFAEDFE       # 64-bit, little-endian
FAT_MAGIC = 0xCAFEBABE         # universal, big-endian
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM = 0xBEBAFECA
FAT_CIGAM_64 = 0xBFBAFECA

# -- cpu types ---------------------------------------------------------------
CPU_TYPE_X86 = 0x00000007
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_ARM_64 = 0x0100000C
CPU_TYPE_PPC = 0x00000012

CPU_NAMES = {
    CPU_TYPE_X86: "x86",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "arm",
    CPU_TYPE_ARM_64: "arm64",
    CPU_TYPE_PPC: "ppc",
}

# -- header flags (subset) -----------------------------------------------
MH_NOUNDEFS = 0x00000001
MH_DYLDLINK = 0x00000004
MH_TWOLEVEL = 0x00000080
MH_PIE = 0x00200000
MH_ALLOW_HEAP_EXECUTION = 0x01000000
MH_ALLOW_STACK_EXECUTION = 0x02000000

FLAG_NAMES = {
    MH_NOUNDEFS: "MH_NOUNDEFS",
    MH_DYLDLINK: "MH_DYLDLINK",
    MH_TWOLEVEL: "MH_TWOLEVEL",
    MH_PIE: "MH_PIE",
    MH_ALLOW_STACK_EXECUTION: "MH_ALLOW_STACK_EXECUTION",
    MH_ALLOW_HEAP_EXECUTION: "MH_ALLOW_HEAP_EXECUTION",
}

# -- load commands -----------------------------------------------------------
LC_SEGMENT = 0x00000001
LC_SYMTAB = 0x00000002
LC_DYSYMTAB = 0x0000000B
LC_LOAD_DYLIB = 0x0000000C
LC_ID_DYLIB = 0x0000000D
LC_LOAD_DYLINKER = 0x0000000E
LC_UUID = 0x0000001B
LC_REQ_DYLD = 0x80000000
LC_LOAD_WEAK_DYLIB = 0x00000018 | LC_REQ_DYLD
LC_RPATH = 0x0000001C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x0000001D
LC_SEGMENT_SPLIT_INFO = 0x00000022
LC_ENCRYPTION_INFO = 0x00000021
LC_ENCRYPTION_INFO_64 = 0x0000002C
LC_LOAD_UPWARD_DYLIB = 0x00000023 | LC_REQ_DYLD
LC_FUNCTION_STARTS = 0x00000026
LC_MAIN = 0x00000028 | LC_REQ_DYLD
LC_SOURCE_VERSION = 0x0000002A
LC_BUILD_VERSION = 0x00000032
LC_SEGMENT_64 = 0x00000019

LC_NAMES = {
    LC_SEGMENT: "LC_SEGMENT",
    LC_SEGMENT_64: "LC_SEGMENT_64",
    LC_SYMTAB: "LC_SYMTAB",
    LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
    LC_ID_DYLIB: "LC_ID_DYLIB",
    LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
    LC_UUID: "LC_UUID",
    LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64",
    LC_MAIN: "LC_MAIN",
    LC_RPATH: "LC_RPATH",
    LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    LC_SOURCE_VERSION: "LC_SOURCE_VERSION",
    LC_BUILD_VERSION: "LC_BUILD_VERSION",
}

DYLIB_CMDS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOAD_UPWARD_DYLIB)

# xtensions of interest
MH_EXECUTE = 0x00000002
MH_DYLIB = 0x00000006
MH_BUNDLE = 0x00000008

FILETYPE_NAMES = {
    1: "MH_OBJECT",
    2: "MH_EXECUTE",
    5: "MH_CORE",
    6: "MH_DYLIB",
    7: "MH_DYLINKER",
    8: "MH_BUNDLE",
    10: "MH_DSYM",
    12: "MH_KEXT_BUNDLE",
}


class MachOError(Exception):
    """Raised when a buffer cannot be parsed as Mach-O."""


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------
@dataclass
class MachOSection:
    name: str
    segment: str
    addr: int = 0
    size: int = 0
    offset: int = 0
    flags: int = 0
    data: bytes = field(default_factory=bytes, repr=False)

    @property
    def is_info_plist(self) -> bool:
        return self.name == "__info_plist"


@dataclass
class MachOSegment:
    name: str
    vm_addr: int
    vm_size: int
    file_offset: int
    file_size: int
    maxprot: int = 0
    initprot: int = 0
    nsects: int = 0
    sections: List[MachOSection] = field(default_factory=list)


@dataclass
class MachOLoadCommand:
    cmd: int
    size: int
    offset: int                      # absolute offset of the command header
    name: Optional[str] = None

    @property
    def label(self) -> str:
        return self.name or LC_NAMES.get(self.cmd, f"LC_{self.cmd:#x}")


@dataclass
class MachOImage:
    """One parsed architecture slice of a Mach-O binary."""

    raw: bytes
    offset: int = 0                 # start of this slice in the (fat) stream
    size: int = 0
    bits: int = 64
    big_endian: bool = False
    cputype: int = 0
    cpusubtype: int = 0
    filetype: int = 0
    flags: int = 0
    load_commands: List[MachOLoadCommand] = field(default_factory=list)
    segments: List[MachOSegment] = field(default_factory=list)
    dylibs: List[str] = field(default_factory=list)
    install_id: Optional[str] = None
    uuid: Optional[str] = None
    symbols: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info_plist: Optional[Dict[str, Any]] = None
    # LC_CODE_SIGNATURE pointer (relative to this slice)
    cs_offset: Optional[int] = None
    cs_size: int = 0
    # outcome of the CodeDirectory page-hash verification (codesign.py):
    # None = no blob / unverifiable shape
    code_signature_verified: Optional[bool] = None
    code_signature_reasons: List[str] = field(default_factory=list)

    @property
    def arch(self) -> str:
        name = CPU_NAMES.get(self.cputype, f"cpu{self.cputype:#x}")
        if self.cputype == CPU_TYPE_ARM_64 and self.cpusubtype & 0x00000002:
            name += "v8"
        if self.cputype == CPU_TYPE_ARM_64 and self.cpusubtype & 0x80000000:
            name = "arm64e"
        return name

    @property
    def is_arm64(self) -> bool:
        return self.cputype == CPU_TYPE_ARM_64

    @property
    def is_executable(self) -> bool:
        return self.filetype == MH_EXECUTE

    @property
    def filetype_name(self) -> str:
        return FILETYPE_NAMES.get(self.filetype, f"0x{self.filetype:08x}")

    @property
    def has_pie(self) -> bool:
        return bool(self.flags & MH_PIE)

    @property
    def has_code_signature(self) -> bool:
        return any(lc.cmd == LC_CODE_SIGNATURE for lc in self.load_commands)

    @property
    def stack_executable(self) -> bool:
        return bool(self.flags & MH_ALLOW_STACK_EXECUTION)

    def flag_names(self) -> List[str]:
        return [n for bit, n in FLAG_NAMES.items() if self.flags & bit]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "file_type": self.filetype_name,
            "pie": self.has_pie,
            "code_signature": self.has_code_signature,
            "uuid": self.uuid,
            "install_id": self.install_id,
            "dylibs": list(self.dylibs),
            "symbols": len(self.symbols),
            "segments": [
                {"name": s.name, "vm_size": s.vm_size, "sections": [x.name for x in s.sections]}
                for s in self.segments
            ],
            "flags": self.flag_names(),
            "warnings": list(self.warnings),
        }


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
class MachOParser:
    def __init__(self, data: bytes) -> None:
        self.data = data if isinstance(data, (bytes, bytearray)) else bytes(data or b"")

    # -- public ----------------------------------------------------------
    def parse_all(self) -> List[MachOImage]:
        raw = self.data
        if len(raw) < 8:
            raise MachOError("truncated Mach-O image")
        (magic,) = struct.unpack_from("<I", raw, 0)
        if magic in (FAT_MAGIC, FAT_MAGIC_64, FAT_CIGAM, FAT_CIGAM_64):
            return self._parse_fat()
        return [self._parse_slice(0)]

    def parse_primary(self) -> MachOImage:
        """Best architecture slice (arm64 preferred), else the first one."""
        slices = self.parse_all()
        prefer = ("arm64v8", "arm64", "arm64e", "x86_64", "arm", "x86")
        for want in prefer:
            for image in slices:
                if image.arch == want:
                    return image
        return slices[0]

    # -- internals --------------------------------------------------------
    def _parse_fat(self) -> List[MachOImage]:
        raw = self.data
        # read magic little-endian: a little-endian fat file yields FAT_MAGIC,
        # a big-endian one yields FAT_CIGAM
        (magic, ) = struct.unpack_from("<I", raw, 0)
        bo = "<" if magic in (FAT_MAGIC, FAT_MAGIC_64) else ">"
        is_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
        stride = 32 if is_64 else 20
        fmt_entry = bo + ("6I" if is_64 else "5I")
        (nfat,) = struct.unpack_from(bo + "I", raw, 4)
        images: List[MachOImage] = []
        for i in range(min(nfat, 16)):
            pos = 8 + i * stride
            fields = struct.unpack_from(fmt_entry, raw, pos)
            if is_64:
                cputype, cpusub, _align_pad, off, size, _res = fields
            else:
                cputype, cpusub, off, size, _align = fields
            try:
                images.append(self._parse_slice(off))
            except MachOError as exc:
                images.append(
                    MachOImage(raw=raw, offset=off, size=size,
                               cputype=cputype, cpusubtype=cpusub,
                               warnings=[f"bad fat entry at {off:#x}: {exc}"])
                )
        if not images:
            raise MachOError("universal image with no architecture entries")
        return images

    def _parse_slice(self, offset: int) -> MachOImage:
        raw = self.data
        data = raw[offset:]
        if len(data) < 32:
            raise MachOError(f"slice at {offset:#x} too short")
        (magic_le,) = struct.unpack_from("<I", data, 0)
        # reading the magic little-endian: MH_MAGIC(_64) => the file itself is
        # little-endian; MH_CIGAM(_64) => the file is big-endian.
        big = magic_le in (MH_CIGAM, MH_CIGAM_64)
        bo = ">" if big else "<"
        bits = 64 if magic_le in (MH_MAGIC_64, MH_CIGAM_64) else 32
        if bits == 64:
            _magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _reserved = struct.unpack_from(
                bo + "IIIIIIII", data, 0
            )
            pos = 32
        else:
            _magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
                bo + "IIIIIII", data, 0
            )
            pos = 28

        img = MachOImage(
            raw=raw, offset=offset, size=len(data), bits=bits, big_endian=big,
            cputype=cputype & 0xFFFFFFFF, cpusubtype=cpusub & 0xFFFFFFFF,
            filetype=filetype & 0xFFFFFFFF, flags=flags & 0xFFFFFFFF,
        )

        end_cmds = min(pos + sizeofcmds, len(data)) if sizeofcmds else min(pos, len(data))
        remaining = ncmds
        while remaining > 0 and pos + 8 <= end_cmds:
            cmd, cmdsize = struct.unpack_from(bo + "II", data, pos)
            if cmdsize < 8 or cmdsize > end_cmds - pos:      # fuzz guard
                img.warnings.append(f"degenerate load command at {pos:#x}")
                break
            self._load_command(img, cmd, pos, cmdsize)
            pos += cmdsize
            remaining -= 1
            if remaining > 4096:  # pragma: no cover - fuzz guard
                break

        self._load_symtab(img)
        self._extract_info_plist(img)
        self._verify_code_signature(img)
        return img

    def _verify_code_signature(self, img: MachOImage) -> None:
        """Run the CodeDirectory page-hash check when a blob is present."""
        if img.cs_offset is None or img.cs_size <= 0:
            return
        if img.cs_offset < 0 or img.cs_offset >= len(img.raw):
            img.code_signature_verified = False
            img.code_signature_reasons = ["signature blob offset out of range"]
            return
        try:
            from .codesign import verify_code_signature

            verified, reasons = verify_code_signature(img.raw, img.cs_offset)
            img.code_signature_verified = verified
            img.code_signature_reasons = reasons
        except Exception as exc:                       # noqa: BLE001 - never abort
            img.code_signature_verified = None
            img.code_signature_reasons = [f"codesign check error: {exc}"]

    # -- individual command handling ---------------------------------------
    def _load_command(self, img: MachOImage, cmd: int, pos: int, size: int) -> None:
        data = img.raw[img.offset:]
        lc = MachOLoadCommand(cmd=cmd, size=size, offset=pos)
        if cmd in DYLIB_CMDS or cmd == LC_ID_DYLIB:
            lc.name = self._lc_dylib_name(data, pos, size)
            if cmd in DYLIB_CMDS:
                img.dylibs.append(lc.name or "unknown.dylib")
            else:
                img.install_id = lc.name
        elif cmd == LC_UUID and size >= 24:
            img.uuid = ":".join(f"{b:02x}" for b in data[pos + 8 : pos + 24])
        elif cmd == LC_MAIN and size >= 24:
            lc.name = "_main (LC_MAIN)"
        elif cmd == LC_LOAD_DYLINKER:
            lc.name = self._lc_dylib_name(data, pos, size)
        elif cmd == LC_CODE_SIGNATURE and size >= 16:
            # linkedit_data_command: dataoff(+8), datasize(+12)
            try:
                (dataoff, datasize) = struct.unpack_from("II", data, pos + 8)
                img.cs_offset = dataoff
                img.cs_size = datasize
                lc.name = f"_signature @ {dataoff:#x} ({datasize}B)"
            except struct.error:
                img.warnings.append("LC_CODE_SIGNATURE truncated")
        img.load_commands.append(lc)

        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            self._segment(img, cmd, pos + 8, size - 8)

    @staticmethod
    def _lc_dylib_name(data: bytes, pos: int, cmdsize: int) -> Optional[str]:
        """Read the NUL-terminated lc_str name of a dylib/dylinker command.

        The string offset lives directly after ``cmd``+``cmdsize`` (pos+8) and
        is relative to the start of the load command.
        """
        if pos + 12 > len(data):
            return None
        (name_off,) = struct.unpack_from("I", data, pos + 8)
        if not (0 <= name_off < cmdsize):
            return None
        return MachOParser._nul_string(data, pos + name_off)

    @staticmethod
    def _nul_string(data: bytes, off: int, cap: int = 4096) -> Optional[str]:
        buf = bytearray()
        end = min(len(data), off + cap)
        while off < end:
            b = data[off]
            if b in (0, 10, 13):
                break
            buf.append(b)
            off += 1
        if not buf:
            return None
        return buf.decode("ascii", "replace").strip() or None

    def _segment(self, img: MachOImage, cmd: int, body: int, size: int) -> None:
        data = img.raw[img.offset:]
        bo = ">" if img.big_endian else "<"
        try:
            if cmd == LC_SEGMENT_64:
                name_raw = data[body : body + 16]
                (vmaddr, vmsize, fileoff, filesize,
                 maxprot, initprot, nsects, segflags) = struct.unpack_from(bo + "QQQQiiII", data, body + 16)
                fields_off = body + 64
                esize = 80
                sect_fmt = bo + "16s16sQQIIIIIIII"   # addr8 size8 off4 align4 ...
            else:
                name_raw = data[body : body + 16]
                (vmaddr, vmsize, fileoff, filesize,
                 maxprot, initprot, nsects, segflags) = struct.unpack_from(bo + "IIIIiiII", data, body + 16)
                fields_off = body + 56
                esize = 68
                sect_fmt = bo + "16s16sIIIIIIIII"    # addr4 size4 off4 align4 ...
        except struct.error:  # pragma: no cover - fuzz tolerance
            img.warnings.append("truncated LC_SEGMENT command")
            return
        segment = MachOSegment(
            name=name_raw.split(b"\x00")[0].decode("utf-8", "replace"),
            vm_addr=vmaddr, vm_size=vmsize,
            file_offset=fileoff, file_size=filesize,
            maxprot=maxprot & 7, initprot=initprot & 7, nsects=nsects,
        )
        cur = fields_off
        for _ in range(min(nsects, 256)):
            if cur + esize > len(data):
                img.warnings.append("truncated section table")
                break
            try:
                fields = struct.unpack_from(sect_fmt, data, cur)
            except struct.error:  # pragma: no cover
                break
            cur += esize
            sect_name = fields[0].split(b"\x00")[0].decode("utf-8", "replace")
            seg_name = fields[1].split(b"\x00")[0].decode("utf-8", "replace")
            addr, ssize, soff = fields[2], fields[3], fields[4]
            sectflags = fields[8]
            blob = b""
            if 0 <= soff < len(data):
                blob = data[soff : soff + min(ssize, 1 << 20)]
            segment.sections.append(
                MachOSection(name=sect_name, segment=seg_name, addr=addr,
                             size=ssize, offset=img.offset + soff, flags=sectflags,
                             data=blob)
            )
        img.segments.append(segment)

    # -- symbol table --------------------------------------------------------
    def _load_symtab(self, img: MachOImage) -> None:
        data = img.raw[img.offset:]
        symtab = next((lc for lc in img.load_commands if lc.cmd == LC_SYMTAB), None)
        if symtab is None:
            return
        try:
            symoff, nsyms, stroff, strsize = struct.unpack_from("IIII", data, symtab.offset + 8)
        except (struct.error, IndexError):  # pragma: no cover
            return
        if not (0 <= stroff < len(data)) or strsize <= 0:
            return
        str_end = min(stroff + strsize, len(data))
        entry = 16 if img.bits == 64 else 12
        for i in range(min(nsyms, 50000)):
            p0 = symoff + i * entry
            if p0 + entry > len(data):
                break
            try:
                if img.bits == 64:
                    nstrx, ntype, nsect, ndesc, nvalue = struct.unpack_from("IBBHQ", data, p0)
                else:
                    nstrx, ntype, nsect, ndesc, nvalue = struct.unpack_from("IBBHI", data, p0)
            except struct.error:  # pragma: no cover
                break
            name_start = stroff + nstrx
            if not (stroff <= name_start < str_end):
                continue
            end = data.find(b"\x00", name_start, str_end)
            if end < 0:
                end = str_end
            name = data[name_start:end].decode("utf-8", "replace")
            if not name or name.startswith("__"):
                continue
            img.symbols.append(name)
            if len(img.symbols) >= 8000:  # pragma: no cover - sanity cap
                break

    # -- embedded plists -------------------------------------------------------
    def _extract_info_plist(self, img: MachOImage) -> None:
        from .plist import parse_bplist

        for seg in img.segments:
            for sect in seg.sections:
                if sect.name == "__info_plist" and sect.data and sect.data[:6] == b"bplist":
                    try:
                        img.info_plist = parse_bplist(bytes(sect.data))
                        return
                    except Exception as exc:  # pragma: no cover
                        img.warnings.append(f"__info_plist: {exc}")


# --------------------------------------------------------------------------
# public helpers
# --------------------------------------------------------------------------
def parse_macho(data: bytes) -> MachOImage:
    """Parse a (possibly universal) Mach-O image and return the best slice."""
    return MachOParser(data).parse_primary()


def is_macho(data: bytes) -> bool:
    if len(data) < 8:
        return False
    (le,) = struct.unpack_from("<I", data, 0)
    (be,) = struct.unpack_from(">I", data, 0)
    return le in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64,
                  FAT_MAGIC, FAT_MAGIC_64, FAT_CIGAM, FAT_CIGAM_64) or be in (
        MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_MAGIC_64)


def image_strings(image: MachOImage, min_len: int = 6, limit: int = 8000) -> List[str]:
    """Printable strings harvested from the raw image slice."""
    raw = image.raw[image.offset : image.offset + (image.size or len(image.raw))]
    seen = set()
    out: List[str] = []
    for _off, text in extract_printable_strings(raw, min_len=min_len, limit=limit):
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out

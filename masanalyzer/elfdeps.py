"""ELF ``.so`` dependency + dangerous-symbol inspection (stdlib-only).

Parses the ELF program headers and the PT_DYNAMIC table to recover:

* ``DT_NEEDED`` shared-library names - the runtime dependency edge list;
  combined across the bundle's ``.so`` files this is the shipped dependency
  graph, and a needed name that is neither an Android system library nor
  another shipped ``.so`` means the app will crash at ``System.loadLibrary``
  time on every device.

* a conservative "dangerous import" byte scan (``dlopen``, ``mprotect``,
  ``ptrace``, ``exec*``): imported symbol names live in ``.dynstr``, so a
  simple substring hit on the ELF body is how linkers/tools like readelf
  reconstruct imports; hits are a superset check (could also occur in
  random data) - findings are reported with reduced confidence.
"""

from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional, Tuple

DT_NEEDED = 1
DT_STRTAB = 5
PT_LOAD = 1
PT_DYNAMIC = 2

#: byte signatures of imports that warrant review (superset check; see
#: module docstring).  "dlopen" very commonly also matches innocuous
#: data, so findings carry reduced confidence downstream.
DANGEROUS_NAMES = (
    "dlopen", "dlsym", "mprotect", "ptrace", "execve", "execl", "execvp",
    "execvpe", "memfd_create",
)

#: NDK system libraries the loader always finds (Android stable public set)
ANDROID_SYSTEM_LIBS = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
    "libstdc++.so", "libandroid.so", "libjnigraphics.so",
    "libEGL.so", "libGLESv2.so", "libOpenSLES.so", "libvulkan.so",
    "libmediandk.so", "libnativewindow.so", "libneuralnetworks.so",
    "libcamera2ndk.so", "libamidi.so", "libnativehelper.so",
    "libaec.so", "libagc.so", "libans.so", "libaaudio.so",
    "libbinder_ndk.so", "libc++_shared.so",   # ok if shipped too; missing = crash
}

# iOS frameworks always available at runtime (for the macOS-style suffix)
IOS_SYSTEM_LIBS = {
    "libSystem.B.dylib", "libobjc.A.dylib", "libc++.dylib", "libsqlite3.dylib",
}


#: fortified libc wrapper function names: ``__<name>_chk`` — emitted when a
#: library is built with ``FORTIFY_SOURCE`` (optionally followed by an ELF
#: version suffix such as ``@@LIBC`` or ``@GLIBC_2.3.4``).
_CHK_NAMES_RE = re.compile(
    rb"__[a-z0-9_]+?_chk(?:@@[A-Za-z0-9_]+|@[A-Za-z0-9_.]+)?(?![A-Za-z0-9_])")


class ElfInfo:
    """Result of :func:`inspect_blob`."""

    __slots__ = (
        "is_elf", "ei_class", "fmt", "needed", "dangerous", "strtab_off",
        "canary", "fortified",
    )

    def __init__(self) -> None:
        self.is_elf = False
        self.ei_class = 0
        self.fmt = "<"
        self.needed: List[str] = []
        self.dangerous: List[str] = []
        self.strtab_off = 0
        # compiler hardening visible in the dynamic string table:
        # stack canary = __stack_chk_fail / __stack_chk_guard imports,
        # FORTIFY_SOURCE = the fortified __*_chk wrapper functions.
        self.canary: bool = False
        self.fortified: List[str] = []


def _load_segments(
    blob: bytes, e_phoff: int, e_phnum: int, e_phentsize: int, fmt: str
) -> Tuple[List[Tuple[int, int, int]], Optional[Tuple[int, int]]]:
    """(PT_LOAD triples (vaddr, off, filesz), PT_DYNAMIC (off, filesz))."""
    loads: List[Tuple[int, int, int]] = []
    dynamic: Optional[Tuple[int, int]] = None
    for i in range(min(e_phnum, 64)):
        pos = e_phoff + i * e_phentsize
        if pos + 8 > len(blob) or pos + e_phentsize > len(blob):
            break
        (p_type,) = struct.unpack_from(fmt + "I", blob, pos)
        try:
            p_off = struct.unpack_from(fmt + "Q", blob, pos + 8)[0]
            p_vaddr = struct.unpack_from(fmt + "Q", blob, pos + 16)[0]
            p_filesz = struct.unpack_from(fmt + "Q", blob, pos + 32)[0]
        except struct.error:
            break
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_off, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_vaddr, p_off, p_filesz)
    return loads, dynamic


def _vaddr_to_off(
    vaddr: int, loads: List[Tuple[int, int, int]]
) -> Optional[int]:
    for seg_vaddr, seg_off, seg_size in loads:
        if seg_vaddr <= vaddr < seg_vaddr + seg_size:
            return seg_off + (vaddr - seg_vaddr)
    return None


def _cstring(blob: bytes, off: int, max_len: int = 255) -> str:
    end = blob.find(b"\x00", off, off + max_len)
    if end == -1:
        end = off + max_len
    raw = blob[off:end]
    if any(b < 0x09 or b > 0x7E for b in raw):
        return ""
    return raw.decode("ascii", "replace")


def inspect_blob(blob: bytes) -> Optional[ElfInfo]:
    """Parse one ELF image into needed-library + dangerous-import lists."""
    if len(blob) < 60 or blob[:4] != b"\x7fELF":
        return None
    info = ElfInfo()
    info.is_elf = True
    info.ei_class = blob[4]
    info.fmt = "<" if blob[5] != 2 else ">"
    fmt = info.fmt
    try:
        if info.ei_class == 2:
            (e_phoff,) = struct.unpack_from(fmt + "Q", blob, 0x20)
            (e_phentsize, e_phnum) = struct.unpack_from(fmt + "HH", blob, 0x36)
        else:
            (e_phoff,) = struct.unpack_from(fmt + "I", blob, 0x1C)
            (e_phentsize, e_phnum) = struct.unpack_from(fmt + "HH", blob, 0x2A)
    except struct.error:
        return info
    loads, dyn = _load_segments(blob, e_phoff, e_phnum, e_phentsize, fmt)
    if dyn is None:
        return info
    dyn_vaddr, dyn_off, dyn_size = dyn

    strtab_vaddr = None
    needed_offsets: List[int] = []
    end = min(len(blob), dyn_off + max(dyn_size, 0))
    pos = dyn_off
    while pos + 16 <= end:
        try:
            (tag,) = struct.unpack_from(fmt + "q", blob, pos)
            (val,) = struct.unpack_from(fmt + "Q", blob, pos + 8)
        except struct.error:
            break
        if tag == 0:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        elif tag == DT_STRTAB and strtab_vaddr is None:
            strtab_vaddr = val
        pos += 16

    strtab_off = (
        _vaddr_to_off(strtab_vaddr, loads)
        if strtab_vaddr is not None
        else None
    )
    info.strtab_off = strtab_off or 0
    if strtab_off is not None:
        for n_off in needed_offsets:
            name = _cstring(blob, strtab_off + n_off)
            if name:
                info.needed.append(name)

    low = blob.lower()
    for name in DANGEROUS_NAMES:
        if name.encode("ascii") in low or (name + "@") .encode("ascii") in low:
            info.dangerous.append(name)

    # compiler hardening markers (byte match on .dynstr content, same
    # superset caveat as the dangerous-import scan):
    #   canary   = __stack_chk_fail (fail path) / __stack_chk_guard (canary)
    #   FORTIFY  = fortified libc wrappers: __memcpy_chk, __strlen_chk, ...
    info.canary = (
        b"__stack_chk_fail" in low or b"__stack_chk_guard" in low
    )
    info.fortified = sorted({
        m.decode("ascii", "replace")
        for m in _CHK_NAMES_RE.findall(low)
    })
    return info


def inspect_blob_backend_note() -> str:  # pragma: no cover - documentation
    return "linked ELF import scan via byte match on .dynstr content"


def missing_dependencies(deps: List[str], shipped: List[str]) -> List[str]:
    """DT_NEEDED names that are neither NDK-system nor another shipped .so."""
    shipped_names = {
        s.replace("\\", "/").split("/")[-1]
        for s in shipped
        if s
    }
    missing = []
    for dep in deps:
        base = dep.replace("\\", "/").split("/")[-1]
        if base in ANDROID_SYSTEM_LIBS:
            continue
        if base in shipped_names:
            continue
        missing.append(dep)
    return missing


def inspect_blob_backend_note() -> str:  # pragma: no cover - documentation
    return "linked ELF import scan via byte match on .dynstr content"

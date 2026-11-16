"""Synthetic fixture builders used by the test suite.

Everything here builds *deliberately vulnerable, benign* fixtures from raw
bytes: a tiny DEX, a compiled AXML manifest, a minimal Mach-O image, a fake
provisioning profile, complete APK/IPA containers and unpacked trees.  The
goal is to exercise the parsers without an Android/iOS toolchain - the same
reason the analyzer itself is stdlib-only.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import random
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "build_axml",
    "build_dex",
    "build_macho",
    "build_mobileprovision",
    "build_apk",
    "build_ipa",
    "build_android_tree",
    "build_ios_tree",
    "build_apks",
    "build_aab",
    "rsa_keypair",
    "cert_der_for_rsa",
    "pkcs7_sf_cert",
    "build_signed_apk",
]


# --------------------------------------------------------------------------
# AXML (binary XML)
# --------------------------------------------------------------------------
def build_axml(
    strings: Sequence[str],
    root_tag_idx: int = 0,
    attrs: Optional[Sequence[Tuple[int, int, int]]] = None,
) -> bytes:
    """Emit a minimal RES_XML chunk with a string pool and one start tag.

    ``attrs`` items are ``(ns_idx, name_idx, value_idx)``; -1 means "no
    namespace".  Every string slot is one of the pooled ``strings``.
    """
    pool = bytearray()
    offsets: List[int] = []
    for s in strings:
        offsets.append(len(pool))
        utf16 = s.encode("utf-16-le")
        pool.extend(struct.pack("<H", len(s)) + utf16 + b"\x00\x00")
    pool = bytes(pool)

    str_base = (28 + len(offsets) * 4 + 3) & ~3
    sp = bytearray()
    sp.extend(struct.pack("<HHI", 0x0001, 28, 0))
    sp.extend(struct.pack("<IIIII", len(strings), 0, 0, str_base, 0))
    sp.extend(struct.pack("<%dI" % len(offsets), *offsets))
    while len(sp) % 4:
        sp.append(0)
    assert len(sp) == str_base
    sp.extend(pool)
    struct.pack_into("<I", sp, 4, len(sp))

    attrs = list(attrs or [])
    tag = bytearray()
    tag.extend(struct.pack("<HHI", 0x0102, 16, 0))
    tag.extend(struct.pack("<I", 1))                     # line
    tag.extend(struct.pack("<I", 0xFFFFFFFF))            # comment
    tag_body = struct.pack(
        "<IIHHHHHH", 0xFFFFFFFF, root_tag_idx, 20, 20, len(attrs), 0, 0, 0
    )
    attrs_blob = b"".join(
        struct.pack("<IIIHBBI", ns & 0xFFFFFFFF, name, val & 0xFFFFFFFF, 8, 0, 3, val)
        for ns, name, val in attrs
    )
    struct.pack_into("<I", tag, 4, 16 + len(tag_body) + len(attrs_blob))
    tag.extend(tag_body)
    tag.extend(attrs_blob)

    doc = bytearray(struct.pack("<HHI", 0x0003, 8, 0))   # RES_XML header
    doc.extend(bytes(sp))
    doc.extend(bytes(tag))
    struct.pack_into("<I", doc, 4, len(doc))
    return bytes(doc)


def manifest_axml(
    package: str,
    version_name: str = "1.0",
    extra_strings: Sequence[str] = (),
) -> bytes:
    """Build `<manifest package=... versionName=...>` AXML."""
    strings = ["manifest", "package", package, "versionName", version_name,
               *extra_strings]
    return build_axml(strings, 0, [(-1, 1, 2), (-1, 3, 4)])


MANIFEST_PLAIN = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="%(pkg)s" android:versionName="%(ver)s">
    <uses-sdk android:minSdkVersion="%(min)d" android:targetSdkVersion="%(tgt)d"/>
    <application android:debuggable="%(dbg)s" android:allowBackup="%(bak)s" android:usesCleartextTraffic="%(clt)s">
%(body)s
    </application>
</manifest>
'''


def manifest_plain(
    package: str = "com.example.insecurebank",
    version: str = "2.3.1",
    min_sdk: int = 16,
    target_sdk: int = 28,
    debuggable: bool = True,
    allow_backup: bool = True,
    cleartext: bool = True,
    uses_permissions: Iterable[str] = ("android.permission.INTERNET",),
    body: str = "",
) -> bytes:
    perms = "".join(
        f'    <uses-permission android:name="{p}"/>\n' for p in uses_permissions
    )
    return (MANIFEST_PLAIN % {
        "pkg": package,
        "ver": version,
        "min": min_sdk,
        "tgt": target_sdk,
        "dbg": str(debuggable).lower(),
        "bak": str(allow_backup).lower(),
        "clt": str(cleartext).lower(),
        "body": perms + body,
    }).encode("utf-8")


# --------------------------------------------------------------------------
# DEX
# --------------------------------------------------------------------------
def _uleb(value: int) -> bytes:
    """ULEB128 encoder for fixture class_data entries."""
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex(
    strings: Sequence[bytes],
    types: Sequence[int] = (),
    classes: Sequence[int] = (),
    methods: Sequence[Tuple[int, int]] = (),
    code: Optional[Dict[int, Sequence[int]]] = None,
) -> bytes:
    """Emit a structurally valid DEX (strings/type_ids/method_ids/class_defs).

    ``strings`` are MUTF-8 bytes, each <= 127 chars (single-byte ULEB128).
    With ``code`` (``method_id_idx -> tuple of u16 insns``), a full
    code_item + class_data layout is emitted so the bytecode walker
    (``DexFile.analyze_callsites``) can be exercised end to end; methods
    without an entry keep ``code_off == 0`` (abstract-like).  ``methods``
    must be class-major (contiguous per class) as real dex toolchains emit.
    """
    str_bytes = bytearray()
    str_offsets: List[int] = []
    for s in strings:
        str_offsets.append(len(str_bytes))
        str_bytes.append(len(s))
        str_bytes.extend(s)
        str_bytes.append(0)
    data = bytes(str_bytes)

    str_ids_off = 0x70
    strings_start = str_ids_off + 4 * len(strings)
    str_ids_blob = b"".join(
        struct.pack("<I", strings_start + off) for off in str_offsets
    )
    type_ids_off = strings_start + len(data)
    type_ids_blob = b"".join(struct.pack("<I", idx) for idx in types)
    method_ids_off = type_ids_off + len(type_ids_blob)
    method_ids_blob = b"".join(struct.pack("<HHI", c, 0, n) for c, n in methods)
    class_defs_off = method_ids_off + len(method_ids_blob)
    class_defs_blob = bytearray(
        b"".join(
            struct.pack("<8I", cls_idx, 1, 0xFFFFFFFF, 0, 0, 0, 0, 0)
            for cls_idx in classes
        )
    )

    code_offs: Dict[int, int] = {}
    code_blob = bytearray()
    cd_blob = bytearray()
    cd_offs: Dict[int, int] = {}
    if code:
        code_base = class_defs_off + len(class_defs_blob)
        for midx in sorted(code):
            units_seq = list(code[midx])
            pad0 = (-len(code_blob)) % 4
            code_blob.extend(b"\x00" * pad0)
            code_offs[midx] = code_base + len(code_blob)
            code_blob.extend(
                struct.pack("<HHHHI", 8, 0, 2, 0, 0)      # regs/ins/outs/tries/dbg
                + struct.pack("<I", len(units_seq))
                + struct.pack("<%dH" % len(units_seq), *units_seq)
            )
            code_blob.extend(b"\x00" * ((-len(code_blob)) % 4))
        # class_data: per class in `classes`, all owned methods in list order
        owner_groups: Dict[int, List[int]] = {}
        for position, (ty, _nm) in enumerate(methods):
            owner_groups.setdefault(ty, []).append(position)
        cd_base = code_base + len(code_blob)
        for ty_idx in classes:
            positions = owner_groups.get(ty_idx, [])
            cd_offs[ty_idx] = cd_base + len(cd_blob)
            cd_blob.extend(_uleb(0) + _uleb(0))           # static/instance fields
            cd_blob.extend(_uleb(len(positions)) + _uleb(0))  # direct, virtual
            prev = 0
            for position in positions:
                diff = position - prev
                prev = position
                if diff < 0:                    # not spec-shaped; abs fallback
                    diff = position
                cd_blob.extend(
                    _uleb(diff) + _uleb(0x01) + _uleb(code_offs.get(position, 0))
                )
        for i, ty_idx in enumerate(classes):
            struct.pack_into("<I", class_defs_blob, i * 32 + 24, cd_offs[ty_idx])

    file_size = class_defs_off + len(class_defs_blob) + len(code_blob) + len(cd_blob)

    header = bytearray()
    header.extend(b"dex\n035\x00")
    header.extend(struct.pack("<I", 0))                 # checksum
    header.extend(b"\x00" * 20)                          # sha1
    header.extend(struct.pack("<II", file_size, 0x70))
    header.extend(struct.pack("<I", 0x12345678))         # endian tag
    header.extend(struct.pack("<II", 0, 0))              # link
    header.extend(struct.pack("<I", 0))                  # map_off
    header.extend(struct.pack("<II", len(strings), str_ids_off))
    header.extend(struct.pack("<II", len(types), type_ids_off))
    header.extend(struct.pack("<II", 0, 0))              # protos
    header.extend(struct.pack("<II", 0, 0))              # fields
    header.extend(struct.pack("<II", len(methods), method_ids_off))
    header.extend(struct.pack("<II", len(classes), class_defs_off))
    header.extend(struct.pack("<II", len(data), strings_start))
    header.extend(b"\x00" * (0x70 - len(header)))
    out = bytes(header) + str_ids_blob + data + type_ids_blob + method_ids_blob \
        + bytes(class_defs_blob) + bytes(code_blob) + bytes(cd_blob)
    assert len(out) == file_size
    return out


BANK_DEX_STRINGS = [
    b"Lcom/example/insecurebank/LoginActivity;",
    b"com/example/insecurebank/LoginActivity",
    b"https://api.insecurebank.example:8443/v2/login",
    b"AES/ECB/PKCS5Padding",
    b"jdbc:mysql://root:S3cr3t!db@10.0.0.5/bank",
    b"La/b/c/D;", b"La/b/c/E;", b"La/b/c/F;",
    b"doLogin", b"password", b"MD5",
]


def bank_dex() -> bytes:
    return build_dex(
        BANK_DEX_STRINGS,
        types=[0, 4, 5, 6, 7, 8],
        classes=[0],
        methods=[(0, 8)],
    )


# --------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------
def build_macho(
    suffix_strings: Sequence[str] = (),
    symbols: Sequence[str] = ("_main_helper_debug",),
    pie: bool = True,
    stack_exec: bool = False,
    codesign: bool = False,
    tamper_signature: bool = False,
) -> bytes:
    """A minimal but parseable arm64e Mach-O with LC_SEGMENT_64/SYMTAB/UUID.

    ``suffix_strings`` are appended as raw ASCII so ``extract_printable_strings``
    finds them later. ``codesign=True`` appends a real embedded-signature
    SuperBlob (CodeDirectory + page hashes); ``tamper_signature`` flips a
    byte in the middle of the code before hashing so verification must fail.
    """
    LC_SEGMENT_64, LC_SYMTAB, LC_UUID = 0x19, 0x2, 0x1B
    MH_MAGIC_64, MH_PIE = 0xFEEDFACF, 0x00200000
    LC_CODE_SIGNATURE = 0x1D
    MH_ALLOW_STACK_EXECUTION = 0x02000000
    CPU_TYPE_ARM_64, CPU_SUB_ARM64E = 0x0100000C, 0x80000002

    body = struct.pack("<16s", b"__TEXT") + struct.pack(
        "<QQQQiiII", 0x1000, 0x2000, 0, 0x1000, 5, 5, 0, 0
    )
    seg = struct.pack("<II", LC_SEGMENT_64, 8 + len(body)) + body

    symbols = list(symbols)
    u = struct.pack("<II16s", LC_UUID, 24, bytes(range(16)))
    # symtab/uuid commands are fixed 24 bytes, so offsets are computable up front
    symoff = 32 + len(seg) + 24 + len(u)         # right after the load commands
    names_blob = bytearray()
    strx = []                                    # per-symbol offset into the string table
    for name in symbols:
        encoded = name.encode("ascii", "replace") + b"\x00"
        strx.append(len(names_blob))
        names_blob.extend(encoded)
    stroff = symoff + 16 * len(symbols)          # nlist_64 entries are 16 bytes
    sym = struct.pack(
        "<IIIIII", LC_SYMTAB, 24, symoff, len(symbols), stroff, len(names_blob)
    )
    cmds = seg + sym + u
    if codesign:
        # linkedit_data_command placeholder (dataoff patched after assembly);
        # command is 16 bytes so ncmds becomes 4
        cs_cmd_len = 16
        cmds += struct.pack("<IIII", LC_CODE_SIGNATURE, cs_cmd_len, 0, 0)
    flags = MH_PIE if pie else 0
    if stack_exec:
        flags |= MH_ALLOW_STACK_EXECUTION
    hdr = struct.pack(
        "<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM_64, CPU_SUB_ARM64E,
        2, 4 if codesign else 3, len(cmds), flags, 0
    )
    data = (hdr + cmds).ljust(symoff, b"\x00")
    for i, name in enumerate(symbols):
        # n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)
        data += struct.pack("<IBBHQ", strx[i], 1, 1, 0, 0)
    data = data.ljust(stroff, b"\x00")
    data += bytes(names_blob)                     # symbol string table
    data = data.ljust((len(data) + 3) & ~3, b"\x00")
    for text in suffix_strings:
        data += text.encode("ascii", "replace") + b"\n"

    if codesign:
        # the CS command placeholder sits at 32 + len(seg) + 24 + 24
        cs_cmd_pos = 32 + len(seg) + 48
        # the SuperBlob length is deterministic from len(data) (which the
        # patch itself does not change), so patch dataoff/datasize FIRST -
        # then compute the page hashes over the fully patched bytes
        sb = _build_codesign_superslot(data)
        blob_len = len(sb)
        data = bytearray(data)
        struct.pack_into("<II", data, cs_cmd_pos + 8, len(data), blob_len)
        data = bytes(data)
        sb = _build_codesign_superslot(data)
        assert len(sb) == blob_len, "CS SuperBlob length must be stable"
        data += sb
        if tamper_signature:
            # flip a byte inside the executable record AFTER the page hashes
            # were computed - verification must fail like a patched binary
            data = bytearray(data)
            data[0x40] ^= 0xFF
            data = bytes(data)

    return data


def _build_codesign_superslot(code: bytes) -> bytes:
    """Assemble an embedded-signature SuperBlob (CodeDirectory, page hashes).

    Layout (big-endian per Apple): ``[0xfade0cc0][count][index pairs]``
    followed by the CodeDirectory itself.
    """
    import hashlib

    ident = b"com.example.insecurenotes\x00"
    entitlements = (
        b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">'
        b"<dict><key>get-task-allow</key><false/></dict></plist>"
    )
    requirements = b"\x00\x00\x00\x00\x00\x00\x00\x00"   # empty requirements set

    page = 4096
    n_slots = (len(code) + page - 1) // page
    hasher = hashlib.sha256

    header_len = 68                       # incl. scatter/team/codeLimit64 (v0x20400)
    ident_off = header_len
    req_off = ident_off + len(ident)
    ent_off = req_off + len(requirements)
    hash_off = (ent_off + len(entitlements) + 3) & ~3
    n_special = 3
    cd_len = hash_off + (n_special + n_slots) * 32

    cd = bytearray(cd_len)
    struct.pack_into(">II", cd, 0, 0xFADE0C02, 0x20400)      # magic + version
    struct.pack_into(">I", cd, 8, 0)                         # flags
    struct.pack_into(">I", cd, 12, hash_off)                 # hashOffset
    struct.pack_into(">I", cd, 16, ident_off)                # identOffset
    struct.pack_into(">I", cd, 20, n_special)                # nSpecialSlots
    struct.pack_into(">I", cd, 24, n_slots)                  # nCodeSlots
    struct.pack_into(">I", cd, 28, len(code))                # codeLimit
    cd[32], cd[33], cd[34], cd[35] = 32, 2, 0, 12            # size, SHA256, plat, log2(4096)
    struct.pack_into(">I", cd, 36, 0)                        # spare2
    struct.pack_into(">I", cd, 40, 0)                        # scatterOffset
    struct.pack_into(">I", cd, 44, 0)                        # teamOffset
    struct.pack_into(">I", cd, 48, 0)                        # spare3
    struct.pack_into(">Q", cd, 52, 0)                        # codeLimit64
    cd[ident_off : ident_off + len(ident)] = ident
    cd[req_off : req_off + len(requirements)] = requirements
    cd[ent_off : ent_off + len(entitlements)] = entitlements

    # special slots (kept honest but not verifier-enforced): -3 req, -5 ents
    slots_in_order = {3: requirements, 5: entitlements}
    for gap, payload in slots_in_order.items():
        at = hash_off - gap * 32
        cd[at : at + 32] = hasher(payload).digest()

    # page hashes over the executable record
    for i in range(n_slots):
        chunk = code[i * page : (i + 1) * page]
        cd[hash_off + i * 32 : hash_off + (i + 1) * 32] = hasher(chunk).digest()

    sb = struct.pack(">II", 0xFADE0CC0, 1)                  # magic + count=1
    sb += struct.pack(">II", 0, 16)                         # CD slot: type 0, offset 16
    sb += cd
    return sb


def build_mobileprovision(get_task_allow: bool = True, name: str = "Dev Profile") -> bytes:
    allow = b"<true/>" if get_task_allow else b"<false/>"
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<plist version="1.0"><dict>'
        b"<key>Name</key><string>" + name.encode() + b"</string>"
        b"<key>TeamName</key><string>Fixture Team</string>"
        b"<key>ApplicationIdentifierPrefix</key>"
        b"<array><string>9FIXTURE00</string></array>"
        b"<key>Entitlements</key><dict>"
        b"<key>get-task-allow</key>" + allow +
        b"<key>application-identifier</key>"
        b"<string>9FIXTURE00.com.example.insecurenotes</string>"
        b"</dict></dict></plist>"
    )
    return b"-----BEGIN FAKE-CMS-----\n" + xml


# --------------------------------------------------------------------------
# IOS plists
# --------------------------------------------------------------------------
IOS_INFO_PLIST_KEYS: Dict[str, object] = {
    "CFBundleIdentifier": "com.example.insecurenotes",
    "CFBundleName": "InsecureNotes",
    "CFBundleExecutable": "InsecureNotes",
    "CFBundleShortVersionString": "1.4.2",
    "CFBundleVersion": "42",
    "MinimumOSVersion": "11.0",
}


def info_plist_dict(arbitrary_loads: bool = True) -> Dict[str, object]:
    from masanalyzer.ios.plist import dump_bplist  # cheap import

    data = dict(IOS_INFO_PLIST_KEYS)
    if arbitrary_loads:
        data["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": True}
    return data  # caller dump_bplist()-s this


def prefs_plist_dict() -> Dict[str, object]:
    return {
        "authToken": "eyJhbGciOiJIUzI1NiJ9fixturesignature",
        "password": "changeme123",
        "rememberedUser": "admin",
    }


# --------------------------------------------------------------------------
# Containers
# --------------------------------------------------------------------------
def build_apk(
    dest_path: str,
    package: str = "com.example.insecurebank",
    dex: Optional[bytes] = None,
    nsc_xml: Optional[bytes] = None,
    so_files: Optional[Dict[str, bytes]] = None,
    sign_v1: bool = False,
) -> str:
    """Write a synthetic (unsigned by default) APK at ``dest_path``."""
    entry = manifest_axml(package, "2.3.1")
    with zipfile.ZipFile(dest_path, "w") as z:
        z.writestr("AndroidManifest.xml", entry)
        z.writestr("classes.dex", dex or bank_dex())
        if nsc_xml is not None:
            z.writestr("res/xml/network_security_config.xml", nsc_xml)
        for name, blob in (so_files or {}).items():
            z.writestr(f"lib/{name}", blob)
        if sign_v1:
            z.writestr("META-INF/CERT.RSA", _fake_v1_cert("Android Debug"))
    return dest_path


NSC_CLEARTEXT = (
    b'<network-security-config><base-config cleartextTrafficPermitted="true">'
    b'<trust-anchors><certificates src="user"/></trust-anchors></base-config>'
    b"</network-security-config>"
)


def build_apks(
    dest_path: str,
    package: str = "com.example.splitset",
) -> str:
    """Write an ``.apks`` APK-Set: base APK + two split APKs + a TOC blob."""
    with tempfile.TemporaryDirectory(prefix="masan_apks_base_") as tmp:
        base_inner = build_apk(os.path.join(tmp, "base.apk"), package=package)
        with open(base_inner, "rb") as fh:
            base_bytes = fh.read()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lib/arm64-v8a/libsplit.so", b"\x7fELF-fake-split-lib")
        z.writestr("assets/split_extra.json", b'{"feature": "on-demand"}\n')
    split_abi = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("res/values/stub.xml", b"<resources/>")
    split_res = buf.getvalue()

    with zipfile.ZipFile(dest_path, "w") as z:
        z.writestr("base.apk", base_bytes)
        z.writestr("split_config.arm64_v8a.apk", split_abi)
        z.writestr("split_assets.apk", split_res)
        z.writestr("toc.pb", b"\n\x18apkset-toc-placeholder")
    return dest_path


def build_aab(dest_path: str, dex: Optional[bytes] = None) -> str:
    """Write an Android App Bundle (.aab): protobuf manifest + bundle tree."""
    with zipfile.ZipFile(dest_path, "w") as z:
        z.writestr(
            "base/manifest/AndroidManifest.xml",      # protobuf, not AXML
            b"\n\x18com.example.bundleapp\x12\x051.0\x22\x03ABC",
        )
        z.writestr("base/dex/classes.dex", dex or bank_dex())
        z.writestr("base/lib/arm64-v8a/libbundle.so", b"\x7fELF-fake-bundle-lib")
        z.writestr("resources.pb", b"\x02\x00RES-TABLE-PROTO")
        z.writestr("BundleConfig.pb", b"\x0a\x11opt-in-bundle-config")
        z.writestr(
            "BUNDLE-METADATA/com.android.tools/proguard.map",
            b"# mapping\ncom.example -> a\n",
        )
    return dest_path


def _fake_v1_cert(cn: str = "Android Debug") -> bytes:
    """Tiny DER: a name blob with a CN, enough for common_names_from_der."""
    def _len(payload: bytes) -> bytes:
        n = len(payload)
        if n < 128:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    cn_oid = bytes.fromhex("0603550403")
    attr = b"\x30" + _len(cn_oid + b"\x0c" + bytes([len(cn)]) + cn.encode()) \
        + cn_oid + b"\x0c" + bytes([len(cn)]) + cn.encode()
    rdn = b"\x31" + _len(attr) + attr
    name = b"\x30" + _len(rdn) + rdn
    return b"\x30" + _len(name) + name


def build_ipa(
    dest_path: str,
    macho: Optional[bytes] = None,
    extra_plists: Optional[Dict[str, bytes]] = None,
    profile: Optional[bytes] = None,
    bundle_id_suffix: str = "insecurenotes",
    frameworks: Optional[Dict[str, str]] = None,
) -> str:
    """Write an ``.ipa`` container.

    ``frameworks`` maps a framework bundle name to its version (e.g.
    ``{"Alamofire": "4.0.0"}``); each generates
    ``Payload/.../Frameworks/<Name>.framework/`` with a Mach-O binary and
    its own ``Info.plist`` carrying ``CFBundleShortVersionString`` — the
    shape real CocoaPods/SPM integrations produce."""
    from masanalyzer.ios.plist import dump_bplist

    app_dir = "Payload/InsecureNotes.app"
    with zipfile.ZipFile(dest_path, "w") as z:
        z.writestr(
            f"{app_dir}/Info.plist",
            dump_bplist(info_plist_dict(arbitrary_loads=True)),
        )
        for fw, version in (frameworks or {}).items():
            fw_dir = f"{app_dir}/Frameworks/{fw}.framework"
            z.writestr(
                f"{fw_dir}/{fw}", macho or build_macho()
            )
            z.writestr(
                f"{fw_dir}/Info.plist",
                dump_bplist(
                    {
                        "CFBundleShortVersionString": version,
                        "CFBundleVersion": version,
                        "CFBundleIdentifier": f"org.example.{fw.lower()}",
                    }
                ),
            )
        for rel, blob in (extra_plists or {}).items():
            z.writestr(f"{app_dir}/{rel}", blob)
        z.writestr(f"{app_dir}/InsecureNotes", macho or build_macho())
        z.writestr(
            f"{app_dir}/embedded.mobileprovision",
            profile or build_mobileprovision(),
        )
    return dest_path


# --------------------------------------------------------------------------
# Unpacked trees (written under a base directory)
# --------------------------------------------------------------------------
def build_android_tree(base: str) -> str:
    """samples/InsecureBank-like source tree under ``base``."""
    from masanalyzer.ios.plist import dump_bplist  # not used, keep imports local

    man_path = os.path.join(base, "app", "src", "main")
    java_path = os.path.join(man_path, "java", "com", "example", "insecurebank")
    res_xml = os.path.join(base, "res", "xml")
    assets = os.path.join(base, "assets")
    for d in (man_path, java_path, res_xml, assets):
        os.makedirs(d, exist_ok=True)

    body = (
        '    <activity android:name=".LoginActivity" android:exported="true"/>\n'
        '    <provider android:name=".CredentialsProvider"\n'
        '        android:grantUriPermissions="true" android:exported="true"/>\n'
    )
    with open(os.path.join(man_path, "AndroidManifest.xml"), "wb") as fh:
        fh.write(
            manifest_plain(
                body=body,
                uses_permissions=(
                    "android.permission.INTERNET",
                    "android.permission.READ_SMS",
                    "android.permission.ACCESS_FINE_LOCATION",
                ),
            )
        )
    with open(os.path.join(res_xml, "network_security_config.xml"), "wb") as fh:
        fh.write(NSC_CLEARTEXT)
    with open(os.path.join(java_path, "LoginActivity.java"), "w") as fh:
        fh.write(
            "package com.example.insecurebank;\n"
            "public class LoginActivity {\n"
            '    private static final String API_KEY = "AKIAIOSFODNN7EXAMPLE";\n'
            '    private static final String PIN = "1234";\n'
            "}\n"
        )
    with open(os.path.join(assets, "config.properties"), "w") as fh:
        fh.write("url=https://api.insecurebank.example\nsecret_seed=9999\n")
    intermediate = os.path.join(base, "app", "build", "intermediates")
    os.makedirs(intermediate, exist_ok=True)
    with open(os.path.join(intermediate, "classes.dex"), "wb") as fh:
        fh.write(bank_dex())
    return base


def build_ios_tree(base: str) -> str:
    """samples/InsecureNotes-like source tree under ``base``."""
    from masanalyzer.ios.plist import dump_bplist

    app = os.path.join(base, "Payload", "InsecureNotes.app")
    sources = os.path.join(base, "Sources")
    outputs = os.path.join(base, "build", "outputs")
    for d in (app, sources, outputs):
        os.makedirs(d, exist_ok=True)

    with open(os.path.join(app, "Info.plist"), "wb") as fh:
        fh.write(dump_bplist(info_plist_dict(arbitrary_loads=True)))
    with open(os.path.join(app, "Prefs.plist"), "wb") as fh:
        fh.write(dump_bplist(prefs_plist_dict()))
    with open(os.path.join(app, "InsecureNotes"), "wb") as fh:
        fh.write(
            build_macho(
                symbols=("_InsecureNotes_DebugHelper",),
                suffix_strings=("https://syncserver.example.net/cache?",),
            )
        )
    with open(os.path.join(app, "embedded.mobileprovision"), "wb") as fh:
        fh.write(build_mobileprovision())
    with open(os.path.join(sources, "Keychain.swift"), "w") as fh:
        fh.write(
            'let password = "P@ssw0rd123"\n'
            "print(\"token: \\(token)\")\n"
        )
    with open(os.path.join(outputs, "InsecureNotes.ipa"), "wb") as fh:
        build_ipa(os.path.join(outputs, "InsecureNotes.ipa"))
    return base


# ==========================================================================
# APK v1 (JAR) signature fixtures - real crypto via masanalyzer.android.pkcs7
# ==========================================================================
def _mr_rounds(n: int, rounds: int, rng) -> bool:
    """Miller-Rabin primality (deterministic given the seeded rng)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng) -> int:
    while True:
        candidate = rng.randrange(1 << (bits - 1), 1 << bits) | 1
        if _mr_rounds(candidate, 14, rng):
            return candidate


@dataclass
class RsaKeyPair:
    """Fixture-grade RSA key (small modulus is fine - verification only)."""

    n: int
    e: int = 65537
    d: int = 0
    p: int = 0
    q: int = 0

    def sign_pkcs1(self, message: bytes, digest_name: str = "sha256") -> bytes:
        import hashlib

        algo = hashlib.sha256 if digest_name == "sha256" else hashlib.sha1
        digest = algo(message).digest()
        prefix = PKCS7_DIGEST_PREFIX[digest_name]
        k = (self.n.bit_length() + 7) // 8
        padding = b"\xff" * (k - len(prefix) - len(digest) - 3)
        block = b"\x00\x01" + padding + b"\x00" + prefix + digest
        sig_int = pow(int.from_bytes(block, "big"), self.d, self.n)
        return sig_int.to_bytes(k, "big")


PKCS7_DIGEST_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}

_RSA_CACHE: dict = {}


def rsa_keypair(seed: int = 20260101) -> RsaKeyPair:
    cached = _RSA_CACHE.get(seed)
    if cached is not None:
        return cached
    rng = random.Random(seed)
    p = _gen_prime(512, rng)
    q = _gen_prime(512, rng)
    key = RsaKeyPair(n=p * q, e=65537, d=pow(65537, -1, (p - 1) * (q - 1)), p=p, q=q)
    _RSA_CACHE[seed] = key
    return key


def _dataclass_ish_unused():  # pragma: no cover - removed shim
    return None


# --- synthetic resources.arsc (for the resource-id -> string resolver) -------
def build_arsc(entries) -> bytes:
    """Compile a minimal ``resources.arsc`` blob.

    ``entries`` is a list of ``(res_id, value)`` pairs where ``res_id`` is
    the full id (``0x7f14006b``) and ``value`` the string resource.  The
    layout mirrors what aapt emits: RES_TABLE header, global string pool,
    one package chunk (type + key string pools, one RES_TABLE_TYPE chunk
    per distinct type id with default config).
    """
    entries = sorted(entries, key=lambda e: e[0])
    values = [v for _, v in entries]
    type_ids = sorted({(rid >> 16) & 0xFF for rid, _ in entries})
    type_names = [f"type{i:02x}" for i in type_ids]
    key_names = [f"key{i}" for i, _ in enumerate(entries)]
    pool = _utf16_pool(values + type_names + key_names)
    g_values, g_types, g_keys = len(values), len(type_names), len(key_names)

    package_id = entries[0][0] >> 24 if entries else 0x7F

    # type string pool + key string pool (offsets patched after sizing)
    type_pool = _utf16_pool(type_names)
    key_pool = _utf16_pool(key_names)

    chunks = bytearray()
    type_offsets: List[Tuple[int, int]] = []  # (type_id, chunk_start)
    # -- reserve type + key pools -----------------------------------------
    chunks.extend(type_pool)
    type_pool_end = len(chunks)
    chunks.extend(key_pool)
    key_pool_end = len(chunks)

    per_type: dict = {}
    for rid, value in entries:
        per_type.setdefault((rid >> 16) & 0xFF, []).append(
            (rid & 0xFFFF, values.index(value)))

    for tid in type_ids:
        items = sorted(per_type.get(tid, []))
        count = max(e for e, _ in items) + 1
        offsets: List[int] = [0xFFFFFFFF] * count
        entries_blob = bytearray()
        for entry_idx, gidx in items:
            offsets[entry_idx] = len(entries_blob)
            entries_blob.extend(
                struct.pack("<HHI", 8, 0, gidx)          # size, flags, key
                + struct.pack("<HBB", 8, 0, 0x03)        # value hdr, STRING
                + struct.pack("<I", gidx))               # global pool index
        header_size = 20 + 4                              # incl. config.size
        offsets_start = header_size
        entries_start = offsets_start + 4 * count
        body = (
            struct.pack("<BBHII", tid, 0, 0, count, entries_start)
            + struct.pack("<I", 4)                        # config: size only
            + struct.pack("<%dI" % count, *offsets)
            + bytes(entries_blob)
        )
        start = len(chunks)
        # chunk bytes = 8-byte chunk header + body (body starts with the
        # ResTable_type fields that continue the header up to header_size)
        chunks.extend(struct.pack("<HHI", 0x0201, header_size,
                                  8 + len(body)) + body)
        type_offsets.append((tid, start))

    key_strings_off = 284 + type_pool_end
    type_strings_off = 284  # 8 header + 4 id + 256 name + 4*4 fields
    pkg_header = (
        struct.pack("<HHI", 0x0200, 12, 0)               # size patched below
        + struct.pack("<I", package_id)
        + b"test.pkg".decode().encode("utf-16-le").ljust(256, b"\x00")
        + struct.pack("<IIII", type_strings_off, len(type_names),
                      key_strings_off, len(key_names))
    )
    package = pkg_header + bytes(chunks)
    package = bytearray(package)
    struct.pack_into("<I", package, 4, len(package))

    global_pool = _utf16_pool(values)
    table_body = global_pool + bytes(package)
    total = 12 + len(table_body)
    table = struct.pack("<HHII", 0x0002, 12, total, 1) + table_body
    return table


def _utf16_pool(strings) -> bytes:
    """UTF-16 string pool chunk (aapt style, no styles)."""
    pool = bytearray()
    offsets: List[int] = []
    for s in strings:
        offsets.append(len(pool))
        pool.extend(struct.pack("<H", len(s))
                    + s.encode("utf-16-le") + b"\x00\x00")
    pool = bytes(pool)
    str_base = (28 + len(offsets) * 4 + 3) & ~3
    sp = bytearray(struct.pack("<HHI", 0x0001, 28, 0))
    sp.extend(struct.pack("<IIIII", len(strings), 0, 0, str_base, 0))
    sp.extend(struct.pack("<%dI" % len(offsets), *offsets))
    while len(sp) % 4:
        sp.append(0)
    sp.extend(pool)
    struct.pack_into("<I", sp, 4, len(sp))
    return bytes(sp)


# --- DER helpers (delegating to the real encoder in android.pkcs7) ----------
# --- APK v4 (.idsig) sidecar fixture -----------------------------------------
def build_idsig(dest_path: str, cert_der: Optional[bytes], apk_size: int) -> str:
    """Write an ``.idsig`` file following apksigv4.py's header contract.

    ``cert_der=None`` produces a sidecar with no/blank certificate section
    (out-of-bounds offsets), exercising the warning path.
    """
    import os

    chunk, digest = 4096, 32
    leaves = (apk_size + chunk - 1) // chunk
    tree_size = max(leaves * digest, digest)          # at least the root digest
    tree = b"\x37" * tree_size                        # opaque tree payload
    digest_blob = b"\xab" * digest                    # root digest
    signer = struct.pack("<I", 1) + struct.pack("<I", 0x0103)
    cert = cert_der or b""
    key_hint = b"\x00" * 8

    header_len = 8 + 10 * 4
    tree_off = header_len
    digest_off = tree_off + len(tree)
    signer_off = digest_off + len(digest_blob)
    cert_off = signer_off + len(signer)
    if cert_der is None:
        # deliberately out-of-bounds certificate section
        cert_off, cert_len = 0x7FFFFFF0, len(cert)
    else:
        cert_len = len(cert)

    hdr = b"APKV" + struct.pack(">I", 1)
    hdr += struct.pack(">10I",
        chunk, digest,
        tree_off, len(tree),
        digest_off, len(digest_blob),
        signer_off, len(signer),
        cert_off, cert_len,
    )
    blob = hdr + tree + digest_blob + signer + cert + key_hint
    with open(dest_path, "wb") as fh:
        fh.write(blob)
    return dest_path


def cert_der_for_rsa(
    key: RsaKeyPair,
    common_name: str = "masanalyzer Test Signer",
    not_before: bytes = b"260101000000Z",
    not_after: bytes = b"340101000000Z",
) -> bytes:
    """A structurally complete (fixture-grade) X.509 self-signed cert.

    Only the fields our SPKI parser needs are real; the rest keeps DER
    well-formed so common walkers survive it.
    """
    from masanalyzer.android.pkcs7 import (
        encode_bitstring,
        encode_context,
        encode_der,
        encode_int,
        encode_oid,
        encode_seq,
        encode_set,
        OID_RSA,
        OID_RSA_SHA256,
    )

    OID_CN = bytes.fromhex("550403")           # 2.5.4.3 commonName
    alg_sha256rsa = encode_seq(encode_oid(OID_RSA_SHA256))
    alg_rsa = encode_seq(encode_oid(OID_RSA))
    rsa_pub = encode_seq(encode_int(key.n) + encode_int(key.e))
    spki = encode_seq(alg_rsa + encode_bitstring(rsa_pub))

    def name(cn: str) -> bytes:
        attr = encode_seq(encode_oid(OID_CN) + encode_der(0x0C, cn.encode("utf-8")))
        return encode_seq(encode_set(attr))

    serial = encode_int(0x2A)
    validity = encode_seq(
        encode_der(0x17, not_before) + encode_der(0x17, not_after)
    )

    tbs_core = (
        encode_context(0, b"\x02\x01\x02")       # [0] EXPLICIT version
        + serial
        + alg_sha256rsa
        + name(common_name)
        + validity
        + name(common_name)
        + spki
    )
    tbs = encode_seq(tbs_core)
    return encode_seq(
        tbs
        + alg_sha256rsa
        + encode_bitstring(key.sign_pkcs1(tbs, "sha256"))
    )


def pkcs7_sf_cert(
    sf_bytes: bytes,
    key: RsaKeyPair,
    cert_der: bytes,
    detached: bool = False,
    digest_name: str = "sha256",
) -> bytes:
    """Build a real PKCS#7 SignedData blob over the .SF bytes.

    ``detached=False`` puts the SF as attached content (eContent);
    ``detached=True`` omits eContent and instead uses signedAttrs with a
    messageDigest attribute — the shape classic ``jarsigner`` produces.
    """
    from masanalyzer.android.pkcs7 import (
        OID_CN,
        OID_DATA,
        OID_SIGNED_DATA,
        OID_MESSAGE_DIGEST,
        OID_CONTENT_TYPE,
        OID_RSA_SHA256,
        OID_RSA_SHA1,
        OID_SHA256,
        OID_SHA1,
        encode_bitstring,
        encode_context,
        encode_der,
        encode_int,
        encode_octet,
        encode_oid,
        encode_seq,
        encode_set,
    )

    if digest_name == "sha256":
        sig_alg_oid = OID_RSA_SHA256
    else:
        sig_alg_oid = OID_RSA_SHA1
    sig_alg_seq = encode_seq(encode_oid(sig_alg_oid))
    digest_oid_bytes = OID_SHA256 if digest_name == "sha256" else OID_SHA1
    digest_alg_seq = encode_seq(encode_oid(digest_oid_bytes))
    hasher = hashlib.sha256 if digest_name == "sha256" else hashlib.sha1

    issuer_and_serial = encode_seq(
        encode_seq(encode_set(encode_seq(encode_oid(OID_CN) + encode_der(0x0C, "masanalyzer Test Signer".encode()))))
        + encode_int(0x2A)
    )

    if detached:
        attrs_value = b"".join([
            encode_seq(encode_oid(OID_CONTENT_TYPE) + encode_set(encode_oid(OID_DATA))),
            encode_seq(encode_oid(OID_MESSAGE_DIGEST) + encode_set(encode_octet(hasher(sf_bytes).digest()))),
        ])
        attrs_raw = encode_context(0, attrs_value)   # [0] IMPLICIT SET
        signature = key.sign_pkcs1(attrs_raw, digest_name)
        signer_info = encode_seq(
            encode_int(1)
            + issuer_and_serial
            + digest_alg_seq
            + attrs_raw
            + sig_alg_seq
            + encode_octet(signature)
        )
        content_info = encode_seq(encode_oid(OID_DATA))   # detached (no [0])
        signed_data = encode_seq(
            encode_int(1)
            + encode_set(digest_alg_seq)
            + content_info
            + encode_context(0, cert_der)
            + encode_set(signer_info)
        )
    else:
        signature = key.sign_pkcs1(sf_bytes, digest_name)
        signer_info = encode_seq(
            encode_int(1)
            + issuer_and_serial
            + digest_alg_seq
            + sig_alg_seq
            + encode_octet(signature)
        )
        content_info = encode_seq(
            encode_oid(OID_DATA) + encode_context(0, encode_octet(sf_bytes))
        )
        signed_data = encode_seq(
            encode_int(1)
            + encode_set(digest_alg_seq)
            + content_info
            + encode_context(0, cert_der)
            + encode_set(signer_info)
        )
    return encode_seq(encode_oid(OID_SIGNED_DATA) + encode_context(0, signed_data))


def build_signed_apk(
    dest_path: str,
    package: str = "com.example.signedapp",
    tamper: bool = False,
    seed: int = 20260101,
    expired_cert: bool = False,
) -> str:
    """Write a properly v1 (JAR) signed APK; ``tamper`` breaks one entry."""
    import base64

    entries = {
        "AndroidManifest.xml": manifest_axml(package, "1.0"),
        "classes.dex": build_dex(strings=(b"com/example/signedapp", b"doWork")),
        "res/values/strings.xml": (
            "<resources><string name=\"app\">fixture</string></resources>"
        ).encode("ascii"),
    }

    # MANIFEST.MF ------------------------------------------------------------
    def section_for(name: str, payload: bytes) -> str:
        digest = base64.b64encode(hashlib.sha256(payload).digest()).decode()
        return f"Name: {name}\nSHA-256-Digest: {digest}\n\n"

    manifest = "Manifest-Version: 1.0\nCreated-By: masanalyzer fixture\n\n" + \
        "".join(section_for(name, blob) for name, blob in sorted(entries.items()))
    manifest_b = manifest.replace("\n", "\r\n").encode("ascii")

    # CERT.SF - the whole-manifest digest lives in the *main* section
    sf_main = (
        "Signature-Version: 1.0\nCreated-By: masanalyzer fixture\n"
        + "SHA-256-Digest-Manifest: "
        + base64.b64encode(hashlib.sha256(manifest_b).digest()).decode()
        + "\n\n"
    )
    sf_b = sf_main.replace("\n", "\r\n").encode("ascii")

    key = rsa_keypair(seed)
    cert = cert_der_for_rsa(
        key,
        not_before=b"150101000000Z" if expired_cert else b"260101000000Z",
        not_after=b"200301000000Z" if expired_cert else b"340101000000Z",
    )
    pkcs7 = pkcs7_sf_cert(sf_b, key, cert, detached=False)

    with zipfile.ZipFile(dest_path, "w") as z:
        for name, blob in sorted(entries.items()):
            z.writestr(name, blob)
        z.writestr("META-INF/MANIFEST.MF", manifest_b)
        z.writestr("META-INF/CERT.SF", sf_b)
        z.writestr("META-INF/CERT.RSA", pkcs7)

    if tamper:
        # modify an entry AFTER signing, like a repacking attack would
        with zipfile.ZipFile(dest_path, "r") as zin:
            order = zin.namelist()
            payload = {n: zin.read(n) for n in order}
        dex = bytearray(payload["classes.dex"])
        dex[-1] ^= 0xFF
        payload["classes.dex"] = bytes(dex)
        with zipfile.ZipFile(dest_path, "w") as z:
            for name in order:
                z.writestr(name, payload[name])
    return dest_path


# ==========================================================================
# APK signature scheme v2 / v3 fixtures (real whole-file signing)
# ==========================================================================
def spki_der_for_rsa(key: RsaKeyPair) -> bytes:
    """SubjectPublicKeyInfo DER for the fixture RSA key (v2/v3 public key)."""
    from masanalyzer.android.pkcs7 import (
        OID_RSA, encode_bitstring, encode_oid, encode_seq, encode_int,
    )

    rsa_pub = encode_seq(encode_int(key.n) + encode_int(key.e))
    return encode_seq(encode_seq(encode_oid(OID_RSA)) + encode_bitstring(rsa_pub))


def _v23_digest(sections: list, algo: str) -> bytes:
    """Spec digest over section payloads: 1 MB chunks, 0xa5/0x5a framing."""
    import hashlib

    hasher = getattr(hashlib, algo)
    chunk_digests = []
    for section in sections:
        if not section:
            continue
        for off in range(0, len(section), 2 ** 20):
            chunk = section[off : off + 2 ** 20]
            chunk_digests.append(
                hasher(b"\xa5" + struct.pack("<I", len(chunk)) + chunk).digest()
            )
    if not chunk_digests:
        chunk_digests = [hasher(b"\xa5" + struct.pack("<I", 0)).digest()]
    return hasher(
        b"\x5a" + struct.pack("<I", len(chunk_digests)) + b"".join(chunk_digests)
    ).digest()


def _v23_signer_blob(
    key: RsaKeyPair,
    cert_der: bytes,
    digest: bytes,
    scheme: str,
) -> bytes:
    """Assemble one v2/v3 signer (spec wire format).

    ``signed data`` (digests + certificates [ + min/max SDK for v3 ] +
    attributes) is signed with RSA PKCS#1 v1.5 over SHA-256 — algorithm
    id 0x0103, the deterministic build-server variant.
    """
    from masanalyzer.android.apksigv2 import SIG_RSA_PKCS1_SHA256, encode_lp

    digest_record = struct.pack("<I", SIG_RSA_PKCS1_SHA256) + encode_lp(digest)
    digests_field = encode_lp(encode_lp(digest_record))      # [len(panel)][len(rec)][rec]
    certs_field = encode_lp(encode_lp(cert_der))             # [len(panel)][len(cert)][cert]
    min_sdk, max_sdk = 9, 0xFFFFFFFF

    if scheme == "v2":
        # signed data = [digests][certificates]; attributes omitted (empty)
        sd = digests_field + certs_field
        signature_record = (
            struct.pack("<I", SIG_RSA_PKCS1_SHA256)
            + encode_lp(key.sign_pkcs1(sd, "sha256"))
        )
        signer = (
            encode_lp(sd)
            + encode_lp(encode_lp(signature_record))          # [len(panel)][len(rec)][rec]
            + encode_lp(spki_der_for_rsa(key))                # [len][SPKI]
        )
    else:
        sd = (
            digests_field + certs_field
            + struct.pack("<I", min_sdk) + struct.pack("<I", max_sdk)
        )
        signature_record = (
            struct.pack("<I", SIG_RSA_PKCS1_SHA256)
            + encode_lp(key.sign_pkcs1(sd, "sha256"))
        )
        signer = (
            encode_lp(sd)
            + struct.pack("<I", min_sdk) + struct.pack("<I", max_sdk)
            + encode_lp(encode_lp(signature_record))
            + encode_lp(spki_der_for_rsa(key))
        )
    return signer


def build_v23_signed_apk(
    dest_path: str,
    package: str = "com.example.v2app",
    scheme: str = "v2",
    tamper: bool = False,
    seed: int = 20260101,
    expired_cert: bool = False,
) -> str:
    """Write a real v2- or v3-signed APK (whole-file scheme, AOSP wire format).

    ``tamper=True`` flips a byte inside the ZIP entries section AFTER the
    signature is computed, so verification must fail with a content-digest
    mismatch, exactly like a repacked APK.
    """
    from masanalyzer.android.apksigv2 import (
        APK_SIG_BLOCK_MAGIC,
        V2_BLOCK_ID,
        V3_BLOCK_ID,
        encode_lp,
    )

    entries = {
        "AndroidManifest.xml": manifest_axml(package, "1.0"),
        "classes.dex": build_dex(strings=(b"com/example/v23app", b"doWork")),
        "res/values/strings.xml": b"<resources><string name=\"app\">fixture</string></resources>",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, blob in sorted(entries.items()):
            z.writestr(name, blob)
    data = buf.getvalue()

    eocd_pos = data.rfind(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<I", data, eocd_pos + 16)

    key = rsa_keypair(seed)
    cert = cert_der_for_rsa(
        key,
        not_before=b"150101000000Z" if expired_cert else b"260101000000Z",
        not_after=b"200301000000Z" if expired_cert else b"340101000000Z",
    )

    def assemble(digest: bytes) -> Tuple[bytes, int]:
        signer = _v23_signer_blob(key, cert, digest, scheme)
        signers_value = encode_lp(encode_lp(signer))
        pairs = b""
        block_id = V2_BLOCK_ID if scheme == "v2" else V3_BLOCK_ID
        value = signers_value
        pairs += struct.pack("<Q", 4 + len(value)) + struct.pack("<I", block_id) + value
        block_size = len(pairs) + 24
        block = (
            struct.pack("<Q", block_size) + pairs
            + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
        )
        # final file = entries || block || CD || EOCD(cd offset patched)
        out = bytearray(data)
        out[cd_offset:cd_offset] = block
        struct.pack_into("<I", out, eocd_pos + len(block) + 16, cd_offset + len(block))
        return bytes(out), len(block)

    placeholder, block_len = assemble(b"\x00" * 32)
    # section 4 digest uses the EOCD with its CD-offset field replaced by
    # the signing block offset (AOSP rule)
    eocd = bytearray(placeholder[eocd_pos + block_len :])
    struct.pack_into("<I", eocd, 16, cd_offset)
    digest = _v23_digest(
        [
            placeholder[0:cd_offset],                                    # section 1
            placeholder[cd_offset + block_len : eocd_pos + block_len],   # section 3
            bytes(eocd),                                                 # section 4
        ],
        "sha256",
    )
    signed, _ = assemble(digest)

    if tamper:
        out = bytearray(signed)
        # target a byte inside the entries section (classes.dex payload)
        out[cd_offset // 2] ^= 0xFF
        signed = bytes(out)
    with open(dest_path, "wb") as fh:
        fh.write(signed)
    return dest_path

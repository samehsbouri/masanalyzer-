"""M7 - Insufficient Binary Protections.

Compiler-level hardening (PIE, executable stack, code signing seal),
reverse-engineering resistance (obfuscation / symbol stripping) and
debuggable dev builds reachable in release.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, iter_pool, make_rule

LOW = Severity.LOW
MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
INFO = Severity.INFO

R_DEBUG_BUILD = make_rule(
    "MAS-BIN-001",
    "M7",
    "Debuggable release build",
    "android:debuggable=\"true\" (or a get-task-allow provisioning profile) "
    "lets a debugger attach to the production process on a rooted/idle "
    "device, exposing everything in memory.",
    HIGH,
    "Ship release builds with debuggable=false and enterprise provisioning "
    "without get-task-allow.",
    cwe="CWE-489",
    confidence=Confidence.HIGH,
    cvss=7.0,
)

R_NO_PIE_SO = make_rule(
    "MAS-BIN-002",
    "M7",
    "Native library compiled without position independence (no PIE)",
    "An .so image is an ET_EXEC (fixed load address) instead of ET_DYN, "
    "disabling ASLR for that module and making exploit code layout static.",
    HIGH,
    "Build with -fPIC -pie; verify ELF e_type==ET_DYN per ABI.",
    cwe="CWE-1301",
    confidence=Confidence.HIGH,
    cvss=7.5,
)

R_EXE_STACK_SO = make_rule(
    "MAS-BIN-003",
    "M7",
    "Native library with executable stack",
    "PT_GNU_STACK is marked RWE for one of the shipped .so files, weakening "
    "NX and enabling ROP/JOP chains directly from attacker-controlled data.",
    HIGH,
    'Build with -z noexecstack (default since GCC 4.8) and check with "readelf -l".',
    cwe="CWE-1234",
    confidence=Confidence.HIGH,
    cvss=7.8,
)

R_NO_PIE_MACHO = make_rule(
    "MAS-BIN-004",
    "M7",
    "Mach-O image lacks PIE (MH_PIE absent)",
    "The executable is not position independent; ASLR slide is not applied to "
    "the main image, which eases memory-corruption exploitation.",
    HIGH,
    "Build with the PIE linker flag (Xcode default for iOS 8+).",
    cwe="CWE-1301",
    confidence=Confidence.HIGH,
    cvss=7.5,
    platform="ios",
)

R_EXE_STACK_MACHO = make_rule(
    "MAS-BIN-005",
    "M7",
    "Mach-O image allows executable stack",
    "MH_ALLOW_STACK_EXECUTION is set - macOS/iOS NX is bypassed for the "
    "stack of this image.",
    HIGH,
    "Rebuild without -allow_stack_execute.",
    cwe="CWE-1234",
    confidence=Confidence.HIGH,
    cvss=7.8,
    platform="ios",
)

R_DEX_OBFUSCATION = make_rule(
    "MAS-BIN-006",
    "M7",
    "Byte code not obfuscated",
    "Class and package names in the DEX remain business-meaningful (no "
    "ProGuard/R8 pass) so reverse engineering cost is near zero.",
    MEDIUM,
    "Enable minifyEnabled=true with R8 (or a proven obfuscator) for the "
    "release build.",
    cwe="CWE-693",
    confidence=Confidence.HIGH,
    cvss=4.0,
)

R_SYMBOL_RICH_MACHO = make_rule(
    "MAS-BIN-007",
    "M7",
    "Mach-O keeps complete symbol table",
    "The image embeds a full symtab with application-local symbols; "
    "class/method intent is readable by static tools.",
    MEDIUM,
    "Strip local symbols of release builds (-Xlinker -strip-all).",
    cwe="CWE-693",
    confidence=Confidence.MEDIUM,
    cvss=4.2,
    platform="ios",
)

R_DEBUG_PROFILE = make_rule(
    "MAS-BIN-008",
    "M7",
    "Development provisioning profile (get-task-allow)",
    "The embedded.mobileprovision grants debugging to the install, so a dev "
    "build can be attached to and inspected by anyone with device access.",
    MEDIUM,
    "Distribute App-Store/ad-hoc profiles without get-task-allow.",
    cwe="CWE-489",
    confidence=Confidence.HIGH,
    cvss=5.5,
    platform="ios",
)

R_NO_FULL_RELRO = make_rule(
    "MAS-BIN-011",
    "M7",
    "Native library without full RELRO / with writable text",
    "The camera-qualified .so either lacks a PT_GNU_RELRO segment (GOT/"
    "function pointers stay writable at runtime) or accepts DT_TEXTREL "
    "(the text segment itself is patchable after relocation). With the "
    "GOT writable, an overwrite gives instant code flow control "
    "(lazy-binding sieges).",
    MEDIUM,
    "Link with -z relro -z now (and avoid text relocations); verify with "
    '"readelf -d" (BIND_NOW / FLAGS BIND_NOW) and "readelf -l" (GNU_RELRO).',
    cwe="CWE-693",
    confidence=Confidence.HIGH,
    cvss=4.5,
)

R_CODESIGN_BROKEN_IOS = make_rule(
    "MAS-BIN-012",
    "M7",
    "iOS code signature verification FAILED",
    "The image advertises an LC_CODE_SIGNATURE blob, but the embedded "
    "CodeDirectory does not verify: the SuperBlob is malformed, page-wise "
    "SHA-256 hashes differ from the file contents (the binary was "
    "modified after signing), or the blob cannot be parsed at all. On a "
    "hardened runtime this is install-time rejection; statically it is "
    "tampering evidence.",
    HIGH,
    "Re-sign the image with codesign --sign; treat a mismatching shipped "
    "binary as a compromised build.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=7.5,
    platform="ios",
)


R_NO_CANARY_SO = make_rule(
    "MAS-BIN-019",
    "M7",
    "Native library compiled without stack canaries",
    "The .so imports no ``__stack_chk_fail``/``__stack_chk_guard`` symbol, "
    "i.e. it was built without ``-fstack-protector-strong``. Stack buffer "
    "overflows then proceed without the canary abort, making a classic "
    "smash-the-stack exploit reliably exploitable.",
    MEDIUM,
    "Compile with ``-fstack-protector-strong`` (NDK default; verify the "
    "symbol is present with \"readelf -s | grep stack_chk\").",
    cwe="CWE-693",
    confidence=Confidence.MEDIUM,
    cvss=5.0,
    platform="android",
)

R_NO_FORTIFY_SO = make_rule(
    "MAS-BIN-020",
    "M7",
    "Native library compiled without FORTIFY_SOURCE",
    "The .so contains no fortified libc wrappers (``__memcpy_chk``, "
    "``__strlen_chk``, ...), i.e. it was built without "
    "``-D_FORTIFY_SOURCE=2``. Common string/memory functions stay "
    "unchecked, so overflow bugs that fortify would have aborted at "
    "runtime remain silent memory corruption.",
    LOW,
    "Add ``-D_FORTIFY_SOURCE=2`` (and -O) to the release build; "
    "NDK's default libc headers provide the fortified wrappers.",
    cwe="CWE-693",
    confidence=Confidence.MEDIUM,
    cvss=3.7,
    platform="android",
)


R_MISSING_SO = make_rule(
    "MAS-BIN-015",
    "M7",
    "Native library depends on a missing shared object",
    "A shipped ``.so`` declares a ``DT_NEEDED`` entry that is neither an "
    "Android system library nor another shipped ``.so``. The loader fails "
    "at ``System.loadLibrary`` on every device, so the native feature is "
    "dead on arrival (or the vendor forgot to ship their bundled "
    "crypto/parts).",
    HIGH,
    "Ship the referenced library inside the bundle (per-ABI) or link it "
    "statically; check the apks per ABI after adding dependencies.",
    cwe="CWE-1357",
    confidence=Confidence.HIGH,
    platform="android",
)

R_DLOPEN = make_rule(
    "MAS-BIN-013",
    "M7",
    "Native library resolves code dynamically at runtime",
    "The library imports ``dlopen``/``dlsym``. Runtime-resolved code "
    "evades this static analysis, integrity checkers and Play's "
    "monotonic manifest: the runtime payload is not covered by anything "
    "that was reviewed.",
    MEDIUM,
    "Eliminate runtime self-loading; load all native code from shipped, "
    "verified images (Play's compressed blobs re-verify hashes).",
    cwe="CWE-1357",
    confidence=Confidence.LOW,
    platform="android",
)

R_MEMEXEC = make_rule(
    "MAS-BIN-014",
    "M7",
    "Native library creates executable memory",
    "The library imports ``mprotect``/``memfd_create`` with respect to "
    "execution. Building W^X-busting or self-modifying code inside a "
    "shipped library is exactly what double-free/ROP loaders and clonking "
    "wrappers require.",
    MEDIUM,
    "Ship non-self-modifying code; where JIT is genuinely needed, use a "
    "documented allow-listed approach.",
    cwe="CWE-1357",
    confidence=Confidence.LOW,
    platform="android",
)

R_PTRACE_EXEC = make_rule(
    "MAS-BIN-016",
    "M7",
    "Native library launches processes or debug-hooks itself",
    "The library imports ``exec*``/``ptrace``. Forking shell processes "
    "from a shipped library or self-attaching via ptrace is the "
    "fingerprint of anti-analysis, jailbreak-style hacks and "
    "shell-driven configuration loaders.",
    LOW,
    "Remove process-spawning / ptrace paths from release binaries; "
    "send any legitimate behavior through platform APIs.",
    cwe="CWE-1357",
    confidence=Confidence.LOW,
    platform="android",
)

R_PACKER = make_rule(
    "MAS-BIN-017",
    "M7",
    "Packer / anti-disassembly wrapper detected",
    "The bundle carries identifiers characteristic of a commercial Android "
    "packer/protector (loader library, stub classes or encrypted-dex asset "
    "names). Packers encrypt classes.dex and rebuild it in a proprietary "
    "loader at runtime, defeating static review and frequently shipping "
    "privileged anti-debugging code in the loader.",
    MEDIUM,
    "Avoid third-party packers for release builds (app-store policy and "
    "auditability); if one is mandated by the vendor, document it and "
    "verify the loader is updated and reproducible.",
    cwe="CWE-1357",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_ROOT_TOOLING = make_rule(
    "MAS-BIN-018",
    "M7",
    "Superuser / instrumentation tooling referenced in the bundle",
    "The bundle references root-tooling packages (su managers, SuperSU, "
    "Xposed, Cydia Substrate or su binary paths). In a legitimate app this "
    "is usually root-detection logic; review that the reference is "
    "detection-only and cannot be abused to obtain elevated privileges.",
    MEDIUM,
    "Keep root/tooling references to detection-only code paths; never "
    "bundle or invoke superuser packages.",
    cwe="CWE-250",
    confidence=Confidence.LOW,
    platform="android",
)


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []
    platform = target.platform
    manifest = target.manifest
    manifest_path = target.meta.get("manifest_path") or "AndroidManifest.xml"

    if manifest is not None and manifest.debuggable:
        out.append(
            R_DEBUG_BUILD.finding(
                file=manifest_path,
                symbol="android:debuggable=\"true\"",
                note="flag parsed from the compiled AXML manifest",
            )
        )
    ipa = target.meta.get("ipa")
    if ipa is not None:
        # debuggable via profile in an IPA; the source-tree variant comes from
        # target.meta["provisioning"]
        if ipa.debuggable:
            out.append(
                R_DEBUG_PROFILE.finding(
                    file=str(getattr(ipa.profile, "descriptive_name", "") or
                             "embedded.mobileprovision"),
                    symbol="get-task-allow = true entitlement",
                    note="parsed from the IPA's embedded provisioning profile",
                )
            )
    prov = target.meta.get("provisioning")
    if prov is not None and platform == "ios":
        ents = getattr(prov, "entitlements", {}) or {}
        if ents.get("get-task-allow") is True:
            out.append(
                R_DEBUG_PROFILE.finding(
                    file=str(getattr(prov, "descriptive_name", "") or
                             "provisioning profile"),
                    symbol="get-task-allow = true entitlement",
                    note="parsed from the provisioning profile's "
                         "Entitlements dictionary",
                )
            )

    # Android native hardening ------------------------------------------------
    so_graph = target.meta.get("so_graph") or {}
    for lib in target.native_libs:
        flags = lib.flags or {}
        if flags.get("pie") is False and lib.arch in ("arm", "x86", "aarch64", "x86_64"):
            out.append(
                R_NO_PIE_SO.finding(
                    file=lib.relpath, symbol="ET_EXEC (position-dependent)",
                    note=f"arch={lib.arch}",
                )
            )
        if flags.get("executable_stack"):
            out.append(
                R_EXE_STACK_SO.finding(
                    file=lib.relpath,
                    symbol="PT_GNU_STACK p_flags |= PF_X",
                    note="stack is executable",
                )
            )
        if lib.platform == "android" and flags.get("pie") is not None:
            if flags.get("writable_text"):
                out.append(
                    R_NO_FULL_RELRO.finding(
                        file=lib.relpath,
                        symbol="DT_TEXTREL in .dynamic",
                        note="writable text segment (DT_TEXTREL present)",
                    )
                )
            elif "full_relro" in flags and not flags["full_relro"]:
                if not flags.get("relro"):
                    sym, note = "no PT_GNU_RELRO program header", "no GNU_RELRO"
                else:
                    sym, note = "no DT_BIND_NOW in .dynamic", "no BIND_NOW"
                out.append(
                    R_NO_FULL_RELRO.finding(file=lib.relpath, symbol=sym, note=note)
                )
            # compiled-in hardening observed in the dynamic symbol table:
            # only when the symbol table was actually seen (pie parsed),
            # otherwise every stripped-in-odd-way image would be flagged.
            if "canary" in flags and not flags.get("canary"):
                out.append(
                    R_NO_CANARY_SO.finding(
                        file=lib.relpath,
                        symbol="__stack_chk_fail absent from imports",
                        note="no stack canary reference in the symbol table",
                    )
                )
            if "fortified" in flags and not flags.get("fortified"):
                out.append(
                    R_NO_FORTIFY_SO.finding(
                        file=lib.relpath,
                        symbol="no __*_chk imports",
                        note="no FORTIFY_SOURCE wrappers in the symbol table",
                    )
                )

        # .so dependency graph evidence
        dangerous = set(lib.dangerous or [])
        if dangerous & {"dlopen", "dlsym"}:
            out.append(
                R_DLOPEN.finding(
                    file=lib.relpath,
                    note="imports " + "/".join(sorted(dangerous & {"dlopen", "dlsym"})),
                )
            )
        if dangerous & {"mprotect", "memfd_create"}:
            out.append(
                R_MEMEXEC.finding(
                    file=lib.relpath,
                    note="imports "
                    + "/".join(sorted(dangerous & {"mprotect", "memfd_create"})),
                )
            )
        if dangerous & {"execve", "execl", "execvp", "execvpe", "ptrace"}:
            out.append(
                R_PTRACE_EXEC.finding(
                    file=lib.relpath,
                    note="imports " + "/".join(
                        sorted(dangerous & {"execve", "execl", "execvp", "execvpe", "ptrace"})
                    ),
                )
            )
        missing = (so_graph.get("missing") or {}).get(lib.relpath)
        if missing:
            out.append(
                R_MISSING_SO.finding(
                    file=lib.relpath,
                    note="DT_NEEDED without a provider: " + ", ".join(missing[:3]),
                )
            )

    # iOS native --------------------------------------------------------------
    for img in target.meta.get("macho", []) or []:
        rel = _macho_relpath(target, img)
        if not img.has_pie:
            out.append(R_NO_PIE_MACHO.finding(file=rel))
        if img.stack_executable:
            out.append(R_EXE_STACK_MACHO.finding(file=rel))
        if getattr(img, "code_signature_verified", None) is False:
            out.append(
                R_CODESIGN_BROKEN_IOS.finding(
                    file=rel,
                    note="; ".join(
                        getattr(img, "code_signature_reasons", [])[:2]
                    )
                    or "signature does not verify",
                )
            )
        symbols = [s for s in (img.symbols or []) if s and not s.startswith("_NS")]
        if len(symbols) >= 20:
            out.append(
                R_SYMBOL_RICH_MACHO.finding(
                    file=rel, note=f"{len(symbols)} local symbols retained"
                )
            )

    # DEX obfuscation -----------------------------------------------------------
    dex_files = target.meta.get("dex", []) or target.meta.get("dex_files", [])
    total_classes = 0
    obfuscated = False
    for dex in dex_files:
        classes = list(getattr(dex, "classes", None) or [])
        total_classes += len(classes)
    for dex in dex_files:
        if getattr(dex, "obfuscated", lambda: False)():
            obfuscated = True
    if total_classes >= 20 and not obfuscated:
        out.append(
            R_DEX_OBFUSCATION.finding(
                file=target.meta.get("manifest_path", "app/bundle"),
                note=f"{total_classes} classes, meaningful package names retained",
            )
        )

    _packer_and_root(out, target)
    return out


# -- packer / root-tooling signatures (MobSF/APKiD parity) --------------------
#: substring -> packer/protector product (case-insensitive).  Self-authored
#: list of the widely documented loader names shipped by commercial Android
#: packers; matching one identifier is factual, the product attribution is
#: the known purpose of that identifier.
_PACKER_SIGNATURES: Tuple[Tuple[str, str], ...] = (
    ("libjiagu", "Qihoo 360 Jiagu"),
    ("libprotectclass", "Qihoo 360 Jiagu"),
    ("stubapp", "Qihoo 360 Jiagu"),
    ("com.qihoo.util", "Qihoo 360 Jiagu"),
    ("libshella", "Tencent Legu"),
    ("libshellx", "Tencent Legu"),
    ("libtup", "Tencent Legu"),
    ("com.tencent.stubshell", "Tencent Legu"),
    ("libexecmain", "Ijiami"),
    ("ijiami.dat", "Ijiami"),
    ("ijiami.ajm", "Ijiami"),
    ("libdexhelper", "Bangcle / SecNeo"),
    ("libsecexe", "Bangcle / SecNeo"),
    ("libsecmain", "Bangcle / SecNeo"),
    ("com.secneo", "Bangcle / SecNeo"),
    ("libbaiduprotect", "Baidu packer"),
    ("libchaosvmp", "AppSanguino"),
    ("libddog", "AppSanguino"),
    ("libfdog", "AppSanguino"),
    ("libnesec", "NetEase Yidun"),
    ("libmobisec", "Alibaba Mobile Secure"),
    ("libkwscmm", "Tencent Kiwi"),
    ("libkwscr", "Tencent Kiwi"),
    ("libkwsgmain", "Tencent Kiwi"),
    ("libdexprotector", "DexProtector"),
)

#: substring -> root / instrumentation tooling
_ROOT_TOOLING: Tuple[Tuple[str, str], ...] = (
    ("com.noshufou.android.su", "Superuser (noshufou)"),
    ("com.thirdparty.superuser", "Superuser (thirdparty)"),
    ("eu.chainfire.supersu", "SuperSU"),
    ("com.koushikdutta.superuser", "Superuser (KoushikDutta)"),
    ("com.saurik.substrate", "Cydia Substrate"),
    ("de.robv.android.xposed", "Xposed"),
    ("com.topjohnwu.superuser", "libsu root-execution library"),
    ("com.stericson.roottools", "RootTools root-execution library"),
    ("com.stericson.rootshell", "RootShell root-execution library"),
    ("superuser.apk", "Superuser.apk"),
    ("/system/xbin/su", "su binary path"),
    ("/system/bin/su", "su binary path"),
    ("/sbin/su", "su binary path"),
)


def _expand_signatures(
    sigs: Tuple[Tuple[str, str], ...],
) -> Tuple[Tuple[str, str], ...]:
    """Package names must match both dotted and DEX-descriptor forms."""
    out: list = []
    for sig, label in sigs:
        out.append((sig, label))
        if "." in sig and "/" not in sig:
            out.append((sig.replace(".", "/"), label))
    return tuple(out)


_PACKER_SIGNATURES = _expand_signatures(_PACKER_SIGNATURES)
_ROOT_TOOLING = _expand_signatures(_ROOT_TOOLING)

#: source-level root-execution shapes: Runtime.exec("su"), exec("/system/bin/su"),
#: ProcessBuilder("su", "-c", ...), os.system("su …")
_RX_SU_EXEC = re.compile(
    r"(?:\.exec|ProcessBuilder)\s*\(\s*[\"'][^\"\n]{0,80}\bsu\b[\"']"
    r"|os\.system\s*\(\s*[\"']su\b"
)


def _packer_and_root(out: List, target: Target) -> None:
    """Signature matches over bundle file names and the shared string pool."""
    seen: set = set()

    def emit(rule, file: str, sym: str, note: str, line: int = 0,
             snippet: str = "") -> None:
        key = (rule.rule_id, file, sym or snippet)
        if key in seen:
            return
        seen.add(key)
        kw: dict = dict(file=file, symbol=sym, note=note)
        if line:
            kw["line"] = line
        if snippet:
            kw["snippet"] = snippet
        out.append(rule.finding(**kw))

    # root-execution call sites: distinguish executing su from referencing it
    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        m = _RX_SU_EXEC.search(text)
        if m:
            emit(R_ROOT_TOOLING, sf.relpath, "", 
                 "root-execution call site: shell 'su' invocation; "
                 "root-detection code would only probe, not execute",
                 line=lineno, snippet=sf.line_at(lineno) or text)

    for sf in target.files:
        low = sf.relpath.lower()
        for sig, label in _PACKER_SIGNATURES:
            if sig in low:
                emit(R_PACKER, sf.relpath, sf.relpath,
                     f"file name matches {label} packer signature")
                break

    for rel, value in iter_pool(target):
        low = value.lower()
        for sig, label in _PACKER_SIGNATURES:
            if sig in low:
                emit(R_PACKER, rel, value[:80],
                     f"string matches {label} packer signature")
                break
        for sig, label in _ROOT_TOOLING:
            if sig in low:
                emit(R_ROOT_TOOLING, rel, value[:80],
                     f"references {label}")
                break


def _macho_relpath(target: Target, img) -> str:
    ipa = target.meta.get("ipa")
    if ipa is not None and getattr(ipa, "macho_paths", None):
        for rel in ipa.macho_paths:
            return rel
    return target.name

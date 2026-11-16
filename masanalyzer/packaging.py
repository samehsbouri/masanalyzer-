"""Packaging: turn an APK/IPA/zip/unpacked-tree input into a ready-to-scan
:class:`masanalyzer.model.Target`.

The pipeline is:

1. **classify** the input (APK zip, IPA zip, iOS ``.app`` tree, Android
   ``app/`` source tree, arbitrary tree).
2. **unpack** zip containers into a temporary work directory.
3. **classify every recovered file** into a :class:`ScanFile` with a kind
   (code / smali / manifest / plist / resource / native / binary / other)
   and a SHA-256.
4. **enrich** the target with platform metadata parsed by the dedicated
   parsers (manifest, DEX strings, arsc strings, network security config,
   APK signing, Info.plist, provisioning profile, Mach-O images, ELF info).
5. build the shared ``string_pool``: ``(relpath, string)`` tuples harvested
   from binaries so regex analyzers can see inside DEX / .so / Mach-O
   without shelling out to ``strings``.

Everything is stdlib-only and defensive: a corrupt member must never abort
a scan; it becomes a warning recorded in ``target.meta["warnings"]``.
"""

from __future__ import annotations

import os
import io
import shutil
import struct
import tempfile
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .model import NativeLib, ScanFile, Target
from .utils import (
    extract_printable_strings,
    is_probably_binary,
    safe_relpath,
    sha256_file,
    sha256_bytes,
)

#: maximum number of strings harvested from one binary
MAX_STRINGS_PER_FILE = 8000
#: upper bound for the whole target's string pool
MAX_POOL_TOTAL = 60000

CODE_KIND = "code"
SMALI_KIND = "smali"
MANIFEST_KIND = "manifest"
PLIST_KIND = "plist"
RESOURCE_KIND = "resource"
NATIVE_KIND = "native"
BINARY_KIND = "binary"
OTHER_KIND = "other"

_WARNS = "warnings"


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def prepare_target(
    input_path: str,
    work_root: Optional[str] = None,
    keep_work_dir: bool = False,
) -> Target:
    """Classify, unpack and enrich ``input_path`` into a Target."""
    path = os.path.abspath(input_path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    if os.path.isdir(path):
        return _finish(_target_from_tree(path))

    with open(path, "rb") as fh:
        head = fh.read(8)

    if head[:2] == b"PK" and zipfile.is_zipfile(path):
        container = _zip_platform(path, head)
        if container == "ios":
            return _finish(_target_from_ipa(path, work_root, keep_work_dir))
        name = os.path.basename(path).lower()
        if name.endswith(".apks"):
            return _finish(_target_from_apks(path, work_root, keep_work_dir))
        if name.endswith(".aab"):
            return _finish(_target_from_aab(path, work_root, keep_work_dir))
        return _finish(_target_from_apk(path, work_root, keep_work_dir))

    if head[:4] == b"\x7fELF":
        # a lone native library scanned directly
        target = Target(input_path=path, platform="android", work_dir=os.path.dirname(path))
        _add_file(target, path, os.path.basename(path), kind=NATIVE_KIND)
        target.name = os.path.basename(path)
        return _finish(target)

    # unknown file: scan it as a text/binary blob
    target = Target(input_path=path, platform="unknown", work_dir=os.path.dirname(path))
    _add_file(target, path, os.path.basename(path))
    target.name = os.path.basename(path)
    return _finish(target)


def _finish(target: Target) -> Target:
    """Post-enrichment shared by every container: inventory layers."""
    from .endpoints import build_inventory

    try:
        build_inventory(target)
    except Exception as exc:  # noqa: BLE001 - inventory is best effort
        target.meta.setdefault("warnings", []).append(f"endpoints: {exc}")

    # excess-access privacy matrix (dangerous permissions x observed APIs)
    if getattr(target, "manifest", None) is not None:
        try:
            from .analysis.privacy import build_privacy_matrix

            build_privacy_matrix(target)
        except Exception as exc:  # noqa: BLE001 - matrix is best effort
            target.meta.setdefault("warnings", []).append(
                f"privacy_matrix: {exc}"
            )

    # embedded SDK fingerprinting (feature: composition analysis). Only run
    # where DEX tables / a string pool exist - pure ELF/plist targets have
    # nothing for the curated signatures to match. iOS targets always run:
    # the framework-bundle detector needs no string source.
    if (target.meta.get("dex_files") or target.string_pool
            or target.platform == "ios"):
        try:
            from .sdks import detect_sdks

            detect_sdks(target)
        except Exception as exc:  # noqa: BLE001 - best effort
            target.meta.setdefault("warnings", []).append(f"sdks: {exc}")
    return target


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------
def _zip_platform(path: str, head: bytes) -> str:
    """Decide whether ``path`` is an APK-ish or an IPA-ish archive."""
    name = os.path.basename(path).lower()
    if name.endswith(".ipa"):
        return "ios"
    if name.endswith(".apk") or name.endswith(".aab"):
        return "android"
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
        for n in names[:200]:
            low = n.lower()
            if low == "androidmanifest.xml" or low.endswith("/androidmanifest.xml"):
                return "android"
            if low.startswith("payload/") and ".app/" in low:
                return "ios"
    except Exception:  # pragma: no cover - defensive
        pass
    if head[:4] == b"bplist00" or head[:4] == b"\xcf\xfa\xed\xfe":
        return "ios"
    return "android"


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------
def _fresh_work_dir(work_root: Optional[str], hint: str) -> str:
    if work_root:
        work = os.path.abspath(os.path.join(work_root, hint))
        if os.path.isdir(work):
            shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work, exist_ok=True)
        return work
    return tempfile.mkdtemp(prefix=f"masan_{hint}_")


def _target_from_apk(path: str, work_root: Optional[str], keep: bool) -> Target:
    from .android.apk import unpack_apk

    work = _fresh_work_dir(work_root, "apk")
    apk_info = unpack_apk(path, work)
    target = Target(
        input_path=path,
        platform="android",
        work_dir=work,
        name=os.path.basename(path),
    )
    target.meta["apk"] = apk_info
    target.meta["container"] = "apk"
    if keep:
        target.meta["keep_work_dir"] = True
    _load_idsig(target, path)
    _collect_tree_files(target, work, rel_base=work)
    _android_info(target)
    _android_native(target)
    _android_strings(target)
    return target


def _target_from_apks(path: str, work_root: Optional[str], keep: bool) -> Target:
    """An ``.apks`` APK-Set archive: base APK primary + split APKs merged."""
    work = _fresh_work_dir(work_root, "apks")
    app_dir = os.path.join(work, "base")
    splits_root = os.path.join(work, "splits")
    os.makedirs(app_dir, exist_ok=True)

    with zipfile.ZipFile(path) as zf:
        inner = sorted(
            (m for m in zf.infolist()
             if not m.is_dir() and m.filename.lower().endswith(".apk")
             and "/" not in m.filename),
            key=lambda m: (m.filename != "base.apk", -m.file_size, m.filename),
        )
    if not inner:
        # not really an APK set: fall back to plain APK handling
        return _target_from_apk(path, work_root, keep)
    primary, splits = inner[0], inner[1:]

    from .android.apk import unpack_apk

    primary_path = os.path.join(work, primary.filename)
    with zipfile.ZipFile(path) as zf:
        primary_path = zf.extract(primary, work)
    apk_info = unpack_apk(primary_path, app_dir)
    target = Target(
        input_path=path,
        platform="android",
        work_dir=app_dir,
        name=os.path.basename(path),
    )
    target.meta["apk"] = apk_info
    target.meta["container"] = "apks"
    target.meta["base_apk"] = primary.filename
    split_rows: List[Dict[str, Any]] = []
    for split in splits:
        stem = os.path.splitext(split.filename)[0]
        dest = os.path.join(splits_root, stem)
        os.makedirs(dest, exist_ok=True)
        merged = 0
        try:
            with zipfile.ZipFile(path) as zf:
                with zipfile.ZipFile(io.BytesIO(zf.read(split))) as inner_zip:
                    keep_members = [
                        n for n in inner_zip.namelist()
                        if n.lower() != "androidmanifest.xml"
                        and not n.lower().startswith("meta-inf/")
                        and not n.endswith("/")
                    ]
                    inner_zip.extractall(dest, members=keep_members)
                    merged = len(keep_members)
        except (zipfile.BadZipFile, OSError) as exc:
            target.meta.setdefault(_WARNS, []).append(
                f"split {split.filename}: {exc}"
            )
        split_rows.append({"apk": split.filename, "entries": merged})
        _collect_tree_files(target, dest, rel_base=splits_root)
    target.meta["splits"] = split_rows
    if keep:
        target.meta["keep_work_dir"] = True
    _load_idsig(target, path)
    _collect_tree_files(target, app_dir, rel_base=app_dir)
    _android_info(target)
    _android_native(target)
    _android_strings(target)
    return target


def _target_from_aab(path: str, work_root: Optional[str], keep: bool) -> Target:
    """An Android App Bundle: flattened bundle tree; protobuf manifest skipped."""
    work = _fresh_work_dir(work_root, "aab")
    with zipfile.ZipFile(path) as zf:
        try:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                zf.extract(member, work)
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            target = Target(input_path=path, platform="android", work_dir=work)
            target.meta.setdefault(_WARNS, []).append(f"unpack: {exc}")
            return target

    target = Target(
        input_path=path,
        platform="android",
        work_dir=work,
        name=os.path.basename(path),
    )
    target.meta["container"] = "aab"
    if keep:
        target.meta["keep_work_dir"] = True
    _collect_tree_files(target, work, rel_base=work)
    # protobuf blocks: bundle format stores manifest/resources/dex metadata as
    # .pb (or as binary AXML-less manifest) - mark them so the enrichment
    # layer skips protobuf-only payloads instead of raising parse noise.
    proto_manifests: List[str] = []
    for sf in target.files:
        low = sf.relpath.replace("\\", "/").lower()
        if sf.kind == MANIFEST_KIND:
            try:
                with open(sf.path, "rb") as fh:
                    head = fh.read(4)
            except OSError:
                head = b""
            if head[:2] != b"\x03\x00":          # not compiled AXML
                sf.kind = BINARY_KIND
                proto_manifests.append(sf.relpath)
        elif low.endswith(".pb"):
            sf.kind = BINARY_KIND
    if proto_manifests:
        target.meta["aab_proto_manifests"] = proto_manifests
        target.meta.setdefault(_WARNS, []).append(
            "aab: protobuf manifest not convertible without bundletool; "
            "scanned the flattened bundle tree "
            + (", ".join(proto_manifests))
        )
    _android_info(target)
    _android_native(target)
    _android_strings(target)
    return target


def _target_from_ipa(path: str, work_root: Optional[str], keep: bool) -> Target:
    from .ios.ipa import load_ipa

    work = _fresh_work_dir(work_root, "ipa")
    ipa_info = load_ipa(path)
    try:
        with zipfile.ZipFile(path) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                zf.extract(member, work)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        ipa_info.warnings.append(f"unpack: {exc}")
    ipa_info.path = path

    target = Target(
        input_path=path,
        platform="ios",
        work_dir=work,
        name=ipa_info.bundle_name or os.path.basename(path),
        package=ipa_info.bundle_identifier,
        version=ipa_info.version,
    )
    target.meta["ipa"] = ipa_info
    target.meta["container"] = "ipa"
    target.meta["macho"] = list(ipa_info.macho_images)
    if ipa_info.profile is not None:
        target.meta["provisioning"] = ipa_info.profile
    target.plist = dict(ipa_info.info_plist)
    target.meta["plists"] = {p: d for p, d in ipa_info.plists.items()}
    _collect_tree_files(target, work, rel_base=work)
    _ios_binaries(target)
    _ios_strings(target)
    return target


def _target_from_tree(path: str) -> Target:
    target = Target(input_path=path, platform="unknown", work_dir=path)
    _collect_tree_files(target, path, rel_base=path)

    is_ios = any(
        ".app/" in f.relpath.lower().replace("\\", "/")
        or f.relpath.lower().replace("\\", "/").startswith("payload/")
        or "/payload/" in f.relpath.lower().replace("\\", "/")
        for f in target.files
    )
    if not is_ios and _find_manifest(target):
        is_ios = False

    if is_ios:
        from .ios.ipa import bundle_info_from_dir

        ipa_info = bundle_info_from_dir(_ios_bundle_root(target, path))
        target.platform = "ios"
        target.meta["ipa"] = ipa_info
        target.meta["macho"] = list(ipa_info.macho_images)
        if ipa_info.profile is not None:
            target.meta["provisioning"] = ipa_info.profile
        target.plist = dict(ipa_info.info_plist)
        target.meta["plists"] = {p: d for p, d in ipa_info.plists.items()}
        target.name = ipa_info.bundle_name or target.name
        target.package = ipa_info.bundle_identifier
        target.version = ipa_info.version
        _reclassify_plists(target)
        _ios_binaries(target)
        _ios_strings(target)
        return target

    if _find_manifest(target):
        target.platform = "android"
        _reclassify_plists(target)
        _android_info(target)
        _android_native(target)
        _android_strings(target)
        return target

    # mixed/unknown tree: best effort text scan
    _reclassify_plists(target)
    _harvest_strings(target)
    return target


# --------------------------------------------------------------------------
# file inventory
# --------------------------------------------------------------------------
def _collect_tree_files(target: Target, root: str, rel_base: Optional[str] = None) -> None:
    base = rel_base or root
    pending: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = safe_relpath(full, base)
            pending.append((full, rel))

    # big bundles: hash + classify concurrently; results land in input
    # (os.walk) order via executor.map, so the inventory stays deterministic
    if len(pending) >= _FILES_PARALLEL_THRESHOLD:
        _add_files_concurrent(target, pending)
    else:
        for full, rel in pending:
            _add_file(target, full, rel)


#: at/above this file count the (hash-bound) inventory runs on a thread pool
_FILES_PARALLEL_THRESHOLD = 24


def _add_files_concurrent(target: Target, pending) -> None:
    """Hash + classify ``pending`` on a thread pool; append results itself.

    Only the (hash-bound) work runs concurrently: ``ScanFile`` records are
    appended back on the calling thread in input order, so the inventory,
    and every downstream pool/index built from it, stays byte-identical
    to the serial path (thread scheduling must not reorder the target).
    """
    from concurrent.futures import ThreadPoolExecutor

    workers = min(8, (os.cpu_count() or 2))

    def _hash_one(item):
        full, rel = item
        rel = rel.replace("\\", "/").lstrip("/")
        try:
            size = os.path.getsize(full)
        except OSError:
            size = 0
        digest = sha256_file(full)  # the expensive part: read the whole file
        try:
            kind = _classify(full, rel)
        except Exception:  # noqa: BLE001 - fall back below
            kind = None
        return full, rel, size, digest, kind

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_hash_one, pending))
    for full, rel, size, digest, kind in results:
        sf = ScanFile(path=full, relpath=rel, size=size, sha256=digest)
        sf.kind = kind if kind is not None else _classify(full, rel)
        target.files.append(sf)


def _add_file(
    target: Target,
    full: str,
    rel: str,
    kind: Optional[str] = None,
) -> ScanFile:
    rel = rel.replace("\\", "/").lstrip("/")
    try:
        size = os.path.getsize(full)
    except OSError:
        size = 0
    sf = ScanFile(path=full, relpath=rel, size=size, sha256=sha256_file(full))
    if kind is None:
        kind = _classify(full, rel)
    sf.kind = kind
    target.files.append(sf)
    return sf


def _classify(full: str, rel: str) -> str:
    name = os.path.basename(rel).lower()
    suffix = os.path.splitext(rel)[1].lower()
    low = rel.lower()

    if name == "androidmanifest.xml" or low.endswith("/androidmanifest.xml"):
        return MANIFEST_KIND
    if suffix in (".java", ".kt", ".kts"):
        return CODE_KIND
    if suffix == ".smali":
        return SMALI_KIND
    if suffix in (".m", ".mm", ".swift", ".h", ".hpp", ".c", ".cpp", ".cs", ".js"):
        return CODE_KIND
    if suffix == ".plist":
        try:
            with open(full, "rb") as fh:
                magic = fh.read(8)
        except OSError:
            magic = b""
        if magic[:8] == b"bplist00":
            return BINARY_KIND
        return PLIST_KIND
    if low.endswith(".mobileprovision"):
        return BINARY_KIND
    if suffix == ".so" or "/lib/" in low and suffix in (".a", ".dylib"):
        return NATIVE_KIND
    if suffix == ".dex":
        return BINARY_KIND
    if suffix in (".xml", ".txt", ".json", ".yml", ".yaml", ".properties", ".gradle",
                  ".pro", ".md", ".html", ".csv", ".ini", ".cfg", ".conf", ".sql",
                  ".pem", ".cer", ".key", ".plist", ".entitlements"):
        return RESOURCE_KIND
    # unknown: sniff whether it is text
    try:
        with open(full, "rb") as fh:
            sample = fh.read(4096)
    except OSError:
        sample = b""
    if is_probably_binary(sample):
        return BINARY_KIND
    return RESOURCE_KIND


def _find_manifest(target: Target) -> Optional[ScanFile]:
    for f in target.files:
        if f.kind == MANIFEST_KIND:
            return f
    return None


# --------------------------------------------------------------------------
# Android enrichment
# --------------------------------------------------------------------------
def _android_info(target: Target) -> None:
    """Attach manifest, resources, NSC, dex objects to an android target."""
    warnings = target.meta.setdefault(_WARNS, [])

    # manifest ------------------------------------------------------------
    manifest_file = _find_manifest(target)
    manifest = None
    if manifest_file is not None:
        try:
            with open(manifest_file.path, "rb") as fh:
                manifest = Manifest_parse(fh.read())
        except Exception as exc:
            warnings.append(f"{manifest_file.relpath}: {exc}")
    if manifest is not None:
        target.manifest = manifest
        target.package = manifest.package or target.package
        target.version = manifest.version_name or target.version
        if not target.name:
            target.name = manifest.application_label or target.package
        target.meta["manifest_path"] = manifest_file.relpath

    # resources ------------------------------------------------------------
    arsc = target.get("resources.arsc")
    if arsc is not None:
        try:
            from .android.resources import parse_resource_table

            with open(arsc.path, "rb") as fh:
                table = parse_resource_table(fh.read())
            target.meta["resources"] = table
        except Exception as exc:
            warnings.append(f"resources.arsc: {exc}")
        try:
            from .android.resources import resource_strings

            with open(arsc.path, "rb") as fh:
                ids = resource_strings(fh.read())
            if ids:
                target.meta["resource_strings"] = ids
                # resolve @res/0x... labels (app name) to their strings
                label = getattr(target.manifest, "application_label", None) \
                    if getattr(target, "manifest", None) is not None else None
                if isinstance(label, str) and label.startswith("@res/"):
                    rid = _parse_res_id(label)
                    resolved = ids.get(rid) if rid is not None else None
                    if resolved:
                        target.manifest.application_label = resolved
                        if not target.name or target.name.startswith("@res/"):
                            target.name = resolved
        except Exception as exc:  # noqa: BLE001 - cosmetic, never fatal
            warnings.append(f"resources.arsc ids: {exc}")

    # network security config ----------------------------------------------
    nsc_file = _find_nsc(target, manifest)
    if nsc_file is not None:
        try:
            from .android.resources import NetworkSecurityConfig

            with open(nsc_file.path, "rb") as fh:
                raw = fh.read()
            target.meta["network_security_config"] = NetworkSecurityConfig.parse(
                raw, path=nsc_file.relpath
            )
        except Exception as exc:
            warnings.append(f"{nsc_file.relpath}: {exc}")

    # DEX ------------------------------------------------------------------
    from .android.dex import is_dex, parse_dex

    dex_files: List[Any] = []
    for sf in target.files:
        if sf.suffix != ".dex":
            continue
        try:
            with open(sf.path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            warnings.append(f"{sf.relpath}: {exc}")
            continue
        if not is_dex(blob):
            continue
        try:
            dex = parse_dex(blob)
            dex.relpath = sf.relpath  # added attribute: pool/evidence labeling
            try:
                dex.analyze_callsites()   # bytecode layer: URL -> callee receipts
            except Exception as exc:
                warnings.append(f"{sf.relpath}: callsites: {exc}")
            meta_dex = dict(dex.summary())
            meta_dex["callsites"] = len(dex.callsites)
            dex_files.append(dex)
            target.meta.setdefault("dex", []).append(
                {
                    "path": sf.relpath,
                    "summary": meta_dex,
                    "classes": list(dex.classes),
                    "methods": list(dex.methods[:2000]),
                }
            )
        except Exception as exc:
            warnings.append(f"{sf.relpath}: dex: {exc}")
    target.meta["dex_files"] = dex_files
    target.meta["callsites"] = [
        {"dex": df.relpath, **r}
        for df in dex_files
        for r in getattr(df, "callsites", ())
    ]
    target.meta["callsite_stats"] = {
        df.relpath: dict(getattr(df, "callsite_stats", {}) or {}) for df in dex_files
    }
    # behaviour layer: quark-style API behaviours attributed to methods
    try:
        from .behaviour import behaviour_meta

        behaviour = behaviour_meta(dex_files)
        if behaviour:
            target.meta["behaviour"] = behaviour
    except Exception as exc:                       # noqa: BLE001 - best effort
        warnings.append(f"behaviour: {exc}")

    # apk signing info when we scanned a source tree that has matching zips --
    for sf in target.files:
        if sf.suffix == ".apk":
            try:
                from .android.apk import load_apk

                target.meta.setdefault("embedded_apks", []).append(load_apk(sf.path))
            except Exception as exc:
                warnings.append(f"{sf.relpath}: apk fingerprint: {exc}")


def Manifest_parse(data: bytes):  # noqa: N802 - keeps import lazy + obvious
    from .android.manifest import Manifest

    return Manifest.parse(data)


def _parse_res_id(label: str) -> Optional[int]:
    """``@res/0x7f14006b`` -> int, or None."""
    try:
        return int(label.replace("@res/0x", ""), 16)
    except (AttributeError, ValueError):
        return None


def _find_nsc(target: Target, manifest):
    """Locate the effective network security config resource."""
    for sf in target.files:
        name = os.path.basename(sf.relpath).lower()
        if "network" in name and "security" in name and sf.suffix == ".xml":
            return sf
    if manifest is not None and manifest.network_security_config:
        hint = manifest.network_security_config.replace("@xml/", "").replace("@res/", "")
        if hint and "0x" not in hint:
            for sf in target.files:
                if sf.suffix == ".xml" and hint in sf.relpath:
                    return sf
    # any xml whose root is <network-security-config>
    for sf in target.files:
        if sf.suffix != ".xml" or sf.kind not in (MANIFEST_KIND, RESOURCE_KIND):
            continue
        try:
            with open(sf.path, "rb") as fh:
                probe = fh.read(1024)
        except OSError:
            continue
        if b"network-security-config" in probe:
            return sf
    return None


def _android_native(target: Target) -> None:
    libs = [sf for sf in target.files if sf.kind == NATIVE_KIND or sf.suffix == ".so"]
    if not libs:
        return
    if len(libs) >= _FILES_PARALLEL_THRESHOLD:
        from concurrent.futures import ThreadPoolExecutor

        workers = min(8, (os.cpu_count() or 2))
        with ThreadPoolExecutor(max_workers=workers) as pool:

            def _safe_parse(sf):
                try:
                    return _elf_native_lib(sf)
                except Exception:  # noqa: BLE001 - per-file, keep going
                    return None

            parsed = list(pool.map(_safe_parse, libs))
    else:
        parsed = [_elf_native_lib(sf) for sf in libs]
    for lib in parsed:
        if lib is not None:
            target.native_libs.append(lib)
    _so_graph(target)


def _android_strings(target: Target) -> None:
    """Push DEX strings, arsc strings, native strings into ``string_pool``."""
    pool = target.string_pool
    for dex in target.meta.get("dex_files", []):
        rel = getattr(dex, "relpath", None)
        if not rel:
            for sf in target.files:
                if sf.relpath == dex_path_of(target, dex):
                    rel = sf.relpath
        if not rel:
            rel = guess_dex_relpath(target, dex)
        for _off, value in dex.iter_strings():
            pool.append((rel, value))
            if len(pool) >= MAX_POOL_TOTAL:
                return
    # resource strings
    table = target.meta.get("resources")
    if table is not None:
        for value in table.strings[:5000]:
            if value:
                pool.append(("resources.arsc", value))
                if len(pool) >= MAX_POOL_TOTAL:
                    return
    _harvest_strings(target)


def dex_path_of(target: Target, dex) -> Optional[str]:  # pragma: no cover - heuristics
    return None


def guess_dex_relpath(target: Target, dex) -> str:
    """Best-effort mapping of a parsed DexFile back to its ScanFile path."""
    names = [sf.relpath for sf in target.files if sf.suffix == ".dex"]
    return names[0] if len(names) == 1 else "classes.dex"


# --------------------------------------------------------------------------
# iOS enrichment
# --------------------------------------------------------------------------
def _reclassify_plists(target: Target) -> None:
    for sf in target.files:
        if sf.suffix == ".plist" and sf.kind not in (PLIST_KIND, BINARY_KIND):
            sf.kind = BINARY_KIND


def _ios_bundle_root(target: Target, root: str) -> str:
    for f in target.files:
        low = f.relpath.lower()
        if ".app/" in low:
            return os.path.join(target.work_dir, low.split(".app/")[0] + ".app")
    return root


def _ios_binaries(target: Target) -> None:
    """Turn Mach-O images found in the bundle into NativeLib entries."""
    images = target.meta.get("macho") or []
    paths = []
    ipa_info = target.meta.get("ipa")
    if ipa_info is not None:
        paths = list(getattr(ipa_info, "macho_paths", []))
    for i, img in enumerate(images):
        rel = paths[i] if i < len(paths) else f"binary[{i}]"
        sf = _match_file(target, rel)
        full = sf.path if sf else os.path.join(target.work_dir, rel)
        try:
            size = os.path.getsize(full)
        except OSError:
            size = 0
        lib = NativeLib(
            relpath=rel,
            path=full,
            size=size,
            arch=img.arch,
            platform="ios",
            symbols=list(img.symbols[:2000]),
            strings=[],
            flags={
                "pie": img.has_pie,
                "executable_stack": img.stack_executable,
                "code_signature": img.has_code_signature,
                "code_signature_verified": img.code_signature_verified,
                "uuid": img.uuid is not None,
            },
            notes=list(img.warnings),
        )
        _fill_native_strings(lib, full)
        target.native_libs.append(lib)


def _match_file(target: Target, rel: str) -> Optional[ScanFile]:
    want = rel.replace("\\", "/").lower()
    for sf in target.files:
        cand = sf.relpath.replace("\\", "/").lower()
        if cand == want or cand.endswith("/" + want):
            return sf
    return None


def _fill_native_strings(lib: NativeLib, full: str) -> None:
    try:
        with open(full, "rb") as fh:
            blob = fh.read()
    except OSError:
        return
    strings = list(extract_printable_strings(blob, min_len=6, limit=MAX_STRINGS_PER_FILE))
    lib.strings = [v for _off, v in strings[:MAX_STRINGS_PER_FILE]]


def _ios_strings(target: Target) -> None:
    pool = target.string_pool
    for lib in target.native_libs:
        for value in lib.strings:
            if pool_len(pool) >= MAX_POOL_TOTAL:
                return
            pool.append((lib.relpath, value))
    # macho images without a NativeLib wrapper (e.g. frameworks skipped)
    for value in _binary_strings(target):
        if pool_len(pool) >= MAX_POOL_TOTAL:
            return
        pool.append(("binaries", value))
    _harvest_plists(target)
    _harvest_strings(target, skip_kinds=(NATIVE_KIND,))


def pool_len(pool: Iterable[Tuple[str, str]]) -> int:  # pragma: no cover - trivial
    return len(list(pool)) if not isinstance(pool, list) else len(pool)


def _binary_strings(target: Target) -> List[str]:
    from .ios.macho import image_strings

    out: List[str] = []
    for img in target.meta.get("macho", []):
        try:
            out.extend(image_strings(img, min_len=6, limit=2000))
        except Exception:  # pragma: no cover
            continue
    return out


def _harvest_plists(target: Target) -> None:
    """Strings from binary plists land in the pool too (keys + values)."""
    plists: Dict[str, Any] = target.meta.get("plists") or {}

    def walk(value: Any, sink: List[str]) -> None:
        if isinstance(value, str):
            sink.append(value)
        elif isinstance(value, dict):
            for k, v in value.items():
                sink.append(str(k))
                walk(v, sink)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, sink)

    rel_seen = set()
    for sf in target.files:
        if sf.suffix != ".plist":
            continue
        rel_seen.add(sf.relpath)
        data: Any = None
        if sf.relpath in plists:
            data = plists[sf.relpath]
        else:
            try:
                with open(sf.path, "rb") as fh:
                    blob = fh.read()
                if blob[:8] == b"bplist00" or b"<plist" in blob[:512]:
                    from .ios.plist import parse_plist

                    data = parse_plist(blob)
                    plists.setdefault(sf.relpath, {}) if not isinstance(data, dict) else plists.setdefault(sf.relpath, data)
                if isinstance(data, dict):
                    plists[sf.relpath] = data
                elif data is None:
                    continue
            except Exception:
                continue
        buf: List[str] = []
        walk(data, buf)
        for value in buf:
            if len(target.string_pool) >= MAX_POOL_TOTAL:
                return
            target.string_pool.append((sf.relpath, value))
    if plists and "plists" in target.meta:
        target.meta["plists"] = plists


# --------------------------------------------------------------------------
# shared text harvesting
# --------------------------------------------------------------------------
def _harvest_strings(target: Target, skip_kinds: Tuple[str, ...] = ()) -> None:
    """Pull printable strings from every unclassified binary on disk."""
    pool = target.string_pool
    for sf in target.files:
        if sf.kind in skip_kinds:
            continue
        if sf.is_text or sf.kind in (RESOURCE_KIND, PLIST_KIND, MANIFEST_KIND, CODE_KIND, SMALI_KIND):
            continue
        # text suffixes handled by analyzers directly
        if sf.suffix in (".json", ".xml", ".txt", ".yaml", ".yml", ".properties", ".gradle", ".pro", ".md", ".html"):
            continue
        try:
            with open(sf.path, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        strings = extract_printable_strings(blob, min_len=6, limit=MAX_STRINGS_PER_FILE)
        for _off, value in strings:
            if len(pool) >= MAX_POOL_TOTAL:
                return
            pool.append((sf.relpath, value))


# --------------------------------------------------------------------------
# ELF (native .so) helper
# --------------------------------------------------------------------------
def _elf_native_lib(sf: ScanFile) -> Optional[NativeLib]:
    try:
        with open(sf.path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    if blob[:4] != b"\x7fELF":
        return None
    ei_class = blob[4]
    ei_data = blob[5]
    fmt = "<" if ei_data != 2 else ">"
    machine, pie, stack_exec, flags_out, hardening = _elf_details(blob, ei_class, fmt)
    from .elfdeps import inspect_blob

    inspected = inspect_blob(blob) or None
    deps = list(inspected.needed) if inspected else []
    dangerous = list(inspected.dangerous) if inspected else []
    fortified = list(inspected.fortified) if inspected else []
    lib = NativeLib(
        relpath=sf.relpath,
        path=sf.path,
        size=sf.size or len(blob),
        arch=_elf_arch(machine, ei_class),
        platform="android",
        dependencies=deps,
        dangerous=dangerous,
        flags={
            "pie": pie,
            "executable_stack": stack_exec,
            # compiled-in hardening observed in the dynamic symbol table
            "canary": bool(inspected.canary) if inspected else False,
            "fortified": bool(fortified),
            **hardening,
        },
    )
    lib.symbols = fortified
    lib.symbols = fortified
    strings = extract_printable_strings(blob, min_len=6, limit=MAX_STRINGS_PER_FILE)
    lib.strings = [v for _off, v in strings]
    return lib


def _load_idsig(target: Target, apk_path: str) -> None:
    """Detect + parse an APK v4 ``.idsig`` sidecar next to the APK."""
    try:
        from .android.apksigv4 import cross_check, find_idsig_path, parse_idsig

        sidecar = find_idsig_path(apk_path)
        if sidecar is None:
            return
        apk_info = target.meta.get("apk")
        try:
            apk_size = os.path.getsize(apk_path)
        except OSError:  # pragma: no cover - defensive
            apk_size = 0
        info4 = parse_idsig(sidecar, apk_size)
        if apk_info is not None:
            cross_check(info4, list(apk_info.signer_fingerprints))
        target.meta["idsig"] = info4.to_dict()
    except Exception as exc:  # noqa: BLE001 - sidecar parsing is best effort
        target.meta["idsig_error"] = str(exc)


def _so_graph(target: Target) -> None:
    """Assemble the shared-library dependency graph into meta."""
    graph: Dict[str, Any] = {}
    shipped = [lib.relpath for lib in target.native_libs]
    for lib in target.native_libs:
        graph[lib.relpath] = {
            "dependencies": list(lib.dependencies or []),
            "dangerous": list(lib.dangerous or []),
        }
    from .elfdeps import missing_dependencies

    missing: Dict[str, List[str]] = {}
    for lib in target.native_libs:
        for dep in missing_dependencies(lib.dependencies or [], shipped):
            missing.setdefault(lib.relpath, []).append(dep) 
    target.meta["so_graph"] = {
        "nodes": graph,
        "missing": missing,
        "total_edges": sum(len(v["dependencies"]) for v in graph.values()),
    }


def _elf_details(
    blob: bytes, ei_class: int, fmt: str
) -> Tuple[int, bool, bool, List[str], Dict[str, bool]]:
    e_type, e_machine = 0, 0
    stack_exec = False
    flags_out: List[str] = []
    hardening: Dict[str, bool] = {}
    try:
        if ei_class == 2:  # 64-bit
            (e_type, e_machine) = struct.unpack_from(fmt + "HH", blob, 16)
            (e_phoff,) = struct.unpack_from(fmt + "Q", blob, 0x20)
            (e_phentsize, e_phnum) = struct.unpack_from(fmt + "HH", blob, 0x36)
        else:
            (e_type, e_machine) = struct.unpack_from(fmt + "HH", blob, 16)
            (e_phoff,) = struct.unpack_from(fmt + "I", blob, 0x1C)
            (e_phentsize, e_phnum) = struct.unpack_from(fmt + "HH", blob, 0x2A)
        PT_LOAD = 1
        PT_DYNAMIC = 2
        PT_GNU_STACK = 0x6474E551
        PT_GNU_RELRO = 0x6474E552
        has_relro = False
        dyn_offset = None                              # file offset of .dynamic
        for i in range(min(e_phnum, 64)):
            pos = e_phoff + i * e_phentsize
            if pos + 8 > len(blob) or pos + e_phentsize > len(blob):
                break
            (p_type,) = struct.unpack_from(fmt + "I", blob, pos)
            try:
                if ei_class == 2:
                    p_flags, = struct.unpack_from(fmt + "I", blob, pos + 4)
                    p_off, = struct.unpack_from(fmt + "Q", blob, pos + 8)
                    p_filesz, = struct.unpack_from(fmt + "Q", blob, pos + 32)
                else:
                    p_flags, = struct.unpack_from(fmt + "I", blob, pos + 24)
                    p_off, = struct.unpack_from(fmt + "I", blob, pos + 4)
                    p_filesz, = struct.unpack_from(fmt + "I", blob, pos + 16)
            except struct.error:
                break
            if p_type == PT_GNU_STACK:
                stack_exec = bool(p_flags & 1)
            elif p_type == PT_GNU_RELRO:
                has_relro = True
            elif p_type == PT_DYNAMIC:
                dyn_offset, dyn_size = p_off, p_filesz
            elif p_type == PT_LOAD and p_off is not None:
                pass

        if dyn_offset is not None and dyn_size:
            hardening = _elf_dynamic_flags(blob, int(dyn_offset), int(dyn_size), fmt)
        hardening.setdefault("relro", has_relro)
        hardening["full_relro"] = bool(hardening.get("relro")) and bool(
            hardening.get("bind_now")
        )
    except (struct.error, IndexError):
        flags_out.append("malformed-elf-header")
    pie = e_type == 3
    return e_machine, pie, stack_exec, flags_out, hardening


def _elf_dynamic_flags(
    blob: bytes, dyn_off: int, dyn_size: int, fmt: str
) -> Dict[str, bool]:
    """Walk the ELF dynamic table; collect RELRO-relevant flags (M7)."""
    DT_BIND_NOW = 24
    DT_TEXTREL = 22
    DT_FLAGS = 30
    DT_FLAGS_1 = 0x6FFFFFFB
    DF_BIND_NOW = 0x8
    DF_1_NOW = 0x1

    out: Dict[str, bool] = {"bind_now": False, "writable_text": False}
    end = min(len(blob), dyn_off + max(dyn_size, 0))
    pos = dyn_off
    while pos + 16 <= end:                              # entries are always 16B
        try:
            tag, = struct.unpack_from(fmt + "q", blob, pos)
            val, = struct.unpack_from(fmt + "Q", blob, pos + 8)
        except struct.error:
            break
        if tag == 0:                                    # DT_NULL: end of table
            break
        if tag == DT_BIND_NOW:
            out["bind_now"] = True
        elif tag == DT_FLAGS:
            if val & DF_BIND_NOW:
                out["bind_now"] = True
        elif tag == DT_FLAGS_1:
            if val & DF_1_NOW:
                out["bind_now"] = True
        elif tag == DT_TEXTREL:
            out["writable_text"] = True
        pos += 16
    return out


def _elf_arch(machine: int, ei_class: int) -> str:
    names = {
        3: "x86",
        8: "mips",
        20: "ppc",
        40: "arm",
        62: "x86_64",
        183: "arm64",
        243: "riscv",
    }
    name = names.get(machine, f"machine{machine}")
    if name == "arm" or name == "arm64":
        name = {"arm": "arm", "arm64": "aarch64"}.get(name, name)
    if ei_class == 2 and name == "x86":
        name = "x86_64"
    return name

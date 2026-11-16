"""IPA (iOS application archive) handling.

An ``.ipa`` is a ZIP file::

    Payload/
        MyApp.app/
            Info.plist          (usually binary)
            MyApp               (Mach-O executable)
            embedded.mobileprovision
            ...resources...

This module extracts the structure, loads the *Info.plist*, decodes the
embedded provisioning profile (``embedded.mobileprovision``) - a CMS signed
XML plist; we read the plist part only - and hands every Mach-O image found
in the bundle to the macho parser so the M7 analyzer can reason about them.
"""

from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .macho import MachOImage, is_macho, parse_macho
from .plist import PlistError, load_plist, parse_plist
from ..utils import safe_relpath


class IpaError(Exception):
    """Raised when a bundle cannot be interpreted."""


@dataclass
class ProvisioningProfile:
    """Decoded ``.mobileprovision`` content (best effort, plist part only)."""

    name: str = ""
    app_id_name: str = ""
    team_id: str = ""
    team_name: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    entitlements: Dict[str, Any] = field(default_factory=dict)
    provisions_all_devices: bool = False
    developer_certificates: List[bytes] = field(default_factory=list)

    @property
    def descriptive_name(self) -> str:
        return self.name or self.app_id_name or "<no profile name>"

    @property
    def is_development(self) -> bool:
        ents = self.entitlements or {}
        for key in ("com.apple.developer.device-identifiers",):
            if key in ents:
                return True
        return "get-task-allow" not in ents or False


@dataclass
class IpaEntry:
    relpath: str
    size: int = 0
    kind: str = "resource"      # plist | macho | resource | code_signature

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.relpath, "size": self.size, "kind": self.kind}


@dataclass
class IpaInfo:
    """Everything the scanner needs about an IPA / iOS app bundle."""

    path: str
    name: str = ""
    size: int = 0
    platform: str = "ios"
    app_dir: str = ""
    executable_name: str = ""
    bundle_identifier: str = ""
    bundle_name: str = ""
    version: str = ""
    minimum_os: str = ""
    entries: List[IpaEntry] = field(default_factory=list)
    plists: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # relpath -> decoded
    macho_images: List[MachOImage] = field(default_factory=list)
    macho_paths: List[str] = field(default_factory=list)
    allow_arbitrary_loads: Optional[bool] = None
    ats_preset: Dict[str, Any] = field(default_factory=dict)
    profile: Optional[ProvisioningProfile] = None
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "bundle_identifier": self.bundle_identifier,
            "version": self.version,
            "minimum_os": self.minimum_os,
            "executable": self.executable_name,
            "files": len(self.entries),
            "macho_images": [img.arch for img in self.macho_images],
            "allow_arbitrary_loads": self.allow_arbitrary_loads,
            "profile": (self.profile.descriptive_name if self.profile else None),
            "warnings": len(self.warnings),
        }

    # -- helpers used by analyzers ---------------------------------------
    @property
    def info_plist(self) -> Dict[str, Any]:
        return self.plists.get("Info.plist", {})

    @property
    def debuggable(self) -> bool:
        """get-task-allow inside the provisioning profile."""
        if not self.profile:
            return False
        return bool(self.profile.entitlements.get("get-task-allow", False))


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def load_ipa(path: str) -> IpaInfo:
    """Inspect an IPA without extracting (works with the file in place)."""
    import zipfile

    info = IpaInfo(path=path, name=_base(path), size=_size(path))
    try:
        is_zip = zipfile.is_zipfile(path)
    except (TypeError, OSError):
        is_zip = False
    if not is_zip:
        info.warnings.append("not a zip archive")
        return info

    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        app_dir = _app_dir(names)
        info.app_dir = app_dir
        prefix = app_dir + "/" if app_dir else ""

        for raw_name in names:
            rel = raw_name[len(prefix):] if prefix and raw_name.startswith(prefix) else raw_name
            rel = rel.replace("\\", "/").lstrip("/")
            data_entry = zf.getinfo(raw_name)
            if rel.lower().endswith(".plist"):
                try:
                    decoded = parse_plist(zf.read(raw_name))
                    if isinstance(decoded, dict):
                        info.plists[rel] = decoded
                except PlistError as exc:
                    info.warnings.append(f"{rel}: {exc}")
                info.entries.append(IpaEntry(rel, data_entry.file_size, "plist"))
            elif rel.endswith("embedded.mobileprovision") or rel.endswith(".mobileprovision"):
                info.entries.append(IpaEntry(rel, data_entry.file_size, "code_signature"))
                profile = _parse_mobileprovision(zf.read(raw_name))
                if profile:
                    info.profile = profile if info.profile is None else info.profile
            else:
                kind = "resource"
                head = zf.read(raw_name)[:16]
                if is_macho(bytes(head)) or (len(head) >= 8 and head[:4] in (0xFEEDFACF.to_bytes(4, "big"), 0xFEEDFACE.to_bytes(4, "big"))):
                    kind = "macho"
                info.entries.append(IpaEntry(rel, data_entry.file_size, kind))

        # main executable ---------------------------------------------------
        info_plist = _find_info_plist(info)
        _load_info_plist_info(info, info_plist)
        for entry in info.entries:
            if entry.kind != "macho":
                continue
            full = prefix + entry.relpath
            try:
                blob = zf.read(full)
            except Exception as exc:  # pragma: no cover - unzip failure
                info.warnings.append(f"{entry.relpath}: {exc}")
                continue
            try:
                image = parse_macho(blob)
            except Exception as exc:
                info.warnings.append(f"{entry.relpath}: mach-o parse: {exc}")
                continue
            info.macho_images.append(image)
            info.macho_paths.append(entry.relpath)

        # extra plists found inside .lproj? keep but do not surface
        del info_plist
        return info


def _load_info_plist_info(info: IpaInfo, info_plist: Dict[str, Any]) -> None:
    """Fill top level fields from the decoded ``Info.plist``."""
    info.bundle_identifier = str(info_plist.get("CFBundleIdentifier", "") or "")
    info.bundle_name = str(info_plist.get("CFBundleName", "") or "")
    info.version = str(info_plist.get("CFBundleShortVersionString")
                       or info_plist.get("CFBundleVersion") or "")
    info.minimum_os = str(info_plist.get("MinimumOSVersion")
                          or info_plist.get("LSMinimumSystemVersion", "") or "")
    executable = info_plist.get("CFBundleExecutable")
    if executable:
        info.executable_name = str(executable)
    else:
        # convention: <bundle-name> without extension == executable
        guess = _base(info.path)
        if guess.endswith(".ipa"):
            guess = guess[:-4]
        info.executable_name = guess

    ats = info_plist.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        info.ats_preset = ats
        arbitrary = ats.get("NSAllowsArbitraryLoads")
        if arbitrary is True:
            info.allow_arbitrary_loads = True
            exemptions = ats.get("NSExceptionDomains")
            if isinstance(exemptions, dict):
                info.allow_arbitrary_loads = True

    if info.name and not info.bundle_name:
        info.bundle_name = info.name


def _find_info_plist(info: IpaInfo) -> Dict[str, Any]:
    if app_plist := info.plists.get("Info.plist"):
        return app_plist
    for rel, plist in info.plists.items():
        if rel.split("/")[-1] == "Info.plist":
            return plist
    return {}


def _app_dir(names: List[str]) -> str:
    """Locate the ``Payload/…​.app`` directory."""
    candidates = {n.split("/")[0] + "/" + n.split("/")[1] for n in names if "/" in n}
    for c in sorted(candidates):
        if c.endswith(".app"):
            return c.rstrip("/")
    return ""


def _parse_mobileprovision(raw: bytes) -> Optional[ProvisioningProfile]:
    """Parse a ``.mobileprovision`` (CMS wrapper around an XML plist)."""
    profile = ProvisioningProfile()
    start = raw.find(b"<?xml")
    if start < 0:
        start = raw.find(b"<plist")
    end = raw.rfind(b"</plist>")
    if start < 0 or end < 0 or end <= start:
        return None
    blob = raw[start : end + len(b"</plist>")]
    try:
        from .plist import parse_xml_plist
        data = parse_xml_plist(blob)
    except Exception:
        return None
    if not isinstance(data, dict):  # pragma: no cover - malformed profile
        return None
    profile.name = str(data.get("Name", "") or "")
    profile.app_id_name = str(data.get("AppIDName", "") or "")
    profile.team_id = str(data.get("ApplicationIdentifierPrefix", [""])[0]) if data.get(
        "ApplicationIdentifierPrefix"
    ) else ""
    profile.team_name = str(data.get("TeamName", "") or "")
    profile.creation_date = str(data.get("CreationDate", "") or "")
    profile.expiration_date = str(data.get("ExpirationDate", "") or "")
    profile.provisions_all_devices = data.get("ProvisionsAllDevices") is True
    ents = data.get("Entitlements")
    if isinstance(ents, dict):
        profile.entitlements = ents
    return profile


# ---------------------------------------------------------------------------
# helpers used when scanning an *unpacked* iOS tree
# ---------------------------------------------------------------------------
def find_app_dir(root: str) -> Optional[str]:
    """Locate ``Payload/*.app`` inside an unpacked IPA or iOS source dir."""
    if not os.path.isdir(root):
        return None
    for dirpath, dirnames, _files in os.walk(root):
        if dirpath.endswith(".app"):
            return dirpath
        for d in list(dirnames):
            if d.endswith(".app"):
                return os.path.join(dirpath, d)
    return None


def bundle_info_from_dir(root: str) -> IpaInfo:
    """Build an :class:`IpaInfo` directly from an unpacked ``*.app`` dir."""
    info = IpaInfo(path=root, name=os.path.basename(root.rstrip("/\\")))
    app_dir = root if os.path.basename(root.rstrip("/\\")).endswith(".app") else (find_app_dir(root) or root)
    info.app_dir = app_dir

    info_plist_path = None
    for root_dir, _dirs, files in os.walk(app_dir):
        for fname in files:
            full = os.path.join(root_dir, fname)
            rel = safe_relpath(full, app_dir)
            if fname.lower() == "info.plist":
                decoded = load_plist(full)
                if isinstance(decoded, dict):
                    info.plists[rel] = decoded
                    info_plist_path = full
                info.entries.append(IpaEntry(rel, _size(full), "plist"))
                continue
            ext = os.path.splitext(fname)[1].lower()
            if fname.endswith(".mobileprovision"):
                profile = _parse_mobileprovision_file(full)
                if profile and info.profile is None:
                    info.profile = profile
                info.entries.append(IpaEntry(rel, _size(full), "code_signature"))
                continue
            if ext == "":
                # Bootable Mach-O (usually the FAT app binary)
                try:
                    with open(full, "rb") as fh:
                        head = fh.read(16)
                except OSError:
                    continue
                if is_macho(bytes(head)):
                    try:
                        info.macho_images.append(parse_macho_file(full))
                        info.macho_paths.append(rel)
                        info.entries.append(IpaEntry(rel, _size(full), "macho"))
                        continue
                    except Exception as exc:  # pragma: no cover
                        info.warnings.append(f"{rel}: {exc}")
            info.entries.append(IpaEntry(rel, _size(full), "resource"))

    info_plist = _find_info_plist(info)
    _load_info_plist_info(info, info_plist)
    return info


def _parse_mobileprovision_file(path: str) -> Optional[ProvisioningProfile]:
    try:
        with open(path, "rb") as fh:
            return _parse_mobileprovision(fh.read())
    except OSError:  # pragma: no cover
        return None


def parse_macho_file(path: str) -> MachOImage:
    with open(path, "rb") as fh:
        return parse_macho(fh.read())


def _base(path: str) -> str:
    return os.path.basename(path.rstrip("\\/"))


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:  # pragma: no cover
        return 0

"""High level model of ``AndroidManifest.xml``.

:mod:`masanalyzer.android.axml` gives us a generic node tree. Analyzers should
not have to know AXML internals, so this module wraps the tree in a typed
:class:`Manifest` object exposing exactly the fields a mobile assessment needs:
package id, SDK levels, permissions, the four component families with their
exported/permission-protected state, plus the assorted "is this build hardened"
flags.

Every component records the *reason* it is considered exported so the report can
explain itself rather than just asserting a boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .axml import XmlNode, parse_xml_any

ANDROID_NS = "http://schemas.android.com/apk/res/android"

#: Permissions that are considered dangerous (protection level DANGEROUS).
#: Only the ones that routinely show up in assessments are listed; anything in
#: this set gets extra scrutiny from the M8/M9 analyzers.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.INTERACT_ACROSS_USERS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
}

#: Signature level permissions an app should never be able to request for real.
SIGNATURE_PERMISSIONS = {
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MASTER_CLEAR",
    "android.permission.BRICK",
    "android.permission.REBOOT",
    "android.permission.SET_DEBUG_APP",
    "android.permission.DUMP",
    "android.permission.READ_LOGS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
}


# --------------------------------------------------------------------------
# Components
# --------------------------------------------------------------------------
@dataclass
class IntentFilter:
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    schemes: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    path_prefixes: List[str] = field(default_factory=list)
    mime_types: List[str] = field(default_factory=list)

    @property
    def browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def has_data(self) -> bool:
        return bool(self.schemes or self.mime_types)


@dataclass
class Component:
    """A single activity/service/receiver/provider declaration."""

    kind: str                      # activity|activity-alias|service|receiver|provider
    name: str
    exported: bool = False
    exported_explicit: bool = False
    permission: Optional[str] = None
    enabled: bool = True
    direct_boot_aware: bool = False
    grant_uri_permissions: bool = False
    filters: List[IntentFilter] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    node: Optional[XmlNode] = None

    # -- convenience ------------------------------------------------------
    @property
    def has_intent_filter(self) -> bool:
        return bool(self.filters)

    @property
    def exported_reason(self) -> str:
        """Why this component is reachable from other applications."""
        if self.exported_explicit:
            return "android:exported=\"true\" set explicitly"
        if self.has_intent_filter:
            return "no android:exported but an intent-filter is present (implicit default true)"
        return "not exported"

    @property
    def protected(self) -> bool:
        """True when a permission guard is present."""
        return bool(self.permission)

    @property
    def short_name(self) -> str:
        return self.name.rsplit(".", 1)[-1]

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Component {self.kind} {self.short_name} exported={self.exported}>"


@dataclass
class Permission:
    name: str
    protection_level: str = "normal"
    dangerous: bool = False
    signature: bool = False

    @classmethod
    def from_node(cls, node: XmlNode) -> "Permission":
        name = str(node.get("name", "") or "")
        level = str(node.get("protectionLevel", "normal") or "normal").lower()
        return cls(
            name=name,
            protection_level=level,
            dangerous="dangerous" in level or name in DANGEROUS_PERMISSIONS,
            signature="signature" in level or name in SIGNATURE_PERMISSIONS,
        )


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------
@dataclass
class Manifest:
    """Typed view over the manifest tree."""

    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    max_sdk: Optional[int] = None       # uses-sdk maxSdkVersion (rare, a fact)

    permissions: List[Permission] = field(default_factory=list)
    uses_permissions: List[str] = field(default_factory=list)
    custom_permissions: List[Permission] = field(default_factory=list)

    activities: List[Component] = field(default_factory=list)
    aliases: List[Component] = field(default_factory=list)
    services: List[Component] = field(default_factory=list)
    receivers: List[Component] = field(default_factory=list)
    providers: List[Component] = field(default_factory=list)

    uses_libraries: List[str] = field(default_factory=list)
    uses_features: List[str] = field(default_factory=list)

    debuggable: bool = False
    allow_backup: bool = True
    backup_agent: Optional[str] = None
    full_backup_content: Optional[str] = None
    data_extraction_rules: Optional[str] = None
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    test_only: bool = False
    vm_safe_mode: bool = False
    hardware_accelerated: bool = True
    shared_user_id: Optional[str] = None
    shared_user_label: Optional[str] = None
    native_libs_extractable: bool = False
    application_class: Optional[str] = None
    application_label: Optional[str] = None
    application_attributes: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    # -- construction -----------------------------------------------------
    @classmethod
    def parse(cls, data: bytes) -> "Manifest":
        """Parse AXML or plain XML manifest bytes."""
        root = parse_xml_any(data)
        if root is None:
            raise ValueError("AndroidManifest.xml could not be decoded")
        return cls.from_node(root)

    @classmethod
    def from_node(cls, root: XmlNode) -> "Manifest":
        man = cls()
        node = root if root.tag == "manifest" else root.child("manifest")
        if node is None:
            raise ValueError("no <manifest> element found")
        man._load(node)
        return man

    # -- parsing internals ------------------------------------------------
    @staticmethod
    def _bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "0xffffffff", "-1")

    @staticmethod
    def _int(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            if isinstance(value, str):
                v = value.strip()
                return int(v, 16) if v.lower().startswith("0x") else int(v)
            return int(value)
        except (TypeError, ValueError):
            return None

    def _load(self, manifest: XmlNode) -> None:
        self.package = str(manifest.get("package", "") or "")
        self.version_name = str(manifest.get("versionName", "") or "")
        self.version_code = str(manifest.get("versionCode", "") or "")
        self.shared_user_id = manifest.get("sharedUserId")
        self.shared_user_label = manifest.get("sharedUserLabel")
        self.test_only = self._bool(manifest.get("testOnly"))

        for node in manifest.find_all("permission"):
            self.custom_permissions.append(Permission.from_node(node))
        for node in manifest.find_all("permission-group"):  # pragma: no cover - rare
            pass
        for node in manifest.find_all("uses-permission"):
            name = str(node.get("name", "") or "")
            if name:
                self.uses_permissions.append(name)
        for node in manifest.find_all("uses-permission-sdk-23"):
            name = str(node.get("name", "") or "")
            if name:
                self.uses_permissions.append(name)
        for node in manifest.find_all("uses-sdk"):
            self.min_sdk = self._int(node.get("minSdkVersion")) or self.min_sdk
            self.target_sdk = self._int(node.get("targetSdkVersion")) or self.target_sdk
            self.compile_sdk = self._int(node.get("compileSdkVersion")) or self.compile_sdk
            self.max_sdk = self._int(node.get("maxSdkVersion")) or self.max_sdk
        for node in manifest.find_all("uses-library"):
            name = str(node.get("name", "") or "")
            if name:
                self.uses_libraries.append(name)
        for node in manifest.find_all("uses-feature"):
            name = str(node.get("name", "") or "")
            if name:
                self.uses_features.append(name)

        # normalise permission records (declared + requested)
        by_name: Dict[str, Permission] = {p.name: p for p in self.custom_permissions}
        for name in self.uses_permissions:
            perm = by_name.get(name)
            if perm is None:
                perm = Permission(
                    name=name,
                    dangerous=name in DANGEROUS_PERMISSIONS,
                    signature=name in SIGNATURE_PERMISSIONS,
                )
                by_name[name] = perm
            self.permissions.append(perm)

        app = manifest.child("application")
        if app is not None:
            self._load_application(app)

    def _load_application(self, app: XmlNode) -> None:
        self.application_class = app.get("name")
        self.application_label = app.get("label")
        self.application_attributes = {
            k: a.value for k, a in app.attributes.items() if not k.startswith("android:")
        }
        self.debuggable = self._bool(app.get("debuggable"))
        self.allow_backup = self._bool(app.get("allowBackup", True), default=True)
        self.backup_agent = app.get("backupAgent")
        self.full_backup_content = app.get("fullBackupContent")
        self.data_extraction_rules = app.get("dataExtractionRules")
        self.network_security_config = app.get("networkSecurityConfig")
        self.vm_safe_mode = self._bool(app.get("vmSafeMode"))
        self.hardware_accelerated = self._bool(app.get("hardwareAccelerated", True), default=True)
        uct = app.get("usesCleartextTraffic")
        self.uses_cleartext_traffic = self._bool(uct) if uct is not None else None
        extract = app.get("extractNativeLibs")
        self.native_libs_extractable = self._bool(extract, default=False)

        mapping = {
            "activity": ("activities", "activity"),
            "activity-alias": ("aliases", "activity-alias"),
            "service": ("services", "service"),
            "receiver": ("receivers", "receiver"),
            "provider": ("providers", "provider"),
        }
        for tag, (bucket, kind) in mapping.items():
            for node in app.children_of(tag):
                comp = self._component(node, kind)
                getattr(self, bucket).append(comp)

        # activity-alias targets its activity: inherit exportedness knowledge
        for alias in self.aliases:
            target = str(alias.attributes.get("targetActivity", "") or "")
            for act in self.activities:
                if act.name == target and alias.exported and not act.exported:
                    act.exported = True
                    act.exported_explicit = act.exported_explicit or False

    def _component(self, node: XmlNode, kind: str) -> Component:
        name = str(node.get("name", "") or "")
        exported_attr = node.get("exported")
        explicit = exported_attr is not None
        filters = [self._filter(f) for f in node.children_of("intent-filter")]
        exported = self._bool(exported_attr) if explicit else bool(filters)
        comp = Component(
            kind=kind,
            name=name,
            exported=exported,
            exported_explicit=explicit,
            permission=node.get("permission"),
            enabled=self._bool(node.get("enabled", True), default=True),
            direct_boot_aware=self._bool(node.get("directBootAware")),
            grant_uri_permissions=self._bool(node.get("grantUriPermissions")),
            filters=filters,
            attributes={k: a.value for k, a in node.attributes.items() if not k.startswith("android:")},
            node=node,
        )
        # keep a few raw android:* attributes analyzers commonly inspect
        for key, attr in node.attributes.items():
            if key.startswith("android:"):
                comp.attributes[key.split(":", 1)[1]] = attr.value
        return comp

    @staticmethod
    def _filter(node: XmlNode) -> IntentFilter:
        filt = IntentFilter()
        for child in node.children:
            value = str(child.get("name", "") or "")
            if child.tag == "action":
                filt.actions.append(value)
            elif child.tag == "category":
                filt.categories.append(value)
            elif child.tag == "data":
                scheme = child.get("scheme")
                host = child.get("host")
                prefix = child.get("pathPrefix") or child.get("path") or child.get("pathPattern")
                mime = child.get("mimeType")
                if scheme:
                    filt.schemes.append(str(scheme))
                if host:
                    filt.hosts.append(str(host))
                if prefix:
                    filt.path_prefixes.append(str(prefix))
                if mime:
                    filt.mime_types.append(str(mime))
        return filt

    # -- queries ----------------------------------------------------------
    def all_components(self) -> List[Component]:
        return (
            self.activities + self.aliases + self.services + self.receivers + self.providers
        )

    def exported_components(self) -> List[Component]:
        return [c for c in self.all_components() if c.exported and c.enabled]

    def unprotected_exported(self) -> List[Component]:
        return [c for c in self.exported_components() if not c.protected]

    def component(self, name: str) -> Optional[Component]:
        for c in self.all_components():
            if c.name == name:
                return c
        return None

    def uses_permission(self, name: str) -> bool:
        return name in self.uses_permissions

    def dangerous_permissions(self) -> List[Permission]:
        return [p for p in self.permissions if p.dangerous]

    def signature_permissions(self) -> List[Permission]:
        return [p for p in self.permissions if p.signature]

    @property
    def allow_cleartext(self) -> bool:
        """True when the app may talk HTTP by configuration."""
        return self.uses_cleartext_traffic is True

    @property
    def targets_modern_sdk(self) -> bool:
        return (self.target_sdk or 0) >= 28

    def summary(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "cleartext": self.uses_cleartext_traffic,
            "permissions": len(self.uses_permissions),
            "dangerous_permissions": len(self.dangerous_permissions()),
            "activities": len(self.activities),
            "services": len(self.services),
            "receivers": len(self.receivers),
            "providers": len(self.providers),
            "exported": len(self.exported_components()),
            "unprotected_exported": len(self.unprotected_exported()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "uses_permissions": list(self.uses_permissions),
            "custom_permissions": [p.name for p in self.custom_permissions],
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "network_security_config": self.network_security_config,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "test_only": self.test_only,
            "components": {
                "activities": [c.name for c in self.activities],
                "services": [c.name for c in self.services],
                "receivers": [c.name for c in self.receivers],
                "providers": [c.name for c in self.providers],
                "aliases": [c.name for c in self.aliases],
            },
            "exported": [
                {
                    "kind": c.kind,
                    "name": c.name,
                    "permission": c.permission,
                    "reason": c.exported_reason,
                }
                for c in self.exported_components()
            ],
        }

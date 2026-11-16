"""M3 - Insecure Authentication/Authorization.

Checks the manifest component model: exported activities / services /
receivers / content providers that other apps can call without a permission
guard, implicit-export components and over-permissive providers.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from ..model import Confidence, Finding, Severity, Target
from .common import make_rule

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
INFO = Severity.INFO

R_EXPORTED_PROVIDER = make_rule(
    "MAS-AUTH-001",
    "M3",
    "Exported content provider without a permission guard",
    "The provider is reachable by every other application and (optionally) "
    "grants URI permissions, so app-private data can be read or modified by "
    "third parties.",
    HIGH,
    'Add an android:permission (signature level) to the provider or set '
    'android:exported="false"; use grantUriPermissions only for specific '
    "intents.",
    cwe="CWE-862",
    confidence=Confidence.HIGH,
    cvss=8.0,
)

R_EXPORTED_UNPROTECTED = make_rule(
    "MAS-AUTH-002",
    "M3",
    "Exported component without a permission guard",
    "A component is exported and not protected by a permission, enabling "
    "unauthorised callers to start the activity/service/receiver.",
    MEDIUM,
    'Set android:exported="false" or protect the component with a '
    "signature-level permission.",
    cwe="CWE-862",
    confidence=Confidence.HIGH,
    cvss=6.2,
    platform="android",
)

R_EXPORTED_IMPLICIT = make_rule(
    "MAS-AUTH-003",
    "M3",
    "Component implicitly exported via intent-filter",
    "The component declares an intent-filter without an explicit "
    "android:exported attribute; on older targetSdk levels this defaults to "
    "exported, leaving the public entry point undocumented.",
    MEDIUM,
    "Add an explicit android:exported attribute and remove intent-filters "
    "that are not part of the public interface.",
    cwe="CWE-1188",
    confidence=Confidence.HIGH,
    cvss=5.5,
    platform="android",
)

R_EXPORTED_HARDCODED_TOKEN = make_rule(
    "MAS-AUTH-004",
    "M3",
    "Exported component handling authentication without an authorisation check",
    "The exported activity/service name suggests an authentication flow that is "
    "reachable from other apps; such IPC entry points bypass the app's own "
    "authorisation logic.",
    MEDIUM,
    "Guard authentication IPC entry points with permissions and re-validate "
    "the caller intent inside the component.",
    cwe="CWE-306",
    confidence=Confidence.MEDIUM,
    cvss=6.5,
    platform="android",
)

R_SHARED_USER_ID = make_rule(
    "MAS-AUTH-005",
    "M3",
    "Shared user id with unrestricted trust boundaries",
    "android:sharedUserId gives another app the same Linux uid, so a "
    "compromised app sharing an id also shares private data paths and "
    "permissions.",
    MEDIUM,
    "Drop android:sharedUserId or move it to a signature-level definition.",
    cwe="CWE-250",
    confidence=Confidence.HIGH,
    cvss=5.5,
    platform="android",
)

R_DEEPLINK_WITHOUT_VALIDATION = make_rule(
    "MAS-AUTH-006",
    "M3",
    "Browsable deep-link activity",
    "A BROWSABLE intent-filter lets a malicious link trigger this activity "
    "from the browser; combined with a missing permission the actor controls "
    "the app's runtime behaviour.",
    MEDIUM,
    "Validate deep-link parameters and don't assume the link came from this "
    "app; guard sensitive actions.",
    cwe="CWE-940",
    confidence=Confidence.MEDIUM,
    platform="android",
)


def analyze(target: Target) -> Iterable[Finding]:
    manifest = target.manifest
    if manifest is None:
        return []
    out: List[Finding] = []
    manifest_path = target.meta.get("manifest_path") or "AndroidManifest.xml"

    for comp in manifest.exported_components():
        ev_kwargs: dict = dict(file=manifest_path, symbol=comp.name, note=comp.exported_reason)
        if comp.kind == "provider":
            if not comp.protected:
                ev_kwargs["note"] = (comp.exported_reason + "; grantUriPermissions="
                                     + str(comp.grant_uri_permissions))
                out.append(R_EXPORTED_PROVIDER.finding(**ev_kwargs))
            # protected providers are documented by the M3 exported list only
        elif comp.kind in ("activity", "activity-alias", "service", "receiver"):
            name_low = comp.name.lower()
            auth_like = any(k in name_low for k in ("auth", "login", "pin", "session", "credential"))
            if auth_like and not comp.protected:
                out.append(R_EXPORTED_HARDCODED_TOKEN.finding(
                    file=manifest_path, symbol=comp.name, note=comp.exported_reason
                ))
            elif not comp.protected:
                if not comp.exported_explicit and comp.has_intent_filter:
                    ev_kwargs.setdefault("note", comp.exported_reason)
                    out.append(R_EXPORTED_IMPLICIT.finding(**ev_kwargs))
                else:
                    out.append(R_EXPORTED_UNPROTECTED.finding(**ev_kwargs))

    if manifest.shared_user_id:
        out.append(
            R_SHARED_USER_ID.finding(
                file=manifest_path, symbol=manifest.shared_user_id
            )
        )

    for comp in manifest.all_components():
        if not comp.protected:
            for filt in comp.filters:
                if filt.browsable and comp.exported:
                    out.append(
                        R_DEEPLINK_WITHOUT_VALIDATION.finding(
                            file=manifest_path, symbol=comp.name,
                            note="schemes=" + ",".join(filt.schemes) if filt.schemes else "",
                        )
                    )
    # de-dupe same (component, rule) tuples from the browsable pass
    seen = set()
    result = []
    for f in out:
        key = (f.rule_id, f.evidence.symbol)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return [f for f in result if f is not None]

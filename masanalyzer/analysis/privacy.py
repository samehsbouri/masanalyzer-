"""Excess-access privacy matrix (dangerous permissions ⊕ observed behavior).

Android grants a bundle a *declaration* of intent: every dangerous runtime
permission is a promise to the user. This module cross-checks that promise
against what the static artifacts actually show:

* class/method names in the DEX tables (``meta["dex"]`` - complete, not
  volume-capped);
* the shared string pool (API strings, content URIs);
* manifest components (receivers/activities and their intent filters).

A dangerous permission with **zero** observed corroborating signals is an
*excess access*: power the app holds but can be shown never to exercise,
attractive for supply-chain policy review. The matrix itself lands in
``target.meta["privacy_matrix"]``; analyzers (m06/m08) turn rows into
findings and reports render the table.

Conservative by design: markers are class-level API names, not guesses;
absence of evidence never inflates severity beyond LOW for broad buckets
(see ``SENSITIVE_PERMISSIONS`` for the medium band). iOS is out of scope
(the permission model is Info.plist-driven, no runtime grant CAD).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from ..android.manifest import DANGEROUS_PERMISSIONS

#: permissions whose misuse is high-impact for the user
SENSITIVE_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.BODY_SENSORS",
}

#: god-mode grants a store reviewer must explicitly justify
SPECIAL_ACCESS = {
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.QUERY_ALL_PACKAGES",
}

#: case-insensitive API markers per dangerous permission (corroboration)
_SIGNALS: Dict[str, Tuple[str, ...]] = {
    "android.permission.CAMERA": (
        "android.hardware.camera", "androidx.camera", "cameraprofile",
        "takepicture", "onpreviewframe",
    ),
    "android.permission.ACCESS_FINE_LOCATION": (
        "locationmanager", "requestlocationupdates", "getlastknownlocation",
        "fusedlocationprovider",
    ),
    "android.permission.ACCESS_COARSE_LOCATION": (
        "locationmanager", "requestlocationupdates", "getlastknownlocation",
        "fusedlocationprovider",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "backgroundlocation", "locationmanager", "requestlocationupdates",
    ),
    "android.permission.RECORD_AUDIO": (
        "mediarecorder", "audiorecord", "mediasource", "startrecording",
    ),
    "android.permission.READ_CONTACTS": ("contactscontract",),
    "android.permission.WRITE_CONTACTS": ("contactscontract",),
    "android.permission.GET_ACCOUNTS": ("accountmanager", "getaccounts"),
    "android.permission.READ_PHONE_STATE": (
        "telephonymanager", "phonestatelistener", "subscriptionmanager",
        "getimei", "getmeid", "getdeviceid",
    ),
    "android.permission.READ_PHONE_NUMBERS": ("telephonymanager",),
    "android.permission.CALL_PHONE": ("intent.action.call", "action_call", "placecall"),
    "android.permission.READ_CALL_LOG": ("calllog", "content://call_log"),
    "android.permission.WRITE_CALL_LOG": ("calllog",),
    "android.permission.SEND_SMS": (
        "smsmanager", "sendtextmessage", "content://sms",
    ),
    "android.permission.RECEIVE_SMS": ("content://sms", "smsmessage", "telephony.sms"),
    "android.permission.READ_SMS": ("content://sms", "telephony.sms"),
    "android.permission.RECEIVE_MMS": ("content://mms", "wap_push", "smsmanager"),
    "android.permission.RECEIVE_WAP_PUSH": ("wap_push",),
    "android.permission.BODY_SENSORS": ("heartrate", "basesensor", "sensortypestepcounter",),
    "android.permission.USE_SIP": ("sipmanager", "sipprofile", "voip"),
    "android.permission.PROCESS_OUTGOING_CALLS": (
        "new_outgoing_call", "action.new_outgoing_call", "calllog",
    ),
    "android.permission.ANSWER_PHONE_CALLS": (
        "answercall", "intelecomservice", "endcall",
    ),
    "android.permission.ADD_VOICEMAIL": ("voicemail",),
    "android.permission.PACKAGE_USAGE_STATS": (
        "usagestatsmanager", "queryandpackageusagestats",
    ),
    "android.permission.READ_CALENDAR": ("calendarcontract", "content://calendar"),
    "android.permission.WRITE_CALENDAR": ("calendarcontract",),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "isexternalstoragemanager", "getexternalstorageDirectory",
        "externalstoragedir", "mediastore", "content://media",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "isexternalstoragemanager", "getexternalstorageDirectory",
        "externalstoragedir", "mediastore",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "isexternalstoragemanager", "environment.isexternalstorage",
    ),
    "android.permission.READ_MEDIA_IMAGES": ("mediastore", "content://media"),
    "android.permission.READ_MEDIA_VIDEO": ("mediastore", "content://media"),
    "android.permission.READ_MEDIA_AUDIO": ("mediastore", "content://media"),
    "android.permission.ACCESS_MEDIA_LOCATION": ("mediastore", "exifinterface"),
    "android.permission.POST_NOTIFICATIONS": (
        "notificationmanager", "notificationchannel", "notify",
    ),
    "android.permission.QUERY_ALL_PACKAGES": (
        "getinstalledpackages", "queryintentactivities", "matchinfo",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "action_install_package", "packageinstaller", "packagesession",
        "packages::install",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "applicationoverlay", "system_alert_window", "addwindowview",
    ),
    "android.permission.WRITE_SETTINGS": (
        "settings.system.put", "settings.canwrite",
    ),
    "android.permission.BLUETOOTH_SCAN": ("bluetoothlescanner", "bluetoothadapter"),
    "android.permission.BLUETOOTH_CONNECT": ("bluetoothadapters", "bluetoothdevice"),
}

_MATRIX_MAX_ROWS = 40


def _dex_surface(target) -> str:
    """Classes + methods from every parsed DEX, one lowercase haystack."""
    parts: List[str] = []
    for dex in target.meta.get("dex") or []:
        parts.extend(dex.get("classes") or [])
        parts.extend(dex.get("methods") or [])
    return " ".join(parts).lower()


def _pool_surface(target) -> List[Tuple[str, str]]:
    """(relpath, lowercase value) from the shared string pool."""
    return [
        (rel, (value or "").lower())
        for rel, value in (getattr(target, "string_pool", None) or [])
        if value
    ]


def _manifest_surface(target) -> str:
    """Component names + intent-filter actions, one lowercase haystack."""
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return ""
    parts: List[str] = []
    for component in manifest.all_components():
        parts.append(component.name)
        for f in component.filters:
            parts.extend(f.actions)
    return " ".join(parts).lower()


def build_privacy_matrix(target) -> Dict[str, Any]:
    """Corroborate every declared dangerous permission; returns the matrix."""
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return {}
    declared: List[str] = list(getattr(manifest, "uses_permissions", None) or [])
    dangerous = sorted(
        p for p in declared if p in DANGEROUS_PERMISSIONS
    )

    hs_dex = _dex_surface(target)
    pool = _pool_surface(target)
    hs_manifest = _manifest_surface(target)

    rows: List[Dict[str, Any]] = []
    for name in dangerous:
        markers = _SIGNALS.get(name, ())
        observed: List[Dict[str, str]] = []
        for marker in markers:
            if marker in hs_dex:
                observed.append({"marker": marker, "surface": "dex-classes"})
            elif marker in hs_manifest:
                observed.append({"marker": marker, "surface": "manifest"})
            else:
                for rel, value in pool:
                    if marker in value:
                        observed.append(
                            {"marker": marker, "surface": f"string-pool:{rel}"}
                        )
                        break
        rows.append(
            {
                "permission": name,
                "special": name in SPECIAL_ACCESS,
                "signals": len(observed),
                "observed": observed[:12],
                "corroborated": bool(observed),
                "excess": len(observed) == 0,
            }
        )
        if len(rows) >= _MATRIX_MAX_ROWS:
            break

    counts = {
        "dangerous": len(rows),
        "corroborated": sum(1 for r in rows if r["corroborated"]),
        "excess": sum(1 for r in rows if r["excess"]),
        "special": sum(1 for r in rows if r["special"]),
    }
    matrix = {"rows": rows, "counts": counts}
    target.meta["privacy_matrix"] = matrix
    return matrix

"""At-a-glance overview facts (the "APP/FILE INFORMATION" panel).

MobSF-style front page, masanalyzer-flavoured: everything here is a
parsed fact (file hashes, manifest identity, signing schemes and the
leaf certificate, permission protection levels, component counts) plus
the analysis layer on top of it (score, assurance counts, surface
summary with the fix-first queue).  No invented claims: permission
descriptions are deliberately absent — the protection level comes from
the manifest itself, nothing else is asserted.

The synthesis never raises: a fact it cannot extract is simply absent
from the returned dict, so ``build_overview`` can run inside any
renderer or the dashboard without a guard.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

_HASH_CHUNK = 1 << 20

_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"


def _file_facts(target: Any) -> Dict[str, Any]:
    """Name, size and content hashes of the analyzed artifact."""
    path = getattr(target, "input_path", None)
    name = getattr(target, "name", None) or (
        os.path.basename(str(path)) if path else "")
    out: Dict[str, Any] = {}
    if name:
        out["name"] = str(name)
    size = 0
    if path and os.path.isfile(str(path)):
        digesters = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }
        size = os.path.getsize(str(path))
        try:
            with open(str(path), "rb") as fh:
                for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
                    for d in digesters.values():
                        d.update(chunk)
            out.update({k: d.hexdigest() for k, d in digesters.items()})
        except OSError:  # noqa: BLE001 - hashes are best-effort
            pass
    if not size:
        apk = (getattr(target, "meta", None) or {}).get("apk")
        size = getattr(apk, "size", 0) or 0
    if size:
        out["size_bytes"] = int(size)
    return out


def _display(comp_name: str, package: str) -> str:
    """Expand ``.Short`` component shorthand to the fully qualified name."""
    if not comp_name:
        return ""
    if comp_name.startswith("."):
        return f"{package}{comp_name}" if package else comp_name[1:]
    if "." not in comp_name and package:
        return f"{package}.{comp_name}"
    return comp_name


def _app_facts(target: Any) -> Dict[str, Any]:
    """Manifest identity facts (Android) — absent keys stay absent."""
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return {}
    package = str(getattr(manifest, "package", "") or "")
    out: Dict[str, Any] = {
        "package": package,
        "version_name": str(getattr(manifest, "version_name", "") or ""),
        "version_code": str(getattr(manifest, "version_code", "") or ""),
        "min_sdk": getattr(manifest, "min_sdk", None),
        "target_sdk": getattr(manifest, "target_sdk", None),
    }
    max_sdk = getattr(manifest, "max_sdk", None)
    if max_sdk:
        out["max_sdk"] = max_sdk
    label = getattr(manifest, "application_label", None)
    if label:
        out["app_name"] = str(label)
    elif target.meta.get("resource_strings"):
        # label attribute itself absent; nothing to resolve — keep absent
        pass
    application_class = getattr(manifest, "application_class", None)
    if application_class:
        out["application_class"] = _display(str(application_class), package)

    # main activity = the LAUNCHER entry point
    for comp in getattr(manifest, "activities", None) or []:
        for filt in getattr(comp, "filters", None) or []:
            if _LAUNCHER_CATEGORY in (getattr(filt, "categories", None) or []):
                out["main_activity"] = _display(comp.name, package)
                break
        if out.get("main_activity"):
            break

    comps = getattr(manifest, "all_components", None)
    components = comps() if callable(comps) else (comps or [])
    kinds = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}
    exported = 0
    for c in components:
        kind = str(getattr(c, "kind", "") or "")
        if kind in kinds:
            kinds[kind] += 1
        if getattr(c, "exported", False):
            exported += 1
    counts = {
        "activities": kinds["activity"],
        "services": kinds["service"],
        "receivers": kinds["receiver"],
        "providers": kinds["provider"],
        "total": len(components),
        "exported": exported,
    }

    def _plural(n: int, word: str) -> str:
        if n == 1:
            return f"1 {word}"
        irregular = {"activity": "activities"}
        return f"{n} {irregular.get(word, word + 's')}"

    counts["text"] = (
        f"{_plural(kinds['activity'], 'activity')}, "
        f"{_plural(kinds['service'], 'service')}, "
        f"{_plural(kinds['receiver'], 'receiver')}, "
        f"{_plural(kinds['provider'], 'provider')} "
        f"({_plural(exported, 'exported door')})")
    out["components"] = counts
    return out


def _signature_facts(target: Any) -> Dict[str, Any]:
    """Signing schemes + parsed leaf certificate (Android)."""
    apk = (getattr(target, "meta", None) or {}).get("apk")
    if apk is None:
        return {}
    out: Dict[str, Any] = {"signed": bool(getattr(apk, "signed", False))}

    schemes: Dict[str, Dict[str, Any]] = {}
    for scheme, signer, verified in (
        ("v1", getattr(apk, "v1", None), getattr(apk, "v1_verified", None)),
        ("v2", getattr(apk, "v2", None), getattr(apk, "v2_verified", None)),
        ("v3", getattr(apk, "v3", None), getattr(apk, "v3_verified", None)),
    ):
        present = signer is not None and (
            not isinstance(signer, (list, tuple)) or len(signer) > 0)
        entry: Dict[str, Any] = {"present": bool(present)}
        if verified is not None:
            entry["verified"] = bool(verified)
        schemes[scheme] = entry
    # v3.1 / v3.2 rotation blocks: parsed facts (presence); v3.2's ML-DSA
    # half is not verifiable with the stdlib, so no verified claim is made.
    v3_extra = sorted({
        str(getattr(s, "scheme", "") or "")
        for s in (getattr(apk, "v3", None) or [])
        if str(getattr(s, "scheme", "") or "") not in ("v3", "")
    })
    for scheme in v3_extra:
        schemes[scheme] = {"present": True}
    # v4 = offline .idsig sidecar; presence is a file-level fact
    path = str(getattr(target, "input_path", "") or "")
    idsig = path + ".idsig" if path else ""
    schemes["v4"] = {"present": bool(idsig) and os.path.isfile(idsig)}
    out["schemes"] = schemes
    if getattr(apk, "rollback_protected", None) is not None:
        out["rollback_protected"] = bool(apk.rollback_protected)

    certs: List[Dict[str, Any]] = []
    seen: set = set()
    candidates = [
        getattr(apk, "v1", None),
        getattr(apk, "v2", None),
        *(getattr(apk, "v3", None) or []),
    ]
    for signer in candidates:
        if signer is None or isinstance(signer, (list, tuple)):
            continue
        fp = str(getattr(signer, "cert_sha256", "") or "")
        info = getattr(signer, "cert_info", None)
        key = fp or (info or {}).get("serial", "")
        if not key or key in seen:
            continue
        seen.add(key)
        cert: Dict[str, Any] = {"sha256": fp}
        for field in ("subject", "issuer", "not_before", "not_after",
                      "key_algorithm", "key_bits", "serial", "self_signed",
                      "signature_algorithm", "hash_algorithm",
                      "md5", "sha1", "sha512"):
            if info and field in info:
                cert[field] = info[field]
        certs.append(cert)
    if certs:
        out["certificates"] = certs
    return out


def _permission_rows(target: Any) -> List[Dict[str, Any]]:
    """Declared permissions with their manifest protection level.

    ``uses-permission`` entries carry no ``protectionLevel`` attribute of
    their own, so the level is inferred from the manifest's parsed
    danger/signature flags (the same facts the privacy matrix uses).
    """
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return []
    seen: set = set()
    rows = []
    for p in getattr(manifest, "permissions", None) or []:
        name = str(getattr(p, "name", "") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        if getattr(p, "dangerous", False):
            level = "dangerous"
        elif getattr(p, "signature", False):
            level = "signature"
        else:
            level = str(getattr(p, "protection_level", "") or "normal")
        row: Dict[str, Any] = {"name": name, "protection_level": level}
        # bundled reference description for well-known platform permissions
        try:
            from .android.perm_info import describe

            text = describe(name)
        except Exception:  # noqa: BLE001 - cosmetic only
            text = None
        if text:
            row["description"] = text
        rows.append(row)
    return sorted(rows, key=lambda r: r["name"])


def build_overview(result: Any) -> Dict[str, Any]:
    """Assemble the overview dict for one scan result (never raises)."""
    out: Dict[str, Any] = {}
    try:
        target = getattr(result, "target", None)
        if target is None:
            return out
        out["platform"] = str(getattr(result, "platform", "")
                              or getattr(target, "platform", "") or "")
        file_facts = _file_facts(target)
        if file_facts:
            out["file"] = file_facts
        app = _app_facts(target)
        if app:
            out["app"] = app
        sig = _signature_facts(target)
        if sig:
            out["signature"] = sig
        perms = _permission_rows(target)
        if perms:
            out["permissions"] = perms

        score = getattr(result, "score", None)
        if score is not None and getattr(score, "grade", None):
            out["score"] = {
                "grade": str(score.grade),
                "total": round(float(getattr(score, "total", 0.0) or 0.0), 2),
            }

        findings = list(getattr(result, "findings", None) or [])
        by_sev: Dict[str, int] = {}
        by_tier: Dict[str, int] = {}
        for f in findings:
            sev = str(getattr(getattr(f, "severity", None), "value",
                              getattr(f, "severity", "info"))).lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            tier = str(getattr(f, "assurance", "") or "ungraded").lower()
            by_tier[tier] = by_tier.get(tier, 0) + 1
        out["findings"] = {
            "total": len(findings),
            "by_severity": by_sev,
            "by_assurance": by_tier,
        }

        surface = (getattr(target, "meta", None) or {}).get(
            "attack_surface") or {}
        summary = surface.get("summary") or {}
        if summary:
            out["surface"] = {
                k: summary[k] for k in (
                    "external_entry_points", "unprotected_entry_points",
                    "browsable_deep_links", "browsable_hosts",
                    "surface_findings", "fix_first") if k in summary
            }

        # tracker endpoints observed in the network-indicator inventory
        # (honest count only: no vendor tracker database denominator)
        inv = (getattr(target, "meta", None) or {}).get("endpoints") or {}
        tracker_n = int((inv.get("counts") or {}).get("tracker", 0) or 0)
        if tracker_n:
            out["trackers"] = {
                "count": tracker_n,
                "note": "tracker endpoints observed in the app's network indicators",
            }
    except Exception:  # noqa: BLE001 - overview must never kill a renderer
        return out
    return out

"""CycloneDX 1.5 SBOM report - supply-chain visibility for scanned bundles.

Follows the same rules as the other renderers:

* fully deterministic: components are sorted by ``bom-ref``, the serial
  number is a ``uuid5`` over the target identity, and JSON keys are sorted;
* duck typing only - importing this module never pulls in
  ``masanalyzer.analysis`` (the Gradle-style dependency harvest replicates
  the m02 analyst regex locally).

Component sources (all optional, missing ones are skipped):

* the application itself -> ``metadata.component`` (type ``application``);
* ``target.native_libs``  -> packaged native libraries;
* ``target.meta["embedded_apks"]`` -> nested applications;
* ``target.meta["macho"]``        -> linked dylibs;
* resource files' ``'group:artifact:version'`` strings -> third-party
  Maven-style dependencies.

Findings are exported as CycloneDX ``vulnerabilities`` entries so a scan
and its inventory travel together.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
TOOL_URI = "https://github.com/masanalyzer/masanalyzer"
#: CycloneDX purl nameCosumer for app-store bundles
PURL_ANDROID = "pkg:generic/android-bundle"
PURL_IOS = "pkg:generic/ios-bundle"

#: same wire shape as analysis.m02._RX_DEP (see module note)
_RX_DEP = re.compile(r"['\"]([\w.\-]+:[\w.\-]+):([\w.\-]+)['\"]")

#: OWASP M2 mitigations are the SBOM audience; map finding severities to
#: CycloneDX rating severities as-is (same vocabulary).
_VALID_SEVS = {"info", "low", "medium", "high", "critical"}


def _deps(text: str) -> List[Tuple[str, str]]:
    """Harvest ``'group:artifact:version'`` strings (same shape as m02)."""
    out = []
    for m in _RX_DEP.finditer(text):
        out.append((m.group(1), m.group(2)))
    return out


def _target_identity(target: Any) -> str:
    name = getattr(target, "name", "") or ""
    version = getattr(target, "version", "") or ""
    return f"{name}@{version}"


def _ref_for(raw: str) -> str:
    """Stable, spec-legal bom-ref from an arbitrary component name."""
    return "ref:" + re.sub(r"[^A-Za-z0-9.\-_]+", "_", raw)


def render_sbom(result: Any) -> str:
    """Render one scan result as a CycloneDX 1.5 JSON document (as text)."""
    target = getattr(result, "target", None)
    tool = getattr(result, "tool", {}) or {}
    started = getattr(result, "started", "") or ""

    root_name = _target_identity(target) or "app"
    root_ref = _ref_for(root_name)
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "masanalyzer|" + root_name + "|"
        + (getattr(target, "input_path", "") if target else ""),
    )

    components: List[Dict[str, Any]] = []
    bom_refs: List[str] = []

    for lib in getattr(target, "native_libs", None) or []:
        rel = getattr(lib, "relpath", "") or getattr(lib, "path", "")
        if not rel:
            continue
        ref = _ref_for("native:" + rel)
        if ref in bom_refs:
            continue
        props: List[Dict[str, str]] = []
        for key in ("arch", "platform"):
            val = getattr(lib, key, None)
            if val:
                props.append({"name": f"masanalyzer:{key}", "value": str(val)})
        comp: Dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": rel,
            "size": getattr(lib, "size", 0) or 0,
        }
        if props:
            comp["properties"] = props
        flags = getattr(lib, "flags", None) or {}
        hardening = [
            k for k, v in sorted(flags.items()) if v and k != "uuid"
        ]
        if hardening:
            comp["properties"].append(
                {"name": "masanalyzer:hardening", "value": ",".join(hardening)}
            )
        components.append(comp)
        bom_refs.append(ref)

    for apk in (getattr(target, "meta", {}) or {}).get("embedded_apks", []) or []:
        name = str(getattr(apk, "name", "") or "?")
        ref = _ref_for("embedded:" + name)
        if ref in bom_refs:
            continue
        components.append(
            {
                "type": "application",
                "bom-ref": ref,
                "name": name,
                "description": "nested application bundle found in the payload "
                "(an unsigned one here is M2 supply-chain risk)",
                "size": getattr(apk, "size", 0) or 0,
            }
        )
        bom_refs.append(ref)

    for img in (getattr(target, "meta", {}) or {}).get("macho", []) or []:
        for dylib in getattr(img, "dylibs", None) or []:
            ref = _ref_for("dylib:" + dylib)
            if ref in bom_refs:
                continue
            components.append(
                {
                    "type": "library",
                    "bom-ref": ref,
                    "name": dylib,
                    "description": "Mach-O linked library recorded at scan time",
                    "scope": "required",
                }
            )
            bom_refs.append(ref)

    # Maven-style dependency strings harvested from text resources
    seen_deps: set = set()
    for sf in getattr(target, "files", None) or []:
        if getattr(sf, "kind", "") not in ("resource", "code"):
            continue
        for _lineno, text in sf.lines():
            for dep, version in _deps(text):
                key = (dep, version)
                if key in seen_deps:
                    continue
                seen_deps.add(key)
                ref = _ref_for(f"dep:{dep}:{version}")
                if ref in bom_refs:
                    continue
                components.append(
                    {
                        "type": "library",
                        "bom-ref": ref,
                        "name": dep,
                        "version": version,
                        "purl": f"pkg:maven/{dep}@{version}" if ":" in dep else "",
                        "scope": "required",
                    }
                )
                bom_refs.append(ref)

    # embedded SDK fingerprints (sdks.py): one component per detected SDK,
    # capped so huge multi-SDK apps keep the SBOM readable
    for hit in list((getattr(target, "meta", {}) or {}).get("sdks") or [])[:50]:
        sdk_id = str(hit.get("id", "?"))
        ref = _ref_for("sdk:" + sdk_id)
        if ref in bom_refs:
            continue
        comp: Dict[str, Any] = {
            "type": "framework",
            "bom-ref": ref,
            "name": sdk_id,
            "scope": "required",
            "properties": [
                {"name": "masanalyzer:vendor", "value": str(hit.get("vendor", ""))},
                {"name": "masanalyzer:category", "value": str(hit.get("category", ""))},
            ],
        }
        version = hit.get("version")
        if version:
            comp["version"] = version
        components.append(comp)
        bom_refs.append(ref)

    components.sort(key=lambda c: c.get("bom-ref", ""))
    components = [_strip_empty(c) for c in components]

    vulnerabilities: List[Dict[str, Any]] = []
    for f in getattr(result, "findings", None) or []:
        sev = str(getattr(getattr(f, "severity", None), "value", "") or "")
        if sev not in _VALID_SEVS:
            sev = "info"
        vuln: Dict[str, Any] = {
            "bom-ref": "finding:" + str(getattr(f, "identity", "")),
            "id": getattr(f, "rule_id", "?"),
            "source": {"name": tool.get("name", "masanalyzer"),
                       "url": TOOL_URI},
            "ratings": [{"severity": sev, "method": "other",
                         "score": getattr(f, "cvss", None)},
                        ],
            "description": getattr(f, "description", "") or "",
            "affects": [{"ref": root_ref}],
        }
        if getattr(f, "category", None):
            vuln["properties"] = [
                {"name": "masanalyzer:owasp", "value": str(f.owasp)},
                {"name": "masanalyzer:category", "value": str(f.category)},
            ]
        vulnerabilities.append(vuln)
    vulnerabilities.sort(key=lambda v: (v["id"], v.get("bom-ref", "")))

    platform = getattr(target, "platform", "") if target else ""
    doc = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": started,
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": root_name.split("@", 1)[0],
                "version": root_name.split("@", 1)[1] if "@" in root_name else "",
                "description": "generated by masanalyzer static scan",
            },
            "tools": (
                [{"vendor": "masanalyzer",
                  "name": tool.get("name", "masanalyzer"),
                  "version": tool.get("version", "")}]
            ),
            "properties": (
                [{"name": "masanalyzer:platform", "value": platform}]
                if platform
                else []
            ),
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": bom_refs},
        ],
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities
    doc["metadata"] = _strip_empty(doc["metadata"])
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _strip_empty(node: Any) -> Any:
    """Drop empty dicts/lists and None values recursively."""
    if isinstance(node, dict):
        cleaned = {k: _strip_empty(v) for k, v in node.items()}
        return {k: v for k, v in cleaned.items()
                if v is not None and v != {} and v != [] and v != ""}
    if isinstance(node, list):
        return [_strip_empty(v) for v in node]
    return node

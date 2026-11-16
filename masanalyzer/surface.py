"""Attack-surface synthesis - the "so what" layer.

Raw scanners emit a flat list of findings. masanalyzer additionally
cross-references every externally-reachable entry point parsed from the
manifest (exported components, permission guards, browsable deep links)
with the findings attached to it, so the report opens with the answer to
the reviewer's real question: *what can an attacker reach, and what do
we already know about each door?*  Each door also carries a transparent
exposure score and rationale, so the report ends with a ranked
**fix first** queue instead of yet another unordered list.

The synthesis is pure post-analysis cross-referencing of parsed facts:
nothing here invents claims. Entry points come from the AXML manifest
(``target.manifest``); the findings linked to a component are matched by
exact component-name evidence or by manifest-relative-path evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _max_severity(finding_ids: List[str], by_id: Dict[str, Any]) -> str:
    best = ""
    best_rank = -1
    for fid in finding_ids:
        f = by_id.get(fid)
        if f is None:
            continue
        sev = getattr(f, "severity", None)
        sev = getattr(sev, "value", sev) or "info"
        sev = str(sev).lower()
        rank = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 0
        if rank > best_rank:
            best_rank = rank
            best = _SEV_ORDER[rank]
    return best


def _sev_rank(sev: str) -> int:
    """Severity rank for the fix-first score (0 none .. 5 critical)."""
    if not sev or sev not in _SEV_ORDER:
        return 0
    return len(_SEV_ORDER) - _SEV_ORDER.index(sev)


def _fix_first(entry: Dict[str, Any], by_id: Dict[str, Any]) -> tuple:
    """Exposure score + transparent rationale for one entry point.

    The formula is deliberately simple and fully explainable in the
    report: every point of the score maps to a fact a reviewer can
    verify on the door itself.

    ``score = worst_severity_rank        (0 none .. 5 critical)
            + 2 x verified findings     (signature-verified facts weigh double)
            + 1 if no permission guard  (any app can invoke it)
            + min(deep links, 3)        (browsable reach from the web)
    """
    sev = str(entry.get("worst_severity") or "")
    verified = 0
    for fid in entry.get("findings") or []:
        f = by_id.get(fid)
        if f is not None and getattr(f, "assurance", "") == "verified":
            verified += 1
    unprotected = not entry.get("permission")
    links = len(entry.get("browsable_links") or [])

    score = _sev_rank(sev) + 2 * verified + (1 if unprotected else 0) \
        + min(links, 3)

    why: List[str] = []
    if verified:
        why.append(f"{verified} verified finding"
                   f"{'s' if verified != 1 else ''}")
    if unprotected:
        why.append("no permission guard")
    if links:
        why.append(f"{links} browsable deep link"
                   f"{'s' if links != 1 else ''}")
    if sev:
        why.append(f"worst: {sev}")
    return score, why


def _fix_first_key(entry: Dict[str, Any]) -> tuple:
    """Sort key: exposure score desc, then component name (deterministic)."""
    return (-entry["fix_score"], entry["component"])


def build_surface(target: Any, findings: List[Any]) -> Dict[str, Any]:
    """Cross-reference manifest entry points with findings.

    Returns ``{"entry_points": [...], "summary": {...}}`` or ``{}`` when
    the target has no manifest (e.g. iOS bundles keep an Info.plist
    surface, but the deep-link/component matrix is Android-shaped).
    """
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return {}

    by_id: Dict[str, Any] = {}
    for f in findings:
        by_id[getattr(f, "identity", "")] = f

    manifest_path = target.meta.get("manifest_path") or "AndroidManifest.xml"
    package = getattr(manifest, "package", "") or ""
    entry_points: List[Dict[str, Any]] = []
    browsable_hosts: set = set()

    # manifest-scoped rules whose evidence symbol is NOT a component name
    # (they attach to every exported door); component-specific rules
    # (AUTH-001..004/006) attach via exact symbol match only.
    manifest_rules_all = {"MAS-MIS-003", "MAS-MIS-007"}

    def display_name(comp_name: str) -> str:
        """Expand android:name shorthand to the fully qualified class."""
        if not comp_name:
            return ""
        if comp_name.startswith("."):
            return f"{package}{comp_name}" if package else comp_name[1:]
        if "." not in comp_name and package:
            return f"{package}.{comp_name}"
        return comp_name

    for comp in manifest.exported_components():
        comp_name = display_name(comp.name)
        fid_by_component: List[str] = []
        fid_by_manifest: List[str] = []
        for f in findings:
            ev = getattr(f, "evidence", None)
            if ev is None:
                continue
            ev_file = ev.file or ""
            ev_sym = ev.symbol or ""
            if ev_sym == comp.name and ev_file == manifest_path:
                fid_by_component.append(f.identity)
            elif ev_file == manifest_path and f.rule_id in manifest_rules_all:
                fid_by_manifest.append(f.identity)

        links: List[Dict[str, str]] = []
        for filt in comp.filters:
            if filt.browsable:
                hosts = filt.hosts or [""]
                for host in hosts:
                    browsable_hosts.add(host)
                links.append({
                    "scheme": "/".join(filt.schemes) or "",
                    "host": "/".join(filt.hosts) or "",
                    "path_prefix": "/".join(filt.path_prefixes) or "",
                })

        attached = fid_by_component + [
            fid for fid in fid_by_manifest if fid not in fid_by_component
        ]
        entry_points.append({
            "component": comp_name,
            "kind": comp.kind,
            "reachable": comp.exported_reason,
            "permission": comp.permission or "",
            "browsable_links": links,
            "finding_count": len(attached),
            "findings": attached,
            "worst_severity": _max_severity(attached, by_id),
        })

    for e in entry_points:
        e["fix_score"], e["fix_why"] = _fix_first(e, by_id)

    # webview bridges: only where source analysis produced bridge findings
    webview_files = sorted({
        f.evidence.file
        for f in findings
        if f.rule_id in ("MAS-MIS-004", "MAS-MIS-005", "MAS-INPUT-004")
        and f.evidence.file
    })

    entry_points.sort(key=_fix_first_key)
    unprotected = sum(1 for e in entry_points if not e["permission"])
    total_links = sum(len(e["browsable_links"]) for e in entry_points)
    summary = {
        "external_entry_points": len(entry_points),
        "unprotected_entry_points": unprotected,
        "browsable_deep_links": total_links,
        "browsable_hosts": sorted(h for h in browsable_hosts if h),
        "webview_integration_files": webview_files,
        "surface_findings": sum(e["finding_count"] for e in entry_points),
        "fix_first": [
            {
                "component": e["component"],
                "score": e["fix_score"],
                "why": e["fix_why"],
            }
            for e in entry_points
        ],
    }
    return {
        "entry_points": entry_points,
        "summary": summary,
    }

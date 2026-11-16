"""Machine readable JSON report.

Produces a versioned, self contained document rather than a raw dump of
:mod:`masanalyzer.scanner` internals, so downstream tooling can rely on a
stable shape::

    {
      "report_version": "1",
      "tool":     {"name": "masanalyzer", "version": "1.0.0"},
      "scan":     {"started", "finished", "duration_seconds", "target", ...},
      "score":    ComplianceScore.to_dict() | null,
      "summary":  {"findings": N, "by_severity": {...}, "top_rules": [...]},
      "findings": [Finding.to_dict(), ...]
    }

The renderer only relies on duck typing (``result.target``, ``result.score``,
``Finding.to_dict``) so it never hard-imports scanner/analysis modules.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..model import ALL_SEVERITIES
from ..owasp import ORDER

REPORT_VERSION = "1"
TOP_RULES_LIMIT = 10


def _tool(result: Any) -> Dict[str, Any]:
    """Tool identification, tolerant of a missing result.tool."""
    tool = getattr(result, "tool", None)
    if isinstance(tool, dict):
        return {
            "name": tool.get("name", "masanalyzer"),
            "version": tool.get("version", ""),
        }
    return {"name": "masanalyzer", "version": ""}


def _target_summary(result: Any) -> Dict[str, Any]:
    """Safe summary of the analyzed target (falls back to the input path)."""
    target = getattr(result, "target", None)
    if target is None:
        return {"from": ""}
    summary = target.summary() if callable(getattr(target, "summary", None)) else {}
    return {"from": target.input_path, **summary}


def _severity_counts(findings: List[Any]) -> Dict[str, int]:
    counts = {s.value: 0 for s in ALL_SEVERITIES}
    for f in findings:
        sev = str(getattr(f, "severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _assurance_counts(findings: List[Any]) -> Dict[str, int]:
    """Findings by verification tier (verified/structural/heuristic)."""
    counts: Dict[str, int] = {}
    for f in findings:
        tier = str(getattr(f, "assurance", "") or "ungraded").lower()
        counts[tier] = counts.get(tier, 0) + 1
    return counts


def _top_rules(findings: List[Any]) -> List[Dict[str, Any]]:
    """Distinct rules seen, ordered by how often / how badly they fired."""
    hits: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rid = getattr(f, "rule_id", "?")
        entry = hits.setdefault(
            rid, {"rule_id": rid, "title": getattr(f, "title", ""), "count": 0}
        )
        entry["count"] += 1
    return [
        hits[rid]
        for rid in sorted(hits, key=lambda r: (-hits[r]["count"], r))[:TOP_RULES_LIMIT]
    ]


def _inventory(result: Any) -> Dict[str, Any]:
    """Endpoint + SDK inventory summary (rows capped to stay usable)."""
    target = getattr(result, "target", None)
    meta = getattr(target, "meta", None) or {}
    out: Dict[str, Any] = {}

    inv = meta.get("endpoints") or {}
    if inv:
        rows = list(inv.get("rows") or [])[:200]
        out["endpoints"] = {
            "total": inv.get("total", len(rows)),
            "counts": inv.get("counts", {}),
            "rows": rows,
        }

    # embedded-SDK fingerprints (sdks.py) - full list above ~50 caps the tail
    sdks = meta.get("sdks") or []
    if sdks:
        out["sdks"] = {
            "total": len(sdks),
            "components": [dict(h) for h in sdks[:50]],
        }

    # excess-access privacy matrix (dangerous permission corroboration)
    matrix = meta.get("privacy_matrix") or {}
    if matrix:
        rows = list(matrix.get("rows") or [])[:100]
        counts = dict(matrix.get("counts") or {})
        if rows:
            out["privacy"] = {
                "dangerous": counts.get(
                    "dangerous", sum(1 for _ in rows)
                ),
                "excess": counts.get(
                    "excess", sum(1 for r in rows if r.get("excess"))
                ),
                "corroborated": counts.get(
                    "corroborated", sum(1 for r in rows if r.get("corroborated"))
                ),
                "rows": rows,
            }

    # behaviour analysis (quark-style rule ids attributed to methods)
    behaviour = meta.get("behaviour") or {}
    if behaviour:
        out["behaviour"] = {
            "total_receipts": behaviour.get("total_receipts", 0),
            "behaviours": list(behaviour.get("behaviours") or []),
            "rows": list(behaviour.get("rows") or [])[:200],
        }

    # callsite receipts (URL -> declaring method -> consuming callee)
    receipts = list(meta.get("callsites") or [])
    if receipts:
        out["callsites"] = {
            "total": len(receipts),
            "rows": receipts[:200],
        }

    # NIAP-style assurance matrix (honest subset, mapped to rule ids)
    try:
        from ..niap import niap_matrix

        niap = niap_matrix(result)
        if niap.get("rows"):
            out["niap"] = niap
    except Exception:  # noqa: BLE001 - never kill a report
        pass

    # bundle facts for release/delta gates (deltacli compares two reports)
    bundle = _bundle_facts(result)
    if bundle:
        out["bundle"] = bundle

    # OSV CVE-cache provenance (deterministic facts only, from intel_status)
    intel = meta.get("intel_status")
    if intel:
        out["intel"] = {
            "source": "OSV.dev cache (masanalyzer-refresh-intel)",
            **{k: intel[k] for k in ("built", "coordinates", "advisories")
               if k in intel},
        }

    # attack-surface synthesis (surface.py cross-reference, if produced)
    surface = meta.get("attack_surface")
    if surface:
        entry_points = list(surface.get("entry_points") or [])
        out["attack_surface"] = {
            "summary": dict(surface.get("summary") or {}),
            "entry_points": entry_points[:200],
        }

    # dynamic session ingestion (masanalyzer.runtime): only present when a
    # runtime bundle was supplied, so static reports stay byte-identical
    runtime = meta.get("runtime") or {}
    if runtime:
        out["runtime"] = runtime

    # at-a-glance facts (file hashes, app identity, signature, permissions)
    try:
        from ..overview import build_overview

        overview = build_overview(result)
        if overview:
            out["overview"] = overview
    except Exception:  # noqa: BLE001 - overview must never kill a report
        pass
    return out


def _bundle_facts(result: Any) -> Dict[str, Any]:
    """Version, size, signing fingerprints + declared permission set."""
    import os as _os

    target = getattr(result, "target", None)
    meta = getattr(target, "meta", None) or {}
    manifest = getattr(target, "manifest", None)
    apk = meta.get("apk")

    permissions = sorted(
        {p for p in (getattr(manifest, "uses_permissions", None) or []) if p}
    )
    signers = sorted(
        {str(f).lower() for f in (getattr(apk, "signer_fingerprints", None) or [])}
    )
    size = getattr(apk, "size", 0)
    if not size and getattr(target, "input_path", None):
        try:
            size = _os.path.getsize(target.input_path)
        except OSError:
            size = 0
    if not (permissions or signers or size):
        return {}
    facts: Dict[str, Any] = {}
    if getattr(target, "version", None):
        facts["version"] = str(target.version)
    if size:
        facts["size_bytes"] = int(size)
    if permissions:
        facts["permissions"] = permissions
    if signers:
        facts["signers"] = signers
    if manifest is not None:
        facts["target_sdk"] = getattr(manifest, "target_sdk", None)
    return facts


def render_json(result: Any) -> str:
    """Render a complete versioned JSON report for one scan result."""
    findings = list(getattr(result, "findings", None) or [])
    score = getattr(result, "score", None)
    doc: Dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "tool": _tool(result),
        "scan": {
            "started": getattr(result, "started", "") or "",
            "finished": getattr(result, "finished", "") or "",
            "duration_seconds": round(float(getattr(result, "duration_s", 0.0) or 0.0), 3),
            "analyzers_run": int(getattr(result, "analyzers_run", 0) or 0),
            "analyzers_failed": list(getattr(result, "analyzers_failed", None) or []),
            "covered_categories": [
                c for c in map(str, getattr(result, "covered_categories", None) or [])
                if c and c in ORDER
            ],
            "platform": getattr(result, "platform", ""),
            "target": _target_summary(result),
        },
        "score": score.to_dict() if score is not None else None,
        "summary": {
            "findings": len(findings),
            "by_severity": _severity_counts(findings),
            "by_assurance": _assurance_counts(findings),
            "top_rules": _top_rules(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }
    inventory = _inventory(result)
    if inventory:
        doc["inventory"] = inventory
    return json.dumps(doc, indent=2, ensure_ascii=False)

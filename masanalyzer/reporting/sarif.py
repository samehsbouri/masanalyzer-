"""SARIF 2.1.0 report so the results load in GitHub Advanced Security,
VS Code Code Scanning and Visual Studio.

Two rules keep the output deterministic and uploadable:

* the ``rules`` array holds exactly one entry per distinct ``rule_id``
  seen and is sorted by ``rule_id`` before any ``ruleIndex`` is computed;
* severity maps to SARIF levels (``error``/``warning``/``note``) with a
  four-way split: critical+high -> error, medium -> warning,
  low+info -> note.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..model import Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "masanalyzer"
TOOL_URI = "https://github.com/masanalyzer/masanalyzer"
#: run.originalUriBaseIds key referenced by artifactLocation.uriBaseId
URI_BASE_ID = "SRCROOT"

#: fallback security-severity (GitHub advisory score 0-10) per severity
_SEV_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _sev(finding: Any) -> Severity:
    raw = str(getattr(finding, "severity", "info"))
    try:
        return Severity(raw)
    except ValueError:  # unknown label - degrade to note
        return Severity.INFO


def render_sarif(result: Any) -> str:
    """Render one scan result as a SARIF 2.1.0 JSON document (as text)."""
    findings: List[Any] = list(getattr(result, "findings", None) or [])
    version = (result.tool or {}).get("version", "") if isinstance(result.tool, dict) else ""

    # -- rules: one entry per distinct rule, sorted for determinism ---------
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rid = getattr(f, "rule_id", "?")
        sev = _sev(f)
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": (getattr(f, "title", "") or "").split()[0].strip(".,;") or rid,
                "shortDescription": {"text": getattr(f, "title", "") or rid},
                "fullDescription": {"text": getattr(f, "description", "") or ""},
                "defaultConfiguration": {"level": _LEVELS[sev]},
                "properties": {
                    "security-severity": f.cvss
                    if getattr(f, "cvss", None) is not None
                    else _SEV_SCORE[sev],
                    "tags": list(getattr(f, "tags", None) or []),
                    "owasp": getattr(f, "owasp", "") or "",
                    "cwe": getattr(f, "cwe", None) or "",
                },
            }
            continue
        # repeat observations: keep the worst severity + the best score
        rule = seen[rid]
        cur = _level_to_sev(rule["defaultConfiguration"]["level"])
        if _SEV_SCORE[sev] > _SEV_SCORE[cur]:
            rule["defaultConfiguration"]["level"] = _LEVELS[sev]
        best = rule["properties"]["security-severity"]
        score_now = f.cvss if getattr(f, "cvss", None) is not None else _SEV_SCORE[sev]
        if score_now > best:
            rule["properties"]["security-severity"] = score_now
        for tag in getattr(f, "tags", None) or []:
            if tag not in rule["properties"]["tags"]:
                rule["properties"]["tags"].append(tag)
    rules = [seen[rid] for rid in sorted(seen)]
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}

    # -- results: one entry per finding -------------------------------------
    results: List[Dict[str, Any]] = []
    for f in findings:
        sev = _sev(f)
        ev = getattr(f, "evidence", None)
        rid = getattr(f, "rule_id", "?")
        location = ev.location if ev is not None else ""
        message_parts = [getattr(f, "description", "") or ""]
        if location:
            message_parts.append(f"Location: {location}")
        if ev is not None and getattr(ev, "snippet", None):
            message_parts.append(f"Evidence: {ev.snippet}")
        entry: Dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index.get(rid, 0),
            "level": _LEVELS[sev],
            "message": {"text": " \n".join(p for p in message_parts if p)},
            "fingerprints": {"masanalyzer/id": getattr(f, "identity", "")},
        }
        if ev is not None and ev.file:
            region: Dict[str, Any] = {}
            if getattr(ev, "line", None):
                region["startLine"] = int(ev.line)
                region["endLine"] = int(ev.line)      # flags cover the line
            if getattr(ev, "offset", None) is not None:
                snippet_bytes = (ev.snippet or "").encode("utf-8")
                region["byteOffset"] = int(ev.offset)
                region["byteLength"] = len(snippet_bytes)
                region.pop("startLine", None)
            if getattr(ev, "snippet", None) is not None:
                region["snippet"] = {"text": ev.snippet}
            loc: Dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ev.file.replace("\\", "/"),
                        "uriBaseId": URI_BASE_ID,
                    }
                }
            }
            if region:
                loc["physicalLocation"]["region"] = region
            entry["locations"] = [loc]
        if getattr(f, "cvss", None) is not None:
            entry["properties"] = {"security-severity": f.cvss}
        else:
            entry["properties"] = {"security-severity": _SEV_SCORE[sev]}
        results.append(entry)

    return _dump(version, rules, results)


def _level_to_sev(level: str) -> Severity:  # pragma: no cover - helper only
    return {v: k for k, v in _LEVELS.items()}.get(level, Severity.INFO)


def _dump(version: str, rules: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> str:
    import json

    doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": version,
                    "informationUri": TOOL_URI,
                    "rules": rules,
                }
            },
            "results": results,
            # spec naming for the artifactLocation.uriBaseId references;
            # upload pipelines map SRCROOT to the repository/app root
            "originalUriBaseIds": {
                URI_BASE_ID: {
                    "description": {"text": "root of the scanned application"}
                }
            },
            "columnKind": "unicodeCodeUnits",
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)

"""Readable Markdown report for humans.

Layout: title, tool/scan summary table, OWASP score table, severity
histogram, worst-first top list, then a detailed section grouped by
severity.  Every dynamic value is escaped for Markdown inline/table
contexts (pipes, backticks, newlines) so hostile app strings cannot
break the layout.  No raw HTML is emitted.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..model import ALL_SEVERITIES
from ..owasp import CATEGORIES
from .score import score_to_grade  # noqa: F401  (re-exported via __init__)

SEV_ORDER = [s.value for s in ALL_SEVERITIES]
SEV_TITLES = {s.value: s.value.upper() for s in ALL_SEVERITIES}
SNIPPET_MAX = 200


def _cell(text: Any) -> str:
    """Escape a value for use inside a Markdown table cell."""
    out = str(text if text is not None else "")
    return out.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("\n", " ")


def _code(text: Any) -> str:
    """Escape a value for use inside inline or fenced code."""
    return str(text if text is not None else "").replace("`", "'")


def _attributes(f: Any) -> str:
    """Compact ``severity / confidence / owasp / cwe`` line for one finding."""
    parts = [f"Severity: {SEV_TITLES[str(f.severity)]}",
             f"Confidence: {getattr(f.confidence, 'value', f.confidence)}"]
    tier = getattr(f, "assurance", "") or ""
    if tier:
        parts.append(f"Assurance: {tier}")
    owasp = getattr(f, "owasp", "")
    cat = CATEGORIES.get((owasp or "").upper())
    parts.append(f"OWASP: {owasp} {cat.name}" if cat else f"OWASP: {owasp}")
    if getattr(f, "cwe", None):
        parts.append(f"CWE: {f.cwe}")
    if getattr(f, "cvss", None) is not None:
        parts.append(f"CVSS: {f.cvss}")
    if getattr(f, "legacy_owasp", None):
        parts.append(f"Legacy: {f.legacy_owasp}")
    return " / ".join(_cell(p) for p in parts)


def _finding_block(f: Any, index: int) -> List[str]:
    ev = f.evidence
    lines = [f"#### {index}. {_code(f.rule_id)} - {_cell(f.title)}", ""]
    lines.append(f"- {_attributes(f)}")
    lines.append(f"- Location: `{_code(ev.location)}`")
    if getattr(ev, "symbol", None):
        # the exact component/endpoint/flag the rule matched on
        lines.append(f"- Matched: {_cell(ev.symbol)}")
    if getattr(ev, "note", None):
        lines.append(f"- How detected: {_cell(ev.note)}")
    if getattr(f, "tags", None):
        lines.append(f"- Tags: {', '.join(_cell(t) for t in f.tags)}")
    lines.append("")
    lines.append(_cell(getattr(f, "description", "")))
    if ev.snippet:
        where = f" (line {ev.line})" if ev.line else ""
        lines += ["", f"Exact code{where}:", f"```", _code(ev.snippet[:SNIPPET_MAX]), "```"]
    if getattr(f, "remediation", ""):
        lines += ["", f"**Remediation**", "", _cell(f.remediation)]
    if getattr(f, "references", None):
        lines += ["", "**References**", "", *[f"- {_cell(r)}" for r in f.references]]
    if getattr(f, "poc", ""):
        lines += ["", f"**Proof of concept**: `{_code(f.poc[:SNIPPET_MAX])}`"]
    lines.append("")
    return lines


def _score_table(result: Any) -> List[str]:
    score = getattr(result, "score", None)
    lines: List[str] = []
    if hasattr(score, "to_dict"):
        detail = score.to_dict()
        lines += [
            f"## Compliance score: {detail['total']} / 100 (grade {detail['grade']})", "",
            "| Category | Name | Score | Grade | Findings |",
            "|---|---|---|---|---|",
        ]
        for cat in detail["categories"]:
            if cat.get("in_scope"):
                lines.append(
                    f"| {_cell(cat['id'])} | {_cell(cat['name'])} | {cat['score']} "
                    f"| {cat['grade']} | {cat['findings']} |"
                )
    elif score is not None and getattr(score, "total", None) is not None:
        total = getattr(score, "total")
        lines += [f"## Compliance score: {total} / 100 (grade {score_to_grade(total)})"]
    return lines or ["## Compliance score: n/a"]


def _surface_section(result: Any) -> List[str]:
    """Attack-surface synthesis: externally reachable doors + known findings."""
    target = getattr(result, "target", None)
    surface = (getattr(target, "meta", None) or {}).get("attack_surface") or {}
    entry_points = surface.get("entry_points") or []
    summary = surface.get("summary") or {}
    if not entry_points:
        return []
    sev_titles = SEV_TITLES
    lines = [
        "## Attack surface", "",
        "Externally-reachable entry points parsed from the manifest, "
        "cross-referenced with the findings attached to each (by exact "
        "component-name evidence or manifest-scoped rules). Start the review "
        "at the worst-severity door.", "",
        "| Component | Kind | Reachable via | Permission | Deep links | Findings | Worst |",
        "|---|---|---|---|---|---|---|",
    ]
    for e in entry_points:
        worst = str(e.get("worst_severity") or "-")
        worst = sev_titles.get(worst, worst) if worst != "-" else "-"
        links = e.get("browsable_links") or []
        link_txt = "; ".join(
            (f"{l.get('scheme') or 'any'}://{l.get('host') or ''}"
             f"{l.get('path_prefix') or ''}") for l in links
        ) if links else "-"
        lines.append(
            f"| {_cell(e.get('component', ''))} | {_cell(e.get('kind', ''))} "
            f"| {_cell(e.get('reachable', ''))} | {_cell(e.get('permission') or '-')} "
            f"| {_cell(link_txt)} | {e.get('finding_count', 0)} | {worst} |"
        )
    lines += [""]
    if summary:
        lines += [
            f"**Entry points**: {summary.get('external_entry_points', 0)} "
            f"(unprotected: {summary.get('unprotected_entry_points', 0)}) · "
            f"**Browsable deep links**: {summary.get('browsable_deep_links', 0)} "
            f"on hosts: "
            f"{', '.join('`' + _code(h) + '`' for h in summary.get('browsable_hosts') or []) or '-'} · "
            f"**Findings touching the surface**: "
            f"{summary.get('surface_findings', 0)}",
        ]
        webview_files = summary.get("webview_integration_files") or []
        if webview_files:
            lines += [
                "",
                "WebView integration files (JS-bridge / unvalidated-load "
                "findings): " + ", ".join(f"`{_code(w)}`" for w in webview_files),
            ]
    fix_first = summary.get("fix_first") or []
    if fix_first:
        lines += [
            "",
            "### Fix first", "",
            "Exposure-ranked remediation order. Score = worst severity "
            "(0-5) + 2 × verified findings + 1 if unguarded + min(deep "
            "links, 3) — every term maps to a fact on the door itself.",
            "",
            "| # | Component | Score | Why |",
            "|---|---|---|---|",
        ]
        for i, e in enumerate(fix_first[:5], 1):
            why = " · ".join(e.get("why") or []) or "-"
            lines.append(
                f"| {i} | {_cell(e.get('component', ''))} "
                f"| {int(e.get('score', 0))} | {_cell(why)} |"
            )
        if len(fix_first) > 5:
            lines += ["", f"*{len(fix_first) - 5} more ranked door(s) in "
                          "`report.json` → `inventory.attack_surface.summary."
                          "fix_first`.*"]
    lines += [""]
    return lines


def _intel_line(result: Any) -> List[str]:
    """CVE-cache provenance line (only present with --osv-cache)."""
    target = getattr(result, "target", None)
    intel = (getattr(target, "meta", None) or {}).get("intel_status") or {}
    if not intel.get("coordinates"):
        return []
    built = str(intel.get("built") or "unknown")
    return [
        f"_CVE data: OSV.dev cache, {intel['coordinates']} coordinates, "
        f"{intel.get('advisories', 0)} advisories, newest fetch {built}. "
        f"Stale coordinates refresh automatically at scan time; "
        f"`masanalyzer-refresh-intel` refreshes fleet-wide._",
        "",
    ]


def _overview_section(result: Any) -> List[str]:
    """At-a-glance fact block: file hashes, app identity, signature."""
    try:
        from ..overview import build_overview

        ov = build_overview(result)
    except Exception:  # noqa: BLE001
        return []
    if not ov:
        return []
    rows: List[tuple] = []
    file_facts = ov.get("file") or {}
    if file_facts.get("name"):
        rows.append(("File name", file_facts["name"]))
    if file_facts.get("size_bytes"):
        size = file_facts["size_bytes"]
        rows.append(("Size", f"{size / (1 << 20):.2f} MiB ({size:,} bytes)"))
    for k in ("md5", "sha1", "sha256"):
        if file_facts.get(k):
            rows.append((k.upper(), f"`{file_facts[k]}`"))
    app = dict(ov.get("app") or {})
    comps = app.pop("components", None) or {}
    for k, title in (("app_name", "App name"), ("package", "Package name"),
                     ("version_name", "Version name"),
                     ("version_code", "Version code"),
                     ("min_sdk", "Min SDK"), ("target_sdk", "Target SDK"),
                     ("max_sdk", "Max SDK"),
                     ("main_activity", "Main activity"),
                     ("application_class", "Application class")):
        if app.get(k) not in (None, ""):
            rows.append((title, _code(str(app[k]))))
    if comps.get("text"):
        rows.append(("Components", _cell(comps["text"])))
    elif comps:
        rows.append((
            "Components",
            f"{comps.get('activities', 0)} activities, "
            f"{comps.get('services', 0)} services, "
            f"{comps.get('receivers', 0)} receivers, "
            f"{comps.get('providers', 0)} providers "
            f"({comps.get('exported', 0)} exported)"))
    sig = ov.get("signature") or {}
    if sig:
        rows.append(("Signed", "yes" if sig.get("signed") else "no"))
        schemes = sig.get("schemes") or {}
        scheme_txt = ", ".join(
            s for s in ("v1", "v2", "v3", "v3.1", "v3.2", "v4")
            if schemes.get(s, {}).get("present"))
        if scheme_txt:
            rows.append(("Signature schemes", scheme_txt))
        for cert in sig.get("certificates") or []:
            if cert.get("subject"):
                rows.append(("Certificate subject", _cell(cert["subject"])))
            if cert.get("key_algorithm") and cert.get("key_bits"):
                rows.append(("Certificate key",
                             f"{cert['key_algorithm']} "
                             f"{cert['key_bits']} bit"))
            for field in ("signature_algorithm", "hash_algorithm",
                          "sha256", "sha512", "sha1", "md5"):
                if cert.get(field):
                    rows.append((f"Certificate {field.replace('_', ' ')}",
                                 f"`{cert[field]}`"))
            if cert.get("not_after"):
                rows.append(("Certificate valid until",
                             _cell(cert["not_after"])))
    perms = ov.get("permissions") or []
    if perms:
        dangerous = sum(
            1 for p in perms
            if "dangerous" in p.get("protection_level", ""))
        rows.append((
            "Permissions",
            f"{len(perms)} declared "
            f"({dangerous} dangerous protection level)"))
    trackers = ov.get("trackers") or {}
    if trackers.get("count"):
        rows.append((f"{int(trackers['count'])} trackers",
                     _cell(trackers.get("note") or "")))
    if not rows:
        return []
    overview_rows = rows
    perm_lines: List[str] = []
    if perms:
        # full permission table with bundled reference descriptions
        perm_lines = [
            "### Declared permissions", "",
            "| Permission | Protection level | Description |",
            "|---|---|---|",
            *(f"| `{_code(p.get('name', ''))}` | "
              f"{_cell(p.get('protection_level', ''))} | "
              f"{_cell(p.get('description', ''))} |" for p in perms),
            "",
        ]
    out: List[str] = [
        "## Overview", "",
        "| Fact | Value |",
        "|---|---|",
        *(f"| {title} | {value} |" for title, value in overview_rows),
        "",
        *perm_lines,
    ]
    return out


def _behaviour_section(result: Any) -> List[str]:
    """Quark-style API behaviours attributed to declaring methods."""
    try:
        meta = getattr(getattr(result, "target", None), "meta", None) or {}
        behaviour = meta.get("behaviour") or {}
        entries = list(behaviour.get("behaviours") or [])
        if not entries:
            return []
        out: List[str] = [
            "## Behaviour analysis", "",
            f"{len(entries)} API behaviours observed "
            f"({int(behaviour.get('total_receipts', 0) or 0)} receipts); "
            "each hit is attributed to the declaring method.", "",
            "| ID | Behaviour | Hits | Declaring methods |",
            "|---|---|---|---|",
        ]
        for e in entries:
            methods = ", ".join(
                f"`{_code(m)}`" for m in (e.get("methods") or [])[:8])
            out.append(
                f"| `{_code(e.get('id', ''))}` | "
                f"{_cell(e.get('title', ''))} | "
                f"{int(e.get('receipts', 0) or 0)} | "
                f"{methods} |")
        out += [""]
        return out
    except Exception:  # noqa: BLE001 - rendering must never kill a report
        return []


def _niap_section(result: Any) -> List[str]:
    """NIAP-style assurance subset (mapped to rule ids, not a cert)."""
    try:
        from ..niap import niap_matrix

        niap = niap_matrix(result)
    except Exception:  # noqa: BLE001
        return []
    rows = list(niap.get("rows") or [])
    if not rows:
        return []
    return [
        "## Assurance matrix (NIAP-style subset)", "",
        f"_{_cell(niap.get('note', ''))} - pass means the mapped checks "
        "ran and produced no finding; it is exactly as strong as those "
        "checks._", "",
        "| ID | Requirement | Status | Detail |",
        "|---|---|---|---|",
        *(f"| `{_code(r.get('identifier', ''))}` | "
          f"{_cell(r.get('requirement', ''))} | "
          f"{_cell(r.get('status', ''))} | "
          f"{_cell(r.get('detail', ''))} |" for r in rows),
        "",
    ]


def _callsite_receipts_section(result: Any) -> List[str]:
    """Callsite receipts: the decompiled-code view (URL -> method -> callee)."""
    try:
        meta = getattr(getattr(result, "target", None), "meta", None) or {}
        receipts = list(meta.get("callsites") or [])
        if not receipts:
            return []
        shown = receipts[:60]
        out: List[str] = [
            "## Network callsite receipts", "",
            f"{len(receipts)} receipt(s) - the exact string constant "
            "paired with the method that passed it to the consuming "
            "callee (the decompiled-code equivalent, without a bundled "
            "decompiler). Evidence pointers only.", "",
            "| DEX | Method | URL | Callee | Offset |",
            "|---|---|---|---|---|",
        ]
        for r in shown:
            out.append(
                f"| `{_code(r.get('dex', ''))}` "
                f"| `{_code(r.get('method', ''))}` "
                f"| `{_code(r.get('url', ''))}` "
                f"| `{_code(r.get('callee', ''))}` "
                f"| {_cell(r.get('offset', ''))} |")
        out += [""]
        if len(receipts) > len(shown):
            out += [f"_... {len(receipts) - len(shown)} more in "
                    "report.json (inventory.callsites)._", ""]
        return out
    except Exception:  # noqa: BLE001 - rendering must never kill a report
        return []


def render_markdown(result: Any) -> str:
    """Render a human readable Markdown report for one scan result."""
    findings: List[Any] = list(getattr(result, "findings", None) or [])
    target = result.target
    tool = dict(result.tool or {"name": "masanalyzer"})
    dur = round(float(getattr(result, "duration_s", 0.0) or 0.0), 2)

    out: List[str] = []
    label = target.package or target.name or target.input_path
    out += [
        f"# Mobile App Security Report - {_cell(label)}", "",
        "| Tool | Version | Platform | Input |",
        "|---|---|---|---|",
        f"| {_cell(tool.get('name', 'masanalyzer'))} | v{_cell(tool.get('version', '?'))} "
        f"| {_cell(target.platform)} | `{_code(target.input_path)}` |",
        "",
        "| Report | Analyzers run | Failed | Duration (s) | Files |",
        "|---|---|---|---|---|",
        f"| {_cell(result.finished or '')} | {int(getattr(result, 'analyzers_run', 0) or 0)} "
        f"| {len(result.analyzers_failed or [])} | {dur} | {len(target.files)} |",
        "",
    ]
    out += _overview_section(result)
    out += _behaviour_section(result)
    out += _niap_section(result)
    out += _callsite_receipts_section(result)
    out += _score_table(result) + [""]
    out += _intel_line(result)

    # severity histogram ----------------------------------------------------
    counts: Dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    out += [
        "## Severity histogram", "",
        "| Severity | Findings |",
        "|---|---|",
        *(f"| {SEV_TITLES[s]} | {counts[s]} |" for s in SEV_ORDER),
        "",
    ]

    # attack surface — externally reachable doors cross-referenced w/ findings
    out += _surface_section(result)

    # worst findings teaser — a *top* list, not a duplicate of the detail
    # section below: only the 10 highest risk findings are enumerated here.
    out += ["## Top findings", ""]
    if findings:
        ranked = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        shown = ranked[:10]
        out += [
            *(f"{i}. [{SEV_TITLES[str(f.severity)]}] {_cell(f.title)}"
              f" ({_code(f.rule_id)}) - `{_code(f.evidence.location)}`"
              for i, f in enumerate(shown, 1)),
        ]
        if len(ranked) > len(shown):
            out.append(
                f"_…and {len(ranked) - len(shown)} more in the detailed "
                f"section below._"
            )
        out += [
            "",
            "Full evidence (exact matched code / component / detection "
            "note) is in the detailed section below.", "",
        ]
    else:
        out += ["No findings.", ""]

    # detailed section, grouped by severity ---------------------------------
    out += ["## Detailed findings", ""]
    for sev in SEV_ORDER:
        group = [f for f in findings if str(f.severity) == sev]
        if not group:
            continue
        out += [f"### {SEV_TITLES[sev]}", ""]
        for i, f in enumerate(group, 1):
            out += _finding_block(f, i)
    if not findings:
        out += ["_Nothing to report._", ""]
    return "\n".join(out).rstrip() + "\n"

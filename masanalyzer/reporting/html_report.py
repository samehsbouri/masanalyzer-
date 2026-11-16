"""Self contained HTML report (soft canvas, printable, XSS-safe).

Every dynamic string - titles, paths, snippets, category names - passes
through :func:`html.escape`, so a hostile application string like
``<script>alert(1)</script>`` can never break out of the document.  The
whole report is a single file: inline CSS only, no JavaScript, no
external assets.
"""

from __future__ import annotations

import html as _html
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..model import ALL_SEVERITIES

SEV_ORDER = [s.value for s in ALL_SEVERITIES]
SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info"}
SNIPPET_MAX = 280


def _esc(value: Any) -> str:
    return _html.escape(str(value if value is not None else ""))


_CSS = """\
:root{
  --canvas-a:#eceef3;--canvas-b:#dfe2ea;--card:#ffffff;--ink:#10141A;
  --ink2:#3c4048;--muted:#7b8089;--faint:#a8abb3;--line:#eceef3;--line2:#f4f5f8;
  --blue:#5f7fc4;--rose:#b45252;--amber:#a97845;--mint:#5d8a6d;
  --fb:"Segoe UI Variable Display","Segoe UI","Avenir Next",system-ui,-apple-system,sans-serif;
  --fm:"JetBrains Mono","Cascadia Code",Consolas,monospace;
  --shadow:0 26px 48px -38px rgba(16,20,26,.55),0 2px 6px rgba(16,20,26,.04);
}
*{box-sizing:border-box}
body{font-family:var(--fb);font-size:13.5px;line-height:1.62;color:var(--ink2);
  background:
    radial-gradient(90% 70% at 12% 0%,#f4f5f8 0%,transparent 55%),
    radial-gradient(80% 60% at 88% 6%,#e9ebf1 0%,transparent 60%),
    linear-gradient(168deg,var(--canvas-a) 0%,#e6e8ef 45%,var(--canvas-b) 100%);
  margin:0 auto;max-width:62rem;padding:1.6rem 1.15rem 3rem;-webkit-font-smoothing:antialiased}
header.hero{background:var(--card);border-radius:24px;box-shadow:var(--shadow);
  padding:20px 22px;margin:0 0 14px}
h1{color:var(--ink);font-size:22px;line-height:1.25;margin:0 0 8px;font-weight:600;
  letter-spacing:-.03em}
h2{color:var(--ink);font-size:15px;margin:0 0 10px;padding-bottom:8px;
  border-bottom:1px solid var(--line);font-weight:600;letter-spacing:-.02em}
h3{color:var(--ink);font-size:13.5px;margin:1.1rem 0 .35rem;font-weight:600}
p{margin:.45rem 0}
.muted{color:var(--muted)}
nav.topnav{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:3px;
  background:#ffffffd9;backdrop-filter:blur(12px);padding:6px;border-radius:999px;
  box-shadow:var(--shadow);margin:0 0 14px}
nav.topnav a{color:#5c6169;text-decoration:none;padding:6px 12px;border-radius:999px;
  font-size:11.5px;transition:background .16s,color .16s}
nav.topnav a:hover{background:#f1f2f6;color:var(--ink);text-decoration:none}
nav.topnav a:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid #83a2db;
  outline-offset:2px;border-radius:6px}
section.block{background:var(--card);border-radius:22px;box-shadow:var(--shadow);
  padding:20px 22px 18px;margin:14px 0}
section.block .card{background:#fbfcfe;border:1px solid #f1f3f8;border-radius:14px;
  padding:12px 14px;margin:.6rem 0}
.card p{margin:.3rem 0}
.card h3{margin:.1rem 0 .35rem}
.fmeta{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;font-size:11px;
  color:var(--muted)}
.fmeta .fitem{margin-right:0;white-space:nowrap}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:2px}
path,code{font-family:var(--fm);font-size:.9em}
code{color:#3c4048;background:#f4f5f8;border-radius:4px;padding:1px 4px;
  word-break:break-all}
code.loc{color:#4d5159;background:#f4f5f8;border:0;padding:2px 6px;border-radius:6px}
table{border-collapse:collapse;margin:10px 0 0;width:100%;font-size:12px}
th,td{border:0;border-bottom:1px solid var(--line2);padding:8px;text-align:left;
  vertical-align:top}
th{background:transparent;color:#9aa0a8;font-weight:500;font-size:9.5px;
  letter-spacing:.07em;text-transform:uppercase;border-bottom:1px solid var(--line);
  padding:4px 8px 8px}
tr:nth-child(even) td{background:transparent}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-family:var(--fm);font-size:11px;color:var(--muted)}
pre{background:#fbfcfe;border:1px solid #f1f3f8;border-radius:12px;padding:.7rem;
  overflow-x:auto;font-size:10.5px;line-height:1.6}
small{color:var(--muted);font-size:11px}
.grad{font-weight:600;font-family:var(--fm)}
.ok{color:var(--mint)}.warn{color:var(--amber)}.bad{color:var(--rose)}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:9.5px;
  font-weight:500;color:#7b8089;background:#f2f3f6;letter-spacing:.02em}
.chip.crit{background:#fbeaea;color:var(--rose)}
.chip.high{background:#fbeaea;color:var(--rose)}
.chip.med{background:#f8efdf;color:var(--amber)}
.chip.low{background:#eaf3ed;color:var(--mint)}
.chip.info{background:#f2f3f6;color:#7b8089}
.chip.verified{background:#eaf3ed;color:var(--mint)}
.chip.structural{background:#eef2fb;color:var(--blue)}
.chip.heuristic{background:#f2f3f6;color:#7b8089}
footer{margin-top:22px;text-align:center}
footer small{color:var(--faint)}
@media print{
  body{background:#fff;padding:0;max-width:none}
  nav.topnav{display:none}
  header.hero,section.block{box-shadow:none;border:1px solid #e5e7ee;
    break-inside:avoid;page-break-inside:avoid}
  section.block .card{break-inside:avoid}
  a{color:inherit}
}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{
  animation:none!important;transition:none!important}}
"""


def _grade_class(grade: str) -> str:
    if grade in ("A+", "A", "B"):
        return "ok"
    return "bad" if grade in ("F",) else "warn"


def _chip(sev: str) -> str:
    return f"<span class=\"chip {SEV_CLASS.get(sev, 'info')}\">{_esc(sev.upper())}</span>"


def _results_header(result: Any) -> List[str]:
    tool = dict(getattr(result, "tool", None) or {"name": "masanalyzer"})
    target = result.target
    dur = round(float(getattr(result, "duration_s", 0.0) or 0.0), 2)
    return [
        "<header class=\"hero\">",
        f"<h1>Mobile App Security Report &ndash; {_esc(target.package or target.name or target.input_path)}</h1>",
        f"<p class=\"muted\">Scan finished <b>{_esc(result.finished or 'n/a')}</b> &mdash; "
        f"duration {dur}s, "
        f"{int(getattr(result, 'analyzers_run', 0) or 0)} analyzers run, "
        f"{len(target.files)} files, {len(findings(result))} findings.</p>",
        "</header>",
        "<table>",
        "<tr><th>Tool</th><th>Version</th><th>Platform</th><th>Input</th></tr>",
        f"<tr><td>{_esc(tool.get('name', 'masanalyzer'))}</td><td>v{_esc(tool.get('version', '?'))}</td>"
        f"<td>{_esc(target.platform)}</td><td><code>{_esc(target.input_path)}</code></td></tr>",
        "</table>",
    ]


def findings(result: Any) -> List[Any]:
    return list(getattr(result, "findings", None) or [])


def _score_section(result: Any) -> List[str]:
    out: List[str] = []
    score = getattr(result, "score", None)
    if score is None or not callable(getattr(score, "to_dict", None)):
        return out
    detail = score.to_dict()
    total, grade = detail["total"], detail["grade"]
    cls = _grade_class(grade)
    out += [
        f"<h2>Compliance score: <span class=\"grad {cls}\">{_esc(total)} / 100 ({_esc(grade)})</span></h2>",
        "<table><tr><th>Category</th><th>Name</th><th>Score</th><th>Grade</th><th>Findings</th></tr>",
    ]
    for cat in detail["categories"]:
        if not cat.get("in_scope"):
            continue
        gcls = _grade_class(cat["grade"])
        out.append(
            f"<tr><td>{_esc(cat['id'])}</td><td>{_esc(cat['name'])}</td>"
            f"<td class=\"num\">{_esc(cat['score'])}</td>"
            f"<td class=\"grad {gcls}\">{_esc(cat['grade'])}</td>"
            f"<td class=\"num\">{cat['findings']}</td></tr>"
        )
    out += ["</table>"]
    return out


def _histogram(findings_list: List[Any]) -> List[str]:
    counts: Dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in findings_list:
        sev = str(getattr(f, "severity", ""))
        counts[sev] = counts.get(sev, 0) + 1
    out = ["<h2>Findings by severity</h2><p>"]
    out += [_chip(sev) + f" &times; {counts[sev]} &nbsp;" for sev in SEV_ORDER]
    out += ["</p>"]
    return out


def _finding_card(f: Any, index: int) -> List[str]:
    ev = getattr(f, "evidence", None)
    sev = str(getattr(f, "severity", "info"))
    refs = getattr(f, "references", None)
    metas = [
        f"{_chip(sev)} confidence: {_esc(getattr(f.confidence, 'value', f.confidence))}",
    ]
    tier = str(getattr(f, "assurance", "") or "")
    if tier:
        # assurance tier: how the finding was established, not what it says
        metas.append(f"assurance: <span class=\"chip {_esc(tier)}\">{_esc(tier)}</span>")
    if getattr(f, "owasp", None):
        metas.append(f"OWASP {_esc(f.owasp)}")
    if getattr(f, "cwe", None):
        metas.append(_esc(f.cwe))
    if getattr(f, "cvss", None) is not None:
        metas.append(f"CVSS {_esc(f.cvss)}")
    card = [
        f"<div class=\"card\" id=\"fnd-{index}\">",
        f"<h3>{index}. {_esc(getattr(f, 'rule_id', ''))} &ndash; {_esc(getattr(f, 'title', ''))}</h3>",
        "<p class=\"fmeta\">" + "".join(
            f"<span class=\"fitem\">{m}</span>" for m in metas if m) + "</p>",
    ]
    if ev is not None:
        card.append(f"<p><code class=\"loc\">{_esc(ev.location)}</code></p>")
        if getattr(ev, "symbol", None):
            card.append(
                f"<p><small><b>Matched:</b> <code>{_esc(ev.symbol)}</code></small></p>"
            )
        if getattr(ev, "snippet", None):
            where = f" (line {_esc(ev.line)})" if getattr(ev, "line", None) else ""
            card.append(
                f"<p><small><b>Exact code{where}:</b></small></p>"
                f"<pre><code>{_esc(ev.snippet[:SNIPPET_MAX])}</code></pre>"
            )
    if getattr(ev, "note", None):
        card.append(f"<p><small><b>How detected:</b> {_esc(ev.note)}</small></p>")
    if getattr(f, "remediation", ""):
        card.append(f"<p><b>Remediation:</b> {_esc(f.remediation)}</p>")
    if getattr(f, "poc", ""):
        card.append(f"<p><b>PoC:</b> <code>{_esc(f.poc[:SNIPPET_MAX])}</code></p>")
    if refs:
        card.append("<p><small>References: "
                    + ", ".join(_esc(r) for r in refs) + "</small></p>")
    card += ["</div>"]
    return card


def _summary_table(findings_list: List[Any]) -> List[str]:
    """Compact, anchor-linked index of every finding (jump-to-card)."""
    out = ["<h2>Findings</h2>", "<table>",
           "<tr><th>#</th><th>Severity</th><th>OWASP</th><th>Rule</th>"
           "<th>Location</th></tr>"]
    for i, f in enumerate(findings_list, 1):
        ev = getattr(f, "evidence", None)
        sev = str(getattr(f, "severity", "info"))
        rule = getattr(f, "rule_id", "?")
        title = getattr(f, "title", "")
        loc = getattr(ev, "location", "") if ev is not None else ""
        out.append(
            f"<tr><td><a href=\"#fnd-{i}\">{i}</a></td>"
            f"<td>{_chip(sev)}</td>"
            f"<td>{_esc(getattr(f, 'owasp', ''))}</td>"
            f"<td><code>{_esc(rule)}</code> {_esc(title)}</td>"
            f"<td><code class=\"loc\">{_esc(loc)}</code></td></tr>"
        )
    out += ["</table>"]
    return out


def _surface_section(result: Any) -> List[str]:
    """Attack-surface synthesis table (entry points x known findings)."""
    target = getattr(result, "target", None)
    surface = (getattr(target, "meta", None) or {}).get("attack_surface") or {}
    entry_points = surface.get("entry_points") or []
    if not entry_points:
        return []
    doc = [
        "<h2>Attack surface</h2>",
        "<p>Externally-reachable entry points from the manifest, "
        "cross-referenced with findings attached to each component.</p>",
        "<table>",
        "<tr><th>Component</th><th>Kind</th><th>Reachable via</th>"
        "<th>Permission</th><th>Deep links</th><th>Findings</th><th>Worst</th></tr>",
    ]
    for e in entry_points:
        worst = str(e.get("worst_severity") or "")
        worst_cell = _chip(worst) if worst else "&ndash;"
        links = e.get("browsable_links") or []
        link_txt = "<br>".join(
            _esc(f"{l.get('scheme') or 'any'}://{l.get('host') or ''}"
                 f"{l.get('path_prefix') or ''}") for l in links
        ) if links else "&ndash;"
        doc.append(
            f"<tr><td><code>{_esc(e.get('component', ''))}</code></td>"
            f"<td>{_esc(e.get('kind', ''))}</td>"
            f"<td>{_esc(e.get('reachable', ''))}</td>"
            f"<td>{_esc(e.get('permission') or '-')}</td>"
            f"<td>{link_txt}</td>"
            f"<td>{int(e.get('finding_count', 0))}</td>"
            f"<td>{worst_cell}</td></tr>"
        )
    doc += ["</table>"]
    summary = surface.get("summary") or {}
    if summary:
        hosts = ", ".join(
            f"<code>{_esc(h)}</code>" for h in summary.get("browsable_hosts") or []
        ) or "-"
        doc.append(
            f"<p><small>Entry points: "
            f"{int(summary.get('external_entry_points', 0))} "
            f"(unprotected: {int(summary.get('unprotected_entry_points', 0))}). "
            f"Browsable deep links: "
            f"{int(summary.get('browsable_deep_links', 0))} on {hosts}. "
            f"Findings touching the surface: "
            f"{int(summary.get('surface_findings', 0))}.</small></p>"
        )
    fix_first = summary.get("fix_first") or []
    if fix_first:
        doc += [
            "<h3>Fix first</h3>",
            "<p>Exposure-ranked remediation order. Score = worst severity "
            "(0&ndash;5) + 2 &times; verified findings + 1 if unguarded "
            "+ min(deep links, 3) &mdash; every term maps to a fact on "
            "the door itself.</p>",
            "<table>",
            "<tr><th>#</th><th>Component</th><th>Score</th><th>Why</th></tr>",
        ]
        for i, e in enumerate(fix_first[:5], 1):
            why = "; ".join(
                _esc(w) for w in (e.get("why") or [])) or "&ndash;"
            doc.append(
                f"<tr><td>{i}</td>"
                f"<td><code>{_esc(e.get('component', ''))}</code></td>"
                f"<td><strong>{int(e.get('score', 0))}</strong></td>"
                f"<td>{why}</td></tr>"
            )
        doc += ["</table>"]
        if len(fix_first) > 5:
            doc += [
                f"<p><small>{len(fix_first) - 5} more ranked door(s) in "
                "<code>report.json</code> &rarr; "
                "<code>inventory.attack_surface.summary.fix_first</code>."
                "</small></p>",
            ]
    return doc


def _overview_section(result: Any) -> List[str]:
    """At-a-glance facts grid (file/app/signature/permissions)."""
    try:
        from ..overview import build_overview

        ov = build_overview(result)
    except Exception:  # noqa: BLE001
        return []
    if not ov:
        return []

    def _kv(rows: List[tuple]) -> List[str]:
        out = ["<table><tr><th>Fact</th><th>Value</th></tr>"]
        for k, v in rows:
            if v in (None, "", "None"):
                continue
            cell = _esc(v)
            if k in ("sha256", "sha512", "sha1", "md5", "v2_cert_sha256"):
                cell = f"<code>{cell}</code>"
            out.append(f"<tr><td>{_esc(k.replace('_', ' '))}</td>"
                       f"<td>{cell}</td></tr>")
        out.append("</table>")
        return out

    doc: List[str] = ["<h2>Overview</h2>"]
    file_rows = [(k, v) for k, v in (ov.get("file") or {}).items()
                 if k != "size_bytes"]
    if ov.get("file", {}).get("size_bytes"):
        size = ov["file"]["size_bytes"]
        file_rows.insert(
            1, ("size",
                f"{size / (1 << 20):.2f} MiB ({size:,} bytes)"))
    if file_rows:
        doc += ["<h3>File information</h3>"] + _kv(file_rows)
    app = ov.get("app") or {}
    if app:
        app = dict(app)
        comps = app.pop("components", None) or {}
        rows = [(k, str(v)) for k, v in app.items()]
        if comps.get("text"):
            rows.append(("components", comps["text"]))
        elif comps:
            rows.append((
                "components",
                f"{comps.get('activities', 0)} activities, "
                f"{comps.get('services', 0)} services, "
                f"{comps.get('receivers', 0)} receivers, "
                f"{comps.get('providers', 0)} providers "
                f"({comps.get('exported', 0)} exported)"))
        doc += ["<h3>App information</h3>"] + _kv(rows)
    sig = ov.get("signature") or {}
    if sig:
        schemes = sig.get("schemes") or {}
        present = [s for s in ("v1", "v2", "v3", "v3.1", "v3.2", "v4")
                   if schemes.get(s, {}).get("present")]
        scheme_txt = ", ".join(present)
        rows = [("signed", "yes" if sig.get("signed") else "no")]
        if scheme_txt:
            rows.append(("signature schemes", scheme_txt))
        for cert in sig.get("certificates") or []:
            for field in ("subject", "issuer", "not_before", "not_after",
                          "key_algorithm", "key_bits", "serial", "sha256",
                          "sha512", "sha1", "md5", "signature_algorithm",
                          "hash_algorithm"):
                if field in cert:
                    rows.append((f"certificate {field}", str(cert[field])))
        doc += ["<h3>Signer certificate</h3>"] + _kv(rows)
    perms = ov.get("permissions") or []
    if perms:
        dangerous = [p for p in perms
                     if "dangerous" in p.get("protection_level", "")]
        doc += [
            "<h3>Permissions</h3>",
            f"<p>{len(perms)} declared "
            f"({len(dangerous)} dangerous protection level).</p>",
            "<table><tr><th>Permission</th><th>Protection level</th>"
            "<th>Description</th></tr>",
        ]
        for p in perms:
            doc.append(
                f"<tr><td><code>{_esc(p.get('name', ''))}</code></td>"
                f"<td>{_esc(p.get('protection_level', ''))}</td>"
                f"<td>{_esc(p.get('description', ''))}</td></tr>")
        doc += ["</table>"]
    trackers = ov.get("trackers") or {}
    if trackers.get("count"):
        doc += [
            "<h3>Trackers</h3>",
            f"<p>{int(trackers['count'])} "
            f"{_esc(trackers.get('note', 'tracker endpoints observed'))}"
            f".</p>",
        ]
    return doc


def _behaviour_section(result: Any) -> List[str]:
    """Quark-style API behaviours attributed to declaring methods."""
    meta = getattr(getattr(result, "target", None), "meta", None) or {}
    behaviour = meta.get("behaviour") or {}
    entries = list(behaviour.get("behaviours") or [])
    if not entries:
        return []
    doc: List[str] = [
        "<h2>Behaviour analysis</h2>",
        f"<p>{len(entries)} API behaviours observed "
        f"({int(behaviour.get('total_receipts', 0) or 0)} receipts). "
        "Each hit is attributed to the declaring method - evidence "
        "pointers, not a dataflow guarantee.</p>",
        "<table><tr><th>ID</th><th>Behaviour</th><th>Hits</th>"
        "<th>Declaring methods</th></tr>",
    ]
    for e in entries:
        methods = " ".join(
            f"<code>{_esc(m)}</code>" for m in (e.get("methods") or [])[:8])
        doc.append(
            f"<tr><td><code>{_esc(e.get('id', ''))}</code></td>"
            f"<td>{_esc(e.get('title', ''))}</td>"
            f"<td>{int(e.get('receipts', 0) or 0)}</td>"
            f"<td>{methods}</td></tr>")
    doc += ["</table>"]
    return doc


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
    doc: List[str] = [
        "<h2>Assurance matrix (NIAP-style subset)</h2>",
        f"<p><small>{_esc(niap.get('note', ''))} &mdash; "
        "pass means the mapped checks ran and produced no finding; "
        "it is exactly as strong as those checks.</small></p>",
        "<table><tr><th>ID</th><th>Requirement</th><th>Status</th>"
        "<th>Detail</th></tr>",
    ]
    for r in rows:
        status = _esc(r.get("status", ""))
        doc.append(
            f"<tr><td><code>{_esc(r.get('identifier', ''))}</code></td>"
            f"<td>{_esc(r.get('requirement', ''))}</td>"
            f"<td>{status}</td>"
            f"<td>{_esc(r.get('detail', ''))}</td></tr>")
    doc += ["</table>"]
    return doc


def _callsite_receipts_section(result: Any) -> List[str]:
    """Callsite receipts: the decompiled-code view (URL -> method -> callee)."""
    meta = getattr(getattr(result, "target", None), "meta", None) or {}
    receipts = list(meta.get("callsites") or [])
    if not receipts:
        return []
    shown = receipts[:60]
    doc: List[str] = [
        "<h2>Network callsite receipts</h2>",
        f"<p><small>{len(receipts)} receipt(s) - the exact string constant "
        "paired with the method that passed it to the consuming callee "
        "(the decompiled-code equivalent, without a bundled "
        "decompiler). Evidence pointers: linear decode, so control-flow "
        "merges are not tracked.</small></p>",
        "<table><tr><th>DEX</th><th>Method</th><th>URL</th><th>Callee</th>"
        "<th>Offset</th></tr>",
    ]
    for r in shown:
        doc.append(
            f"<tr><td><code>{_esc(r.get('dex', ''))}</code></td>"
            f"<td><code>{_esc(r.get('method', ''))}</code></td>"
            f"<td><code>{_esc(r.get('url', ''))}</code></td>"
            f"<td><code>{_esc(r.get('callee', ''))}</code></td>"
            f"<td>{_esc(r.get('offset', ''))}</td></tr>")
    doc += ["</table>"]
    if len(receipts) > len(shown):
        doc += [f"<p><small>... {len(receipts) - len(shown)} more in "
                f"report.json (inventory.callsites).</small></p>"]
    return doc


def render_html(result: Any) -> str:
    """Render a self-contained, XSS-safe HTML report."""
    findings_list = findings(result)
    tool = dict(getattr(result, "tool", None) or {"name": "masanalyzer", "version": ""})
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # assemble titled sections; every one that produced content gets a
    # card + a sticky-nav anchor
    header = _results_header(result)
    summary = _summary_table(findings_list) if findings_list else []
    detail: List[str] = ["<h2>Detailed findings</h2>"]
    if not findings_list:
        detail += ["<p>No findings &mdash; nothing to report.</p>"]
    else:
        for i, f in enumerate(findings_list, 1):
            detail += _finding_card(f, i)
    sections = [
        ("overview", "Overview", _overview_section(result)),
        ("behaviour", "Behaviour", _behaviour_section(result)),
        ("callsites", "Callsites", _callsite_receipts_section(result)),
        ("assurance", "Assurance", _niap_section(result)),
        ("score", "Score", _score_section(result)),
        ("severity", "Severity", _histogram(findings_list)),
        ("surface", "Surface", _surface_section(result)),
        ("findings", "Findings", summary + detail),
    ]
    nav = "".join(
        f"<a href=\"#{sid}\">{_esc(title)}</a>"
        for sid, title, parts in sections if parts)
    doc: List[str] = [
        "<!doctype html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<title>Mobile App Security Report</title>",
        "<style>" + _CSS + "</style></head><body>",
        *header,
    ]
    if nav:
        doc += [f"<nav class=\"topnav\">{nav}</nav>"]
    for sid, _title, parts in sections:
        if parts:
            doc += [f"<section class=\"block\" id=\"{sid}\">", *parts, "</section>"]
    doc += [
        "<footer><small class=\"muted\">Generated by "
        f"{_esc(tool.get('name', 'masanalyzer'))} "
        f"v{_esc(tool.get('version', ''))} on {_esc(stamp)}.</small></footer>",
        "</body></html>",
    ]
    return "\n".join(doc)

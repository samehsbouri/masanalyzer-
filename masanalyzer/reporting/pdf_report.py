"""PDF report writer (PDF 1.4, stdlib only) — readable, colored edition.

A deterministic byte-for-byte PDF built from the base-14 fonts
(Helvetica / Bold / Oblique) with **no compression and no external
references**, so it opens anywhere and is reproducible: two scans of
the same result produce identical bytes.

Layout (this is the same fact set as the HTML/MD reports, arranged for
reading, not a text dump):

* a colored cover banner with the app label and scan identity;
* a score card (grade letter + score/100 + findings count) next to a
  **severity bar chart** (one colored bar per severity, proportional
  widths);
* an overview fact table (package, versions, signing schemes, signer
  subject, trackers — best effort, conservative);
* findings grouped by severity, worst first: each finding opens with a
  colored severity chip, a bold rule-id + title line, a wrapped
  description (capped) and the evidence pointer in oblique gray;
* a footer on every page with tool, report name and ``page N of M``.

Non-Latin-1 characters in app-controlled strings are replaced with
``?`` (the base-14 standard encoding cannot carry them); layout-breaking
characters are escaped per PDF string syntax.
"""

from __future__ import annotations

from typing import Any, List, Sequence, Tuple

PAGE_W, PAGE_H = 612, 792          # US Letter, points
MARGIN = 54
CONTENT_W = PAGE_W - 2 * MARGIN    # 504
FOOTER_Y = 36                      # footer baseline
_bottom = MARGIN + 20              # content must stay above this

#: palette (r, g, b) — fill colors used across the document
WHITE = (1.0, 1.0, 1.0)
DARK = (0.10, 0.13, 0.16)
MIDGRAY = (0.42, 0.45, 0.50)
LIGHTGRAY = (0.86, 0.88, 0.90)
ROWALT = (0.955, 0.962, 0.97)
ACCENT = (0.10, 0.36, 0.78)        # cover banner / section accents

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_COLORS = {
    "critical": (0.71, 0.11, 0.11),
    "high": (0.85, 0.24, 0.17),
    "medium": (0.89, 0.51, 0.07),
    "low": (0.81, 0.67, 0.10),
    "info": (0.45, 0.50, 0.55),
}
_SEV_RANK = {name: i for i, name in enumerate(reversed(_SEV_ORDER), 1)}
_GRADE_COLORS = {
    "A": (0.16, 0.63, 0.36), "B": (0.36, 0.68, 0.20),
    "C": (0.87, 0.72, 0.09), "D": (0.90, 0.52, 0.08),
    "E": (0.85, 0.30, 0.14), "F": (0.78, 0.16, 0.14),
}

#: approximate characters-per-line for a width at a given size
#  (Helvetica averages ~0.5 em per glyph; keep a safety margin)
_CHARS = {8: 120, 8.5: 112, 9: 104, 10: 92, 10.5: 86, 11: 82, 12: 74,
          16: 56, 22: 40, 30: 28}


def _esc(text: str) -> str:
    """Escape + transliterate one string for a PDF literal."""
    out = []
    for ch in str(text if text is not None else ""):
        if ch in "\\()":
            out.append("\\" + ch)
        elif ord(ch) < 256 and ch not in "\r\n":
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def _wrap(text: str, width: int) -> List[str]:
    """Greedy word wrap for the literal lines."""
    words = str(text or "").split()
    lines: List[str] = []
    cur = ""
    for w in words:
        cand = f"{cur} {w}".strip()
        if len(cand) <= width:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            cur = w if len(w) <= width else w[:width]
    if cur:
        lines.append(cur)
    return lines or [""]


def _col(c: Tuple[float, float, float]) -> str:
    return "%.3f %.3f %.3f rg" % c


def _sev_of(f: Any) -> str:
    return str(getattr(getattr(f, "severity", None), "value",
                       getattr(f, "severity", "info")))


def _facts(result: Any) -> List[Tuple[str, str]]:
    """Overview fact rows (conservative: only what parsed cleanly)."""
    try:
        from ..overview import build_overview

        ov = build_overview(result)
    except Exception:  # noqa: BLE001 - cosmetic
        return []
    rows: List[Tuple[str, str]] = []
    file_ = ov.get("file") or {}
    app = ov.get("app") or {}
    if file_.get("name"):
        rows.append(("File", str(file_["name"])))
    if file_.get("size") is not None:
        rows.append(("Size", f"{int(file_['size']):,} bytes"))
    if app.get("package"):
        rows.append(("Package", str(app["package"])))
    if app.get("version_name"):
        rows.append(("Version", str(app["version_name"])))
    if app.get("min_sdk"):
        rows.append(("Min SDK", str(app["min_sdk"])))
    if app.get("target_sdk"):
        rows.append(("Target SDK", str(app["target_sdk"])))
    sig = ov.get("signature") or {}
    schemes = sig.get("schemes") or {}
    present = [k for k in ("v1", "v2", "v3", "v4")
               if isinstance(schemes.get(k), dict)
               and schemes[k].get("present")]
    if present:
        rows.append(("Signing schemes", ", ".join(present)))
    certs = sig.get("certificates") or []
    if certs and certs[0].get("subject"):
        rows.append(("Signer subject", str(certs[0]["subject"])))
    trackers = ov.get("trackers") or {}
    if trackers.get("count"):
        rows.append(("Trackers",
                     f"{int(trackers['count'])} endpoints observed"))
    return rows[:10]


class _Doc:
    """A tiny flow canvas: pages of PDF ops with a moving y cursor."""

    def __init__(self) -> None:
        self.pages: List[List[str]] = []
        self.ops: List[str] = []
        self.y = PAGE_H - MARGIN
        self._new_page()

    def _new_page(self) -> None:
        self.ops = []
        self.pages.append(self.ops)
        self.y = PAGE_H - MARGIN

    def need(self, h: float) -> None:
        if self.y - h < _bottom:
            self._new_page()

    def rect(self, x: float, y: float, w: float, h: float,
             color: Tuple[float, float, float]) -> None:
        self.ops.append(f"{_col(color)} {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def text_at(self, x: float, y: float, size: float, txt: str,
                font: str = "F1",
                color: Tuple[float, float, float] = DARK) -> None:
        self.ops.append(
            f"BT /{font} {size} Tf {_col(color)} {x:.1f} {y:.1f} Td "
            f"({_esc(txt)}) Tj ET")

    def line(self, txt: str, size: float, font: str = "F1",
             color: Tuple[float, float, float] = DARK, gap: float = 3.0,
             x: float = MARGIN, wrap: bool = True) -> None:
        """Flow one (possibly wrapped) paragraph at the cursor."""
        parts = _wrap(txt, _CHARS.get(int(size), 100)) if wrap else [txt]
        for part in parts:
            self.need(size + gap)
            self.text_at(x, self.y - size, size, part, font, color)
            self.y -= size + gap

    def gap(self, h: float) -> None:
        self.y -= h


def _cover(doc: _Doc, result: Any) -> None:
    findings = list(getattr(result, "findings", None) or [])
    target = getattr(result, "target", None)
    tool = dict(getattr(result, "tool", None) or {"name": "masanalyzer"})
    label = (getattr(target, "package", "") or getattr(target, "name", "")
             or getattr(target, "input_path", "") or "unknown input")

    # banner ------------------------------------------------------------
    top = PAGE_H - MARGIN
    doc.rect(MARGIN, top - 66, CONTENT_W, 66, ACCENT)
    doc.text_at(MARGIN + 16, top - 34, 21,
                "Mobile App Security Report", font="F2", color=WHITE)
    doc.text_at(MARGIN + 16, top - 54, 9.5,
                f"{tool.get('name', 'masanalyzer')} v{tool.get('version', '?')}"
                f"  |  {label}", color=WHITE)
    doc.gap(66 + 20)

    # score card ---------------------------------------------------------
    score = getattr(result, "score", None)
    grade = str(getattr(score, "grade", "") or "") if score else ""
    total = getattr(score, "total", None) if score else None
    sev_counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = _sev_of(f)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if grade:
        box_h = 92
        doc.rect(MARGIN, doc.y - box_h, 150, box_h, LIGHTGRAY)
        gcol = _GRADE_COLORS.get(grade, MIDGRAY)
        doc.text_at(MARGIN + 18, doc.y - 62, 46, grade, font="F2", color=gcol)
        if total is not None:
            doc.text_at(MARGIN + 78, doc.y - 30, 12,
                        f"{round(float(total), 2)} / 100", font="F2")
        doc.text_at(MARGIN + 78, doc.y - 48, 9, "risk score", color=MIDGRAY)
        doc.text_at(MARGIN + 78, doc.y - 72, 10,
                    f"{len(findings)} findings", font="F2")

        # severity bar chart, right of the score card ---------------------
        bx = MARGIN + 170
        doc.text_at(bx, doc.y - 12, 10.5, "Severity breakdown",
                    font="F2", color=DARK)
        by = doc.y - 30
        maxc = max(sev_counts.values()) or 1
        for sev in _SEV_ORDER:
            c = sev_counts[sev]
            doc.text_at(bx, by, 8.5, sev.upper(), font="F2",
                        color=_SEV_COLORS[sev])
            w = 210.0 * (c / maxc)
            if w > 0.5:
                doc.rect(bx + 66, by - 1.5, w, 10.5, _SEV_COLORS[sev])
            doc.text_at(bx + 66 + 210 + 10, by, 8.5, str(c),
                        color=MIDGRAY)
            by -= 14.5
        doc.gap(box_h - 12 + 14)

    # scan meta ----------------------------------------------------------
    dur = round(float(getattr(result, "duration_s", 0.0) or 0.0), 2)
    doc.line(
        f"Scan: {getattr(result, 'finished', '')}   |   "
        f"analyzers run: {int(getattr(result, 'analyzers_run', 0) or 0)}"
        f"   |   failed: {len(getattr(result, 'analyzers_failed', None) or [])}"
        f"   |   duration: {dur}s   |   platform: "
        f"{getattr(target, 'platform', '')}", 8.5, color=MIDGRAY)
    doc.gap(6)

    # overview fact table -------------------------------------------------
    facts = _facts(result)
    if facts:
        doc.text_at(MARGIN, doc.y - 12, 12, "Overview", font="F2", color=ACCENT)
        doc.gap(22)
        row_h = 15.0
        for i, (k, v) in enumerate(facts):
            doc.need(row_h)
            if i % 2 == 0:
                doc.rect(MARGIN, doc.y - row_h + 3, CONTENT_W, row_h, ROWALT)
            doc.text_at(MARGIN + 5, doc.y - 8, 9, k, font="F2")
            for j, part in enumerate(_wrap(v, 64)[:1]):
                doc.text_at(MARGIN + 165, doc.y - 8, 9, part)
            doc.y -= row_h
        doc.gap(10)


def _findings(doc: _Doc, result: Any) -> None:
    findings = list(getattr(result, "findings", None) or [])
    # worst severity first, stable within a severity
    findings.sort(key=lambda f: -_SEV_RANK.get(_sev_of(f), 0))

    doc.need(30)
    doc.text_at(MARGIN, doc.y - 13, 13,
                f"Findings ({len(findings)})", font="F2", color=DARK)
    doc.rect(MARGIN, doc.y - 18, CONTENT_W, 1.1, LIGHTGRAY)
    doc.gap(26)

    if not findings:
        doc.line("No findings - nothing to report.", 10)
        return

    current_sev: str = ""
    for f in findings:
        sev = _sev_of(f)
        if sev != current_sev:
            current_sev = sev
            color = _SEV_COLORS.get(sev, MIDGRAY)
            n = sum(1 for g in findings if _sev_of(g) == sev)
            doc.need(40)
            doc.text_at(MARGIN, doc.y - 11, 11,
                        f"{sev.upper()}  -  {n} finding"
                        f"{'s' if n != 1 else ''}", font="F2", color=color)
            doc.gap(20)

        rule_id = str(getattr(f, "rule_id", "") or "")
        title = str(getattr(f, "title", "") or "")
        description = str(getattr(f, "description", "") or "")
        where = str(getattr(f, "file", "") or "")
        symbol = str(getattr(f, "symbol", "") or "")

        block = 18 + 16 * min(len(_wrap(description, 96)), 4) + 14
        doc.need(min(block, 200))

        # severity chip
        chip_w = 8 * len(sev) + 14
        doc.rect(MARGIN, doc.y - 13, chip_w, 13.5, _SEV_COLORS.get(sev, MIDGRAY))
        doc.text_at(MARGIN + 7, doc.y - 9.5, 8, sev.upper(), font="F2",
                    color=WHITE)
        doc.text_at(MARGIN + chip_w + 8, doc.y - 9.5, 9.5, rule_id,
                    font="F2", color=DARK)
        doc.gap(18)

        doc.line(title, 10.5, font="F2", color=DARK, gap=2.5)
        if description:
            for part in _wrap(description, 96)[:4]:
                doc.line(part, 9, color=(0.28, 0.30, 0.33), gap=2)
        if where:
            ev = f"evidence: {where}"
            if symbol:
                ev += f"   ({symbol})"
            doc.line(ev, 8.5, font="F3", color=MIDGRAY, gap=2)
        doc.gap(9)


def render_pdf(result: Any) -> bytes:
    """Render a deterministic PDF 1.4 document (bytes)."""
    doc = _Doc()
    _cover(doc, result)
    _findings(doc, result)

    # footers (second pass: needs the final page count) --------------------
    tool = dict(getattr(result, "tool", None) or {"name": "masanalyzer"})
    total_pages = len(doc.pages)
    for i, ops in enumerate(doc.pages, 1):
        ops.append(
            f"BT /F1 8 Tf {_col(MIDGRAY)} {MARGIN} {FOOTER_Y} Td "
            f"(masanalyzer v{_esc(str(tool.get('version', '?')))}  -  "
            f"Mobile App Security Report  -  page {i} of {total_pages}) "
            f"Tj ET")

    # object numbering: 1 catalog, 2 pages, 3-5 fonts, then page/stream pairs
    n_fonts = 3
    page_ids = [4 + n_fonts + 2 * i for i in range(total_pages)]
    stream_ids = [5 + n_fonts + 2 * i for i in range(total_pages)]

    buf = bytearray()
    offsets: List[Tuple[int, int]] = []

    def obj(num: int, body: bytes) -> None:
        offsets.append((num, len(buf)))
        buf.extend(f"{num} 0 obj\n".encode("ascii"))
        buf.extend(body)
        buf.extend(b"\nendobj\n")

    buf.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    obj(2, f"<< /Type /Pages /Count {total_pages} /Kids [{kids}] >>"
        .encode("ascii"))
    for num, name in zip((3, 4, 5), ("Helvetica", "Helvetica-Bold",
                                     "Helvetica-Oblique")):
        obj(num, f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} "
                 f"/Encoding /WinAnsiEncoding >>".encode("ascii"))

    for pid, sid, ops in zip(page_ids, stream_ids, doc.pages):
        content = "\n".join(ops).encode("latin-1", "replace")
        obj(pid, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} "
                 f"{PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R "
                 f"/F3 5 0 R >> >> /Contents {sid} 0 R >>".encode("ascii"))
        obj(sid, f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
            + content + b"\nendstream")

    xref_pos = len(buf)
    n_objs = 3 + n_fonts + 2 * total_pages + 1
    xref = [f"xref\n0 {n_objs}\n", "0000000000 65535 f \n"]
    by_num = {num: off for num, off in offsets}
    for num in range(1, n_objs):
        off = by_num.get(num, 0)
        xref.append(f"{off:010d} 00000 n \n")
    buf.extend("".join(xref).encode("ascii"))
    buf.extend(
        f"trailer\n<< /Size {n_objs} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii"))
    return bytes(buf)

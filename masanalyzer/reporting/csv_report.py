"""Comma-separated findings export - spreadsheet triage for clients.

One row per finding, stable column order, RFC-4180 quoting via the stdlib
``csv`` module; secrets arriving in ``snippet``/``note``/``symbol`` are
already redacted upstream by :class:`masanalyzer.model.Evidence`.
"""

from __future__ import annotations

import csv
import io
from typing import Any, List

COLUMNS = [
    "severity",
    "risk_score",
    "rule_id",
    "title",
    "owasp",
    "category",
    "platform",
    "confidence",
    "assurance",
    "cvss",
    "cwe",
    "file",
    "line",
    "evidence",
    "note",
    "remediation",
]


def render_csv(result: Any) -> str:
    """Render all findings as CSV text (header row first)."""
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    rows = [f.to_dict() for f in (getattr(result, "findings", None) or [])]
    for d in rows:
        ev = d.get("evidence") if isinstance(d.get("evidence"), dict) else {}
        writer.writerow([
            d.get("severity", ""),
            d.get("risk_score", ""),
            d.get("rule_id", ""),
            d.get("title", ""),
            d.get("owasp", ""),
            d.get("category", ""),
            d.get("platform", ""),
            d.get("confidence", ""),
            d.get("assurance", ""),
            d.get("cvss", ""),
            d.get("cwe", ""),
            ev.get("file", ""),
            ev.get("line", ""),
            ev.get("snippet") or ev.get("symbol") or "",
            ev.get("note", ""),
            d.get("remediation", ""),
        ])
    return buf.getvalue()

"""Reporting layer: turn a :class:`masanalyzer.scanner.ScanResult` into a
rendered report.

Public API::

    from masanalyzer.reporting import render

    md   = render(result, "md")       # or "markdown"
    html = render(result, "html")     # "htm" also accepted
    j    = render(result, "json")
    s    = render(result, "sarif")

All renderers rely on duck typing only (``result.target``, ``result.score``,
``Finding.to_dict``), so importing this package never pulls in
``masanalyzer.analysis``.

Formats can be case-insensitive; every alias of ``FORMATS`` entries is
accepted, anything else raises ``ValueError`` listing the valid names.
"""

from __future__ import annotations

from typing import Any

from .score import ComplianceScore, CategoryScore, compute_score, score_to_grade
from .html_report import render_html
from .json_report import render_json
from .md_report import render_markdown
from .sarif import render_sarif
from .sbom import render_sbom
from .csv_report import render_csv
from .junit_report import render_junit
from .gitlab_report import render_gitlab
from ..masvs import render_audit
from .pdf_report import render_pdf

FORMATS = ["json", "md", "html", "pdf", "sarif", "sbom", "audit", "csv", "junit", "gitlab"]

__all__ = [
    "FORMATS",
    "render",
    "render_json",
    "render_markdown",
    "render_html",
    "render_sarif",
    "render_sbom",
    "render_audit",
    "render_csv",
    "render_junit",
    "render_gitlab",
    "render_pdf",
    "ComplianceScore",
    "CategoryScore",
    "compute_score",
    "score_to_grade",
]

#: alias -> canonical FORMATS entry
_ALIASES = {
    "json": "json",
    "md": "md",
    "markdown": "md",
    "mdown": "md",
    "mkd": "md",
    "html": "html",
    "htm": "html",
    "sarif": "sarif",
    "sbom": "sbom",
    "cdx": "sbom",
    "cyclonedx": "sbom",
    "audit": "audit",
    "masvs": "audit",
    "matrix": "audit",
    "csv": "csv",
    "junit": "junit",
    "xunit": "junit",
    "gitlab": "gitlab",
    "codequality": "gitlab",
    "cq": "gitlab",
    "pdf": "pdf",
}

_RENDERERS = {
    "json": render_json,
    "md": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
    "sbom": render_sbom,
    "audit": render_audit,
    "csv": render_csv,
    "junit": render_junit,
    "gitlab": render_gitlab,
    "pdf": render_pdf,
}


def render(result: Any, fmt: str) -> Any:
    """Dispatch one scan result to the renderer for ``fmt`` (any alias).

    Every renderer returns ``str`` except ``pdf``, which returns the
    raw deterministic ``bytes`` (PDF is not utf-8 text; writers encode
    str results and write bytes results as-is).
    """
    key = _ALIASES.get(str(fmt or "").strip().lower())
    if key is None:
        valid = ", ".join(FORMATS)
        raise ValueError(f"unknown format: {fmt!r} (valid formats: {valid})")
    return _RENDERERS[key](result)

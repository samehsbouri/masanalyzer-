"""Shared helpers for the OWASP analyzer modules (m01..m10).

Keeps every analyzer small: rule construction with consistent metadata,
comment-aware source iteration, string-pool iteration and redaction of any
captured secret material.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Tuple

from ..model import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    ScanFile,
    Severity,
    Target,
    clean_snippet,
    redact,
)
from ..owasp import category_name

OWASP_URL = "https://owasp.org/www-project-mobile-top-10/"

#: prefixes identifying whole-line comments in the languages we scan
_COMMENT_PREFIXES = ("//", "/*", "*", "#", "<!--", "-->")


def make_rule(
    rule_id: str,
    owasp: str,
    title: str,
    description: str,
    severity: Severity,
    remediation: str,
    *,
    cwe: Optional[str] = None,
    cvss: Optional[float] = None,
    confidence: Confidence = Confidence.MEDIUM,
    platform: str = "any",
    extra_refs: Optional[List[str]] = None,
) -> Rule:
    """Build a :class:`Rule` with consistent OWASP/CWE metadata."""
    refs = [OWASP_URL]
    if cwe and str(cwe).upper().startswith("CWE-"):
        refs.append(
            "https://cwe.mitre.org/data/definitions/%s.html" % str(cwe).split("-", 1)[1]
        )
    if extra_refs:
        refs.extend(extra_refs)
    return Rule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        owasp=owasp,
        category=category_name(owasp),
        remediation=remediation,
        cwe=cwe,
        cvss=cvss,
        confidence=confidence,
        platform=platform,
        references=refs,
    )


def code_files(target: Target) -> List[ScanFile]:
    """Source and smali files of the target."""
    return [f for f in target.files if f.kind in ("code", "smali")]


def code_lines(
    target: Target, kinds: Tuple[str, ...] = ("code", "smali")
) -> Iterator[Tuple[ScanFile, int, str]]:
    """Yield ``(file, lineno, text)`` for source lines, skipping comments."""
    for sf in target.files:
        if sf.kind not in kinds:
            continue
        for lineno, text in sf.lines():
            stripped = text.strip()
            if not stripped or stripped.startswith(_COMMENT_PREFIXES):
                continue
            yield sf, lineno, text


def text_scan(
    target: Target, kinds: Tuple[str, ...] = ("code", "resource", "plist")
) -> Iterator[Tuple[ScanFile, int, str]]:
    """Yield lines of text-ish files (code, xml resources, plists)."""
    for sf in target.files:
        if sf.kind not in kinds:
            continue
        for lineno, text in sf.lines():
            stripped = text.strip()
            if not stripped or stripped.startswith(("//", "/*", "*", "<!--")):
                continue
            yield sf, lineno, text


def matches_in_text(sf: ScanFile, rx: re.Pattern) -> Iterator[Tuple[int, str]]:
    """Run a (possibly multi-line) regex over a text file, report per hit."""
    text = sf.read_text()
    if not text:
        return
    all_lines = text.splitlines()
    for m in rx.finditer(text):
        line_number = text[: m.start()].count("\n") + 1
        if 1 <= line_number <= len(all_lines):
            yield line_number, all_lines[line_number - 1]


def ev(sf: ScanFile, lineno: Optional[int], text: str, note: str = "") -> Evidence:
    return Evidence(file=sf.relpath, line=lineno, snippet=clean_snippet(text), note=note)


def ev_at(sf: ScanFile, lineno: int, all_text: str, note: str = "") -> Evidence:
    """Evidence built from a line of an already-read text blob."""
    try:
        line = all_text.splitlines()[lineno - 1]
    except IndexError:  # pragma: no cover - defensive
        line = ""
    return ev(sf, lineno, line, note)


def ev_pool(relpath: str, value: str, note: str = "") -> Evidence:
    """Evidence for a hit inside the binary string pool (value is redacted)."""
    shown = value if len(value) <= 80 else value[: 77] + "..."
    return Evidence(file=relpath, symbol=shown, note=note)


def secret_poc(value: str) -> str:
    """Redacted summary of a captured secret for the poc field."""
    return "matched value (redacted): %s" % redact(value)


def iter_pool(
    target: Target,
    min_len: int = 6,
    ban: Tuple[str, ...] = (),
) -> Iterator[Tuple[str, str]]:
    """Iterate the target's string pool, dropping trivially benign strings."""
    banned = (
        "http://schemas.android.com",
        "http://www.w3.org",
        "https://www.w3.org",
        "http://xml.apache.org",
        "http://ns.adobe.com",
        "http://www.apple.com",
        "http://schemas.microsoft.com",
        "apache.org/license",
        "software-license-agreement",
        "gnu general public license",
    ) + tuple(ban)
    for rel, value in target.string_pool:
        v = (value or "").strip()
        if len(v) < min_len:
            continue
        low = v.lower()
        if any(b in low for b in banned):
            continue
        yield rel, v


def is_code_relpath(rel: str) -> bool:
    """Prefer credential-looking strings coming from compiled code assets."""
    low = rel.lower()
    return low.endswith((".dex", ".so")) or "/lib/" in low


def version_tuple(version: str) -> Tuple[int, ...]:
    """Numeric projection of a dotted version string for comparisons."""
    parts: List[int] = []
    for chunk in re.split(r"[._\-+]", (version or "").strip()):
        if chunk.isdigit():
            parts.append(int(chunk))
        elif chunk:
            digits = re.match(r"(\d+)", chunk)
            if digits:
                parts.append(int(digits.group(1)))
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    """True when version ``a`` is strictly older than ``b``."""
    ta, tb = version_tuple(a), version_tuple(b)
    if not ta or not tb:
        return False
    size = max(len(ta), len(tb))
    ta += (0,) * (size - len(ta))
    tb += (0,) * (size - len(tb))
    return ta < tb

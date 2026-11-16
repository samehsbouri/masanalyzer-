"""A light intra-procedural taint-tracking pass for M4 (and friends).

Design goals: stdlib-only, per-file, lexical, no dataflow engine.  Each
source file is scanned top-to-bottom; a small set of *source* calls capture
attacker-controlled values into locals, and a set of *sink* call sites is
checked against the currently tainted names.  Propagation covers plain
copies and string concatenation, catching the classic mobile shapes:

    String q   = intent.getStringExtra("q");              <- source capture
    String sql = "SELECT * FROM t WHERE a = '" + q + "'";  <- propagation
    db.execSQL(sql);                                       <- SINK (flagged)

Scope is deliberately narrow (name-based, file-local, statement-level) so
the pass is never significantly slower than the same-statement regexes it
extends.  It exists to (a) catch flows the concatenate-on-one-line patterns
cannot express and (b) record which variable taints the sink in the note.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..model import ScanFile

# --- sources ---------------------------------------------------------------
# calls whose return value is attacker-influenced (deep-link data, IPC
# payloads, external storage, streams)
_SOURCE_ALTS = (
    "getStringExtra", "getIntExtra", "getBooleanExtra",
    "getSerializableExtra", "getParcelableExtra", "getExtras",
    "getData", "getQueryParameter", "getParameters", "getArguments",
    "getIntent\\s*\\(\\s*\\)", "getDataString",
    "openInputStream", "readLine",
    "getExternalStorageDirectory", "getExternalFilesDir",
    "getPrimaryClip", "getInputStream",
)
_RX_SOURCE_CALL = re.compile(
    "(?:" + "|".join(_SOURCE_ALTS) + r")\s*\(", re.I
)

# --- sinks: (callee pattern, human label) -----------------------------------
_SINKS: Tuple[Tuple[re.Pattern, str], ...] = (
    (
        re.compile(r"(?:\.\s*)?(execSQL|rawQuery|insert|update|delete|query)\s*\(", re.I),
        "SQL database sink",
    ),
    (
        re.compile(
            r"(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\(",
            re.I,
        ),
        "command-execution sink",
    ),
    (
        re.compile(r"(?:openFileOutput\s*\(|new\s+FileOutputStream\s*\(|new\s+File\s*\()", re.I),
        "file-write sink",
    ),
    (
        re.compile(r"(?:\.\s*)?loadUrl\s*\(", re.I),
        "WebView navigation sink",
    ),
    (
        re.compile(r"(?:\.\s*)?(startActivity|startService|sendBroadcast)\s*\(", re.I),
        "component-launch sink",
    ),
    (
        re.compile(r"(?:\.\s*)?openOrCreateDatabase\s*\(", re.I),
        "database-creation sink",
    ),
)

# Re-validating calls that break taint reachability in the statement.
_RX_CLEANSER = re.compile(
    r"(?:\.\s*(?:equals|matches|isDigitsOnly)\s*\(|Pattern\s*\.\s*compile|"
    r"Integer\.(?:parseInt|valueOf))",
    re.I,
)

_RX_ASSIGNMENT = re.compile(r"(?:^|[^=!<>])\b([A-Za-z_][A-Za-z0-9_]{0,40})\s*=\s*([^;]+);")
_RX_DECL_SOURCE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]{0,40})\s*=\s*[^;]*?\b(?:" + "|".join(_SOURCE_ALTS) + r")\s*\("
)

_COMMENT_PREFIXES = ("//", "*", "#", "/*")


@dataclass
class TaintFlow:
    """One attacker-data-to-sink reachability result."""

    lineno: int                       # 1-based line of the sink
    line: str                         # the sink line
    sink: str                         # human label of the sink family
    tainted: List[str]                # tainted names visible on the sink line
    source_line: Optional[int] = None  # capture point of the first taint


def _word(pattern_name: str) -> str:
    return r"\b" + re.escape(pattern_name) + r"\b"


def taint_flows(sf: ScanFile) -> List[TaintFlow]:
    """Scan one code file and return tainted-argument sink reaches."""
    captured: dict = {}   # name -> line it became tainted
    origin: dict = {}     # name -> original source capture line
    flows: List[TaintFlow] = []
    for lineno, line in sf.lines():
        stripped = line.strip()
        if stripped.startswith(_COMMENT_PREFIXES):
            continue

        # -- 1. flag sinks reached by already-tainted names -----------------
        active_sinks = [
            (label, rx.search(line) is not None) for rx, label in _SINKS
        ]
        flagged_labels = {label for label, hit in active_sinks if hit}
        if flagged_labels:
            on_line = [n for n in captured if re.search(_word(n), line)]
            if on_line and not _RX_CLEANSER.search(line):
                first = min(on_line)
                for label in sorted(flagged_labels):
                    flows.append(
                        TaintFlow(
                            lineno=lineno,
                            line=stripped[:300],
                            sink=label,
                            tainted=sorted(on_line),
                            source_line=origin.get(first, captured.get(first)),
                        )
                    )

        # -- 2. capture a source into a local --------------------------------
        m = _RX_DECL_SOURCE.search(line)
        if m:
            captured[m.group(1)] = lineno
            origin[m.group(1)] = lineno
            continue

        # -- 3. propagate through copy / concatenation -----------------------
        m = _RX_ASSIGNMENT.search(line)
        if m:
            target, rhs = m.group(1), m.group(2)
            hits = [n for n in captured if re.search(_word(n), rhs)]
            if hits and not _RX_CLEANSER.search(rhs):
                captured[target] = lineno
                origin[target] = origin.get(hits[0], lineno)

    return flows


def describe(flow: TaintFlow) -> str:
    """Human provenance for the finding note field."""
    src = f"; source captured near line {flow.source_line}" if flow.source_line else ""
    return f"{flow.sink}; tainted: {', '.join(flow.tainted)}{src}"

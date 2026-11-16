"""M4 - Insufficient Input/Output Validation.

Regex-driven detection of the classic untrusted-input-into-sink shapes in
source code: SQL string concatenation, Runtime.exec/ProcessBuilder with
concatenated commands, file paths built from deep-link/intent data and
WebView navigation to unvalidated URLs.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, make_rule
from .taint import describe, taint_flows

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
INFO = Severity.INFO

R_SQL_CONCAT = make_rule(
    "MAS-INPUT-001",
    "M4",
    "SQL query built via string concatenation",
    "A query statement is concatenated with a variable instead of a bound "
    "parameter ('?', ?). Any untrusted value reaching this expression becomes "
    "a SQL injection primitive.",
    HIGH,
    "Use parameterised queries (SQLiteDatabase with ? placeholders, "
    "preparedStatement) or an ORM-level escape.",
    cwe="CWE-89",
    confidence=Confidence.HIGH,
    cvss=8.6,
)

R_CMD_CONCAT = make_rule(
    "MAS-INPUT-002",
    "M4",
    "Command execution with concatenated input",
    "Runtime.exec / ProcessBuilder is invoked on a string that concatenates "
    "user-controlled values; shell metacharacters then become injectable.",
    HIGH,
    "Pass an explicit argument array to execProcess and never route through a "
    "shell string; validate/allow-list arguments.",
    cwe="CWE-78",
    confidence=Confidence.HIGH,
    cvss=8.4,
)

R_FILE_FROM_UNTRUSTED = make_rule(
    "MAS-INPUT-003",
    "M4",
    "File path derived from unvalidated input",
    "A file-writing/file-open call uses an external or intent-sourced value "
    "in the path, allowing path traversal ('../') into arbitrary app data.",
    HIGH,
    "Canonicalise and validate the final path, restrict writes to the "
    "app-private directory (getExternalFilesDir with explicit names).",
    cwe="CWE-22",
    confidence=Confidence.MEDIUM,
    cvss=7.0,
)

R_WEBVIEW_UNVALIDATED_URL = make_rule(
    "MAS-INPUT-004",
    "M4",
    "WebView navigation to unvalidated URL",
    "loadUrl/evaluateJavascript receives a value that is not from a fixed "
    "allow-list; combined intent.getData() the caller can navigate the "
    "WebView anywhere.",
    MEDIUM,
    "Validate deep-link URLs against an allow-list before navigation.",
    cwe="CWE-80",
    confidence=Confidence.MEDIUM,
    cvss=6.0,
)

R_QUERY_SEGMENT = make_rule(
    "MAS-INPUT-005",
    "M4",
    "URI query parameter concatenated into SQL",
    "Uri.getQueryParameter is concatenated/string-built into an SQL "
    "expression - a cross-component SQL injection channel.",
    HIGH,
    "Bind query parameters before executing SQL; refuse unexpected "
    "identifiers.",
    cwe="CWE-89",
    confidence=Confidence.MEDIUM,
    cvss=8.0,
)

R_INSECURE_DESER = make_rule(
    "MAS-INPUT-007",
    "M4",
    "Polymorphic deserialization of untrusted data enabled",
    "ObjectMapper.enableDefaultTyping()/activateDefaultTyping() embeds "
    "class names in the payload and instantiates whatever type the data "
    "names - untrusted input then becomes arbitrary code execution "
    "(CWE-502 gadget chains).",
    HIGH,
    "Disable default typing; deserialize into concrete DTO types (or "
    "apply a StrictTypingSolver allow-list).",
    cwe="CWE-502",
    confidence=Confidence.HIGH,
    cvss=8.1,
)

R_LOCAL_SERVER_SOCKET = make_rule(
    "MAS-INPUT-008",
    "M4",
    "LocalServerSocket without authentication",
    "A LocalServerSocket listens on a local abstract-namespace UNIX socket "
    "with no built-in authentication: any app on the device can connect "
    "and issue commands unless a handshake is enforced.",
    MEDIUM,
    "Require an app-private permission or cryptographic handshake before "
    "honoring commands received on the socket.",
    cwe="CWE-306",
    confidence=Confidence.MEDIUM,
    cvss=6.5,
)

R_TAINT_SINK = make_rule(
    "MAS-INPUT-006",
    "M4",
    "User-controlled data reaches a sensitive sink (taint flow)",
    "A value captured from an untrusted source (intent extra, deep-link "
    "content, external storage, stream) flows through local variables into "
    "a sensitive call site (database, command, file, WebView, component "
    "launch) without validation on the path.",
    HIGH,
    "Validate/allow-list the value at the boundary, then pass a "
    "parameterised/escaped form to the sink; never trust IPC payload "
    "content.",
    cwe="CWE-20",
    confidence=Confidence.MEDIUM,
    cvss=7.5,
)


_RX_SQL_CONCAT = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE)[^\n;]*[\"\']\s*\+",
    re.I,
)
_RX_CMD = re.compile(
    r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(\s*[^\n]*\+"
)
_RX_QUERY_PARAM_SQL = re.compile(
    r"getQueryParameter\s*\([^)]*\)[^\n]{0,80}"
    r"(?:SELECT|sql|query|rawQuery|execSQL)",
    re.I,
)
_RX_WEBVIEW_LOADURL = re.compile(
    r"loadUrl\s*\(\s*[a-zA-Z_][\w.]+(?:\.[a-zA-Z_][\w]*\( *\))*\s*\)"
)
_RX_FILE_UNTRUSTED = re.compile(
    r"new\s+File\s*\([^)]*?(?:getData\(\)|getIntent\(\)|getExternalStorage"
    r"|getStringExtra|getParcelable|getQueryParameter)[^)]*?\)",
    re.I,
)
_RX_DESER = re.compile(
    r"\.enableDefaultTyping\s*\(\s*\)|\.activateDefaultTyping\s*\("
)
_RX_LOCAL_SOCKET = re.compile(r"(?<![\w.])LocalServerSocket\s*\(")


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []
    jackson_files: set = set()

    for sf, lineno, text in code_lines(target, kinds=("code", "smali")):
        if "jackson" in text.lower() or "ObjectMapper" in text:
            jackson_files.add(sf.relpath)
        if _RX_SQL_CONCAT.search(text):
            out.append(
                R_SQL_CONCAT.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_CMD.search(text):
            out.append(
                R_CMD_CONCAT.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_QUERY_PARAM_SQL.search(text):
            out.append(
                R_QUERY_SEGMENT.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_WEBVIEW_LOADURL.search(text):
            out.append(
                R_WEBVIEW_UNVALIDATED_URL.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_FILE_UNTRUSTED.search(text):
            out.append(
                R_FILE_FROM_UNTRUSTED.finding(
                    file=sf.relpath, line=lineno, snippet=sf.line_at(lineno) or text
                )
            )
        if _RX_DESER.search(text):
            out.append(
                R_INSECURE_DESER.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                    note="default typing enabled on an ObjectMapper"
                    if sf.relpath in jackson_files or "ObjectMapper" in text
                    else "default typing call; confirm the mapper only "
                         "handles trusted payloads",
                )
            )
        if _RX_LOCAL_SOCKET.search(text):
            out.append(
                R_LOCAL_SERVER_SOCKET.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                    note="abstract-namespace server socket",
                )
            )

    # --- taint pass: flows that same-statement regexes cannot express -------
    reported: set = set()
    for sf in target.code_files():
        for flow in taint_flows(sf):
            key = (sf.relpath, flow.lineno)
            if key in reported:
                continue
            reported.add(key)
            f = R_TAINT_SINK.finding(
                file=sf.relpath,
                line=flow.lineno,
                snippet=sf.line_at(flow.lineno) or flow.line,
            )
            f.poc = ""
            note = describe(flow)
            f.evidence.note = note[:300]
            out.append(f)
    return out

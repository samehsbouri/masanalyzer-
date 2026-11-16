"""Core data model shared by every extractor, analyzer and reporter.

The whole tool is built around three objects:

``ScanFile``   - one physical file recovered from the application package
``Target``     - the application under analysis (APK, IPA or unpacked directory)
``Finding``    - a single security observation produced by an analyzer

Keeping these types tiny and dependency free makes the analyzer modules easy
to test: an analyzer is just ``def analyze(target: Target) -> list[Finding]``.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence


# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------
class Severity(str, enum.Enum):
    """Severity of a finding.

    ``str`` mixin keeps JSON serialisation trivial.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


#: Ordering used for sorting (higher == worse).
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Points subtracted from the compliance score per finding.
SEVERITY_WEIGHT: Dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.5,
    Severity.MEDIUM: 4.0,
    Severity.HIGH: 9.0,
    Severity.CRITICAL: 16.0,
}

ALL_SEVERITIES: Sequence[Severity] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def parse_severity(value: str) -> Severity:
    """Parse a severity from user input, tolerant of prefixes and case."""
    raw = (value or "").strip().lower()
    if not raw:
        return Severity.INFO
    for sev in Severity:
        if sev.value.startswith(raw[0]) and raw in (sev.value, sev.value[0]):
            return sev
    for sev in Severity:
        if sev.value == raw:
            return sev
    raise ValueError(f"unknown severity: {value!r}")


class Confidence(str, enum.Enum):
    """How sure the analyzer is that the finding is a true positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


CONFIDENCE_WEIGHT: Dict[Confidence, float] = {
    Confidence.LOW: 0.4,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}


# --------------------------------------------------------------------------
# Location / evidence
# --------------------------------------------------------------------------
@dataclass
class Evidence:
    """Where the issue was observed."""

    file: Optional[str] = None          # path relative to the unpacked app
    line: Optional[int] = None          # 1-based, for source-like files
    snippet: Optional[str] = None       # redacted, single-ish line of context
    symbol: Optional[str] = None        # class/method/symbol for decompiled output
    offset: Optional[int] = None        # byte offset for binaries
    note: Optional[str] = None          # free-form clarifier

    @property
    def location(self) -> str:
        """Human readable ``file:line`` locator."""
        if not self.file:
            return self.symbol or "<unknown>"
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file and self.offset is not None:
            return f"{self.file}+0x{self.offset:x}"
        return self.file

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------
@dataclass
class Finding:
    """One security observation."""

    rule_id: str                      # e.g. "MAS-CRYPTO-001"
    title: str
    description: str
    severity: Severity
    owasp: str                        # "M9" (OWASP Mobile Top 10 2024 id)
    category: str                     # human readable OWASP category
    platform: str = "any"             # android | ios | native | any
    evidence: Evidence = field(default_factory=Evidence)
    remediation: str = ""
    poc: str = ""                     # proof of concept / exploitation notes
    cwe: Optional[str] = None         # "CWE-798"
    cvss: Optional[float] = None      # indicative CVSS v3.1 base score
    confidence: Confidence = Confidence.MEDIUM
    legacy_owasp: Optional[str] = None  # 2016 list id, e.g. "M2"
    assurance: str = ""                # verified | structural | heuristic
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # -- identity ---------------------------------------------------------
    @property
    def identity(self) -> str:
        """Stable identity used for de-duplication."""
        ev = self.evidence
        parts = [
            self.rule_id,
            ev.file or "",
            str(ev.line or ev.offset or ""),
            (ev.snippet or ev.symbol or "")[:120],
        ]
        return hashlib.sha1("|".join(parts).encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def risk_score(self) -> float:
        """severity x confidence, used for ranking inside the report."""
        return round(
            SEVERITY_WEIGHT[self.severity] * CONFIDENCE_WEIGHT[self.confidence], 2
        )

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.identity,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "owasp": self.owasp,
            "category": self.category,
            "legacy_owasp": self.legacy_owasp,
            "platform": self.platform,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "confidence": self.confidence.value,
            "assurance": self.assurance,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "poc": self.poc,
            "tags": list(self.tags),
            "references": list(self.references),
        }
        return {k: v for k, v in data.items() if v not in (None, [], "")}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class Rule:
    """Declarative metadata for a pattern based rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    owasp: str
    category: str
    remediation: str
    poc: str = ""
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    confidence: Confidence = Confidence.MEDIUM
    platform: str = "any"
    legacy_owasp: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def finding(self, **evidence_kw: Any) -> Finding:
        """Build a :class:`Finding` bound to this rule."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            owasp=self.owasp,
            category=self.category,
            platform=self.platform,
            remediation=self.remediation,
            poc=self.poc,
            cwe=self.cwe,
            cvss=self.cvss,
            confidence=self.confidence,
            legacy_owasp=self.legacy_owasp,
            tags=list(self.tags),
            references=list(self.references),
            evidence=Evidence(**evidence_kw),
        )


class FindingCollector:
    """Collects findings while dropping duplicates."""

    def __init__(self) -> None:
        self._items: List[Finding] = []
        self._seen: set[str] = set()

    def add(self, finding: Optional[Finding]) -> Optional[Finding]:
        if finding is None:
            return None
        ident = finding.identity
        if ident in self._seen:
            return None
        self._seen.add(ident)
        self._items.append(finding)
        return finding

    def extend(self, findings: Iterable[Optional[Finding]]) -> None:
        for f in findings:
            self.add(f)

    @property
    def findings(self) -> List[Finding]:
        return list(self._items)

    def sorted(self) -> List[Finding]:
        return sorted(
            self._items,
            key=lambda f: (-SEVERITY_RANK[f.severity], -f.risk_score, f.rule_id),
        )

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._items)


# --------------------------------------------------------------------------
# Files and target
# --------------------------------------------------------------------------
TEXT_SUFFIXES = {
    ".java", ".kt", ".smali", ".xml", ".json", ".txt", ".yml", ".yaml",
    ".properties", ".gradle", ".plist", ".h", ".m", ".mm", ".swift", ".c",
    ".cpp", ".hpp", ".cs", ".js", ".html", ".md", ".sh", ".ini", ".cfg",
    ".conf", ".pem", ".key", ".sql",
}

CODE_SUFFIXES = {".java", ".kt", ".smali", ".m", ".mm", ".swift", ".c", ".cpp", ".h", ".hpp", ".cs", ".js"}


@dataclass
class ScanFile:
    """A file extracted from the application bundle."""

    path: str                     # absolute path on disk (inside the work dir)
    relpath: str                  # path relative to the bundle root
    size: int = 0
    kind: str = "other"           # code|smali|manifest|plist|resource|binary|native|other
    sha256: str = ""

    @property
    def name(self) -> str:
        return os.path.basename(self.relpath)

    @property
    def suffix(self) -> str:
        return os.path.splitext(self.relpath)[1].lower()

    @property
    def is_text(self) -> bool:
        if self.kind in ("code", "smali", "manifest", "plist", "resource"):
            return True
        return self.suffix in TEXT_SUFFIXES

    @property
    def language(self) -> str:
        return {
            ".java": "java",
            ".kt": "kotlin",
            ".smali": "smali",
            ".xml": "xml",
            ".plist": "plist",
            ".swift": "swift",
            ".m": "objc",
            ".mm": "objc",
            ".h": "objc",
            ".json": "json",
        }.get(self.suffix, "")

    def lines(self, limit: int = 0) -> Iterator[tuple[int, str]]:
        """Yield ``(lineno, text)`` pairs, skipping binary garbage."""
        if not self.is_text:
            return
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if limit and i > limit:
                        break
                    yield i, line.rstrip("\n\r")
        except OSError:
            return

    def read_text(self) -> str:
        if not self.is_text:
            return ""
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def line_at(self, lineno: int) -> Optional[str]:
        for i, line in self.lines():
            if i == lineno:
                return line
        return None


@dataclass
class NativeLib:
    """A native library shipped inside the bundle (.so / Mach-O)."""

    relpath: str
    path: str
    size: int = 0
    arch: str = ""
    platform: str = "android"
    symbols: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    #: DT_NEEDED entries parsed from the ELF dynamic table (android .so)
    dependencies: List[str] = field(default_factory=list)
    #: dangerous import names found in the ELF body (dlopen, mprotect, ...)
    dangerous: List[str] = field(default_factory=list)
    flags: Dict[str, bool] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class Target:
    """Everything the analyzers need to know about the app under test."""

    input_path: str
    platform: str                       # android | ios | dir
    work_dir: str
    name: str = ""
    package: str = ""
    version: str = ""
    files: List[ScanFile] = field(default_factory=list)
    native_libs: List[NativeLib] = field(default_factory=list)
    manifest: Optional[Any] = None      # android Manifest model
    plist: Dict[str, Any] = field(default_factory=dict)
    #: every printable string harvested from binaries/dex, tied to its origin
    string_pool: List[tuple[str, str]] = field(default_factory=list)
    #: opaque bag for platform specific extras (plist raw, code objects, ...)
    meta: Dict[str, Any] = field(default_factory=dict)

    # -- selectors --------------------------------------------------------
    def by_kind(self, *kinds: str) -> List[ScanFile]:
        return [f for f in self.files if f.kind in kinds]

    def code_files(self) -> List[ScanFile]:
        return [f for f in self.files if f.kind in ("code", "smali")]

    def find(self, pattern: str) -> List[ScanFile]:
        rx = re.compile(pattern, re.I)
        return [f for f in self.files if rx.search(f.relpath)]

    def get(self, relpath: str) -> Optional[ScanFile]:
        for f in self.files:
            if f.relpath.replace("\\", "/").lower() == relpath.replace("\\", "/").lower():
                return f
        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "platform": self.platform,
            "package": self.package,
            "version": self.version,
            "files": len(self.files),
            "native_libraries": len(self.native_libs),
            "input": self.input_path,
        }


def redact(secret: str, keep: int = 4) -> str:
    """Mask a secret value for safe display in reports."""
    secret = (secret or "").strip()
    if len(secret) <= keep:
        return "*" * len(secret)
    return secret[:keep] + "*" * min(len(secret) - keep, 12)


def clean_snippet(line: str, max_len: int = 300) -> str:
    """Collapse whitespace and truncate a source line for report display."""
    line = re.sub(r"\s+", " ", (line or "").strip())
    if len(line) > max_len:
        line = line[: max_len - 3] + "..."
    return line

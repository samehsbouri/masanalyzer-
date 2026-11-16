"""Scan configuration: per-run policy loaded from a JSON file.

A config file lets a team pin policy without touching code::

    {
      "exclude_rules":    ["MAS-NET-004"],
      "exclude_paths":    ["^test/", "\\.md$"],
      "rule_severity":    {"MAS-MIS-006": "INFO"},
      "min_severity":     "medium"
    }

* ``exclude_rules``   - rule ids to drop entirely.
* ``exclude_paths``   - regexes; a finding whose evidence file matches is
  dropped (matched with ``re.search`` on the forward-slash relpath).
* ``rule_severity``   - per-rule severity overrides (case-insensitive).
* ``min_severity``    - default floor; the CLI ``--min-severity`` flag wins
  when both are given.

Unknown keys are ignored, so configs stay forward compatible.  Everything is
best-effort: a broken config file disables itself with a warning instead of
aborting the scan.
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional

from .model import ALL_SEVERITIES, Finding, Severity, parse_severity

CONFIG_KEYS = {
    "exclude_rules",
    "exclude_paths",
    "rule_severity",
    "min_severity",
}


class ScanConfig:
    """Immutable-per-scan policy applied right after the analyzers run."""

    __slots__ = ("exclude_rules", "exclude_paths", "rule_severity",
                 "min_severity", "source")

    def __init__(
        self,
        exclude_rules: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        rule_severity: Optional[Dict[str, str]] = None,
        min_severity: Optional[str] = None,
        source: str = "",
    ) -> None:
        self.exclude_rules: List[str] = [r.upper() for r in (exclude_rules or [])]
        self.exclude_paths: List[re.Pattern] = [
            re.compile(p) for p in (exclude_paths or [])
        ]
        self.rule_severity: Dict[str, Severity] = {
            rid.upper(): parse_severity(str(sev))
            for rid, sev in (rule_severity or {}).items()
        }
        self.min_severity: Optional[Severity] = (
            parse_severity(min_severity) if min_severity else None
        )
        self.source = source

    # -- loading -----------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str]) -> "ScanConfig":
        """Load ``path``; returns an inert config when omitted/unreadable."""
        if not path:
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("config root must be a JSON object")
            unknown = set(data) - CONFIG_KEYS
            if unknown:
                print(
                    f"warning: ignoring unknown config keys: {', '.join(sorted(unknown))}",
                    file=sys.stderr,
                )
            return cls(
                exclude_rules=[str(r) for r in data.get("exclude_rules", [])],
                exclude_paths=[str(p) for p in data.get("exclude_paths", [])],
                rule_severity={str(k): str(v) for k, v in (data.get("rule_severity") or {}).items()},
                min_severity=data.get("min_severity"),
                source=path,
            )
        except (OSError, ValueError) as exc:
            print(f"warning: config {path} ignored ({exc})", file=sys.stderr)
            return cls()

    # -- application ---------------------------------------------------------
    def applies(self, finding: Finding) -> bool:
        """True when ``finding`` survives the exclusion filters."""
        rid = (finding.rule_id or "").upper()
        if rid in self.exclude_rules:
            return False
        file = finding.evidence.file or ""
        norm = file.replace("\\", "/")
        pattern = any(rx.search(norm) for rx in self.exclude_paths)
        return not pattern

    def reseverity(self, finding: Finding) -> None:
        """Apply per-rule severity override in-place."""
        rid = (finding.rule_id or "").upper()
        if rid in self.rule_severity:
            finding.severity = self.rule_severity[rid]

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"ScanConfig(source={self.source!r}, exclude_rules={self.exclude_rules}, "
            f"exclude_paths={[rx.pattern for rx in self.exclude_paths]}, "
            f"rule_severity={ {r: s.value for r, s in self.rule_severity.items()} }, "
            f"min_severity={self.min_severity.value if self.min_severity else None})"
        )

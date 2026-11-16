"""Baseline: store known findings, suppress them on later scans.

A baseline is a JSON file listing the stable ``Finding.identity`` hashes of
accepted/known issues::

    {"version": 1,
     "tool": "masanalyzer",
     "created": "2026-11-08T...",
     "identities": ["a1b2c3d4e5f60718", ...]}

Workflow:

1. First triage pass:  ``masanalyzer app.apk -o out --update-baseline base.json``
2. Every later scan:   ``masanalyzer app.apk -o out --baseline base.json``
   -> everything already accepted is suppressed; only *new* work shows up.

Identities are content-derived (rule + file + line + snippet), so a baseline
stays valid as long as the offending code does not change.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Iterable, List, Optional

BASELINE_VERSION = 1


class Baseline:
    """A set of accepted finding identities."""

    __slots__ = ("identities", "path")

    def __init__(self, identities: Iterable[str] = (), path: str = "") -> None:
        self.identities: set = set(identities)
        self.path = path

    # -- load --------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str]) -> "Baseline":
        if not path:
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("baseline root must be a JSON object")
            ids = data.get("identities", [])
            if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids):
                raise ValueError("identities must be a list of strings")
            return cls(ids, path=str(path))
        except (OSError, ValueError) as exc:
            print(f"warning: baseline {path} ignored ({exc})", file=sys.stderr)
            return cls()

    # -- queries -----------------------------------------------------------
    def suppresses(self, finding) -> bool:
        return getattr(finding, "identity", "") in self.identities

    def filter(self, findings: List) -> List:
        return [f for f in findings if not self.suppresses(f)]

    # -- write ---------------------------------------------------------------
    def dump(self, findings: Iterable) -> str:
        """Serialise the given findings into a baseline document string."""
        payload = {
            "version": BASELINE_VERSION,
            "tool": "masanalyzer",
            "identities": sorted({f.identity for f in findings}),
        }
        return json.dumps(payload, indent=2) + "\n"

    def is_empty(self) -> bool:
        return not self.identities

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.identities)

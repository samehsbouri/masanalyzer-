"""GitLab Code Quality report - merge-request security annotations.

Emits the ``codequality`` artifact schema GitLab consumers expect::

    [
      {
        "description": "...",
        "check_name": "MAS-NET-005",
        "fingerprint": "a1b2..",            # deterministic sha256
        "severity": "major",
        "location": {"path": "classes.dex", "lines": {"begin": 42}}
      }
    ]

Severity mapping (GitLab has no direct medium/high bands):

* ``info`` -> info, ``low`` -> minor, ``medium`` -> major,
* ``high`` -> critical, ``critical`` -> blocker.

The fingerprint is deterministic (sha256 over rule id + location + evidence
stem), so repeated scans annotate the same MR diff comments instead of
spamming new ones. Stdlib only, duck-typed, no analysis imports.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

_SEVERITY_MAP = {
    "info": "info",
    "low": "minor",
    "medium": "major",
    "high": "critical",
    "critical": "blocker",
}

#: findings at/above this GitLab band are worth an MR comment
MAX_ISSUES = 2000


def render_gitlab(result: Any) -> str:
    """Render one scan result as a GitLab Code Quality JSON array."""
    issues: List[Dict[str, Any]] = []
    findings = list(getattr(result, "findings", None) or [])
    for f in findings[:MAX_ISSUES]:
        d = f.to_dict()
        ev = d.get("evidence") if isinstance(d.get("evidence"), dict) else {}
        path = str(ev.get("file", "") or "") or "."
        line = ev.get("line")
        remediation = str(d.get("remediation", "") or "")
        description = f"[{d.get('owasp', '')}] {d.get('title', '')}".strip()
        if remediation:
            description += f" - {remediation}"
        # MR annotations truncate hard; keep the message bounded
        description = description[:500]
        issues.append(
            {
                "description": description,
                "check_name": str(d.get("rule_id", "?")),
                "fingerprint": _fingerprint(d, path, line),
                "severity": _SEVERITY_MAP.get(
                    str(d.get("severity", "info")), "unknown"
                ),
                "location": {
                    "path": path,
                    "lines": {"begin": int(line) if line else 1},
                },
            }
        )
    return json.dumps(issues, indent=1, sort_keys=True) + "\n"


def _fingerprint(d: Dict[str, Any], path: str, line: Any) -> str:
    evidence = d.get("evidence") if isinstance(d.get("evidence"), dict) else {}
    stem = "|".join(
        (
            str(d.get("rule_id", "?")),
            path,
            str(line or evidence.get("offset") or ""),
            (str(evidence.get("snippet") or evidence.get("symbol") or ""))[:120],
        )
    )
    return hashlib.sha256(stem.encode("utf-8", "replace")).hexdigest()

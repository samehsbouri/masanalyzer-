"""Report-to-report diffing for release gates.

Compares two ``report.json`` documents (same or different builds) and prints
what changed::

    NEW       findings present now but not in the baseline build
    RESOLVED  findings removed since the baseline build
    CHANGED   same rule location, different finding
    SCORE     total / grade movement

Exit code is ``0`` when nothing worse appeared, ``1`` when new findings at or
above ``--fail-on`` (default ``high``) exist, ``2`` on usage errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

SEV_ORDER = ["info", "low", "medium", "high", "critical"]

_RISK = {s: i for i, s in enumerate(SEV_ORDER)}


def _key(f: Dict[str, Any]) -> str:
    return str(f.get("id") or f.get("identity") or "")


def _rule_loc(f: Dict[str, Any]) -> Tuple[str, str]:
    ev = f.get("evidence") or {}
    loc = ev.get("line") is not None and f"{ev.get('file')}:{ev.get('line')}" or str(ev.get("file") or "")
    return str(f.get("rule_id")), loc


def _as_report(doc: Any) -> Dict[str, Any]:
    """Tolerate raw findings lists and full report documents."""
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        return doc
    if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "rule_id" in doc[0]:
        return {"findings": doc}
    raise ValueError("not a masanalyzer report document")


def load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return _as_report(json.load(fh))


def diff_reports(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the change set between two report documents."""
    old_by_id = {_key(f): f for f in old.get("findings", [])}
    new_by_id = {_key(f): f for f in new.get("findings", [])}

    added = [f for fid, f in new_by_id.items() if fid not in old_by_id]
    resolved = [f for fid, f in old_by_id.items() if fid not in new_by_id]
    kept = [f for fid, f in new_by_id.items() if fid in old_by_id]

    def _max_sev(findings: List[Dict[str, Any]]) -> str:
        present = [str(f.get("severity", "info")).lower() for f in findings]
        best = "info"
        for s in present:
            if _RISK.get(s, -1) > _RISK.get(best, -1):
                best = s
        return best

    old_score = None
    new_score = None
    if isinstance(old.get("score"), dict):
        old_score = old["score"].get("total")
    if isinstance(new.get("score"), dict):
        new_score = new["score"].get("total")

    return {
        "added": added,
        "resolved": resolved,
        "kept": len(kept),
        "added_max_severity": _max_sev(added),
        "resolved_max_severity": _max_sev(resolved),
        "old_total": old_score,
        "new_total": new_score,
        "old_count": len(old.get("findings", [])),
        "new_count": len(new.get("findings", [])),
    }


def _fmt_finding(f: Dict[str, Any]) -> str:
    rule, loc = _rule_loc(f)
    return f"    [{str(f.get('severity', '?')):>8}] {f.get('owasp', '')} {rule}  ({loc})"


def fail_on_rank(value: str) -> int:
    return _RISK.get(str(value).lower(), _RISK["high"])


def print_diff(diff: Dict[str, Any], fail_on: str = "high") -> int:
    rank_limit = fail_on_rank(fail_on)
    added = diff["added"]
    resolved = diff["resolved"]

    print(f"findings : {diff['old_count']} -> {diff['new_count']} "
          f"({len(added)} new, {len(resolved)} resolved, {diff['kept']} unchanged)")
    if diff["old_total"] is not None and diff["new_total"] is not None:
        arrow = "+" if diff["new_total"] >= diff["old_total"] else ""
        print(f"score    : {diff['old_total']} -> {diff['new_total']} ({arrow}{round(diff['new_total'] - diff['old_total'], 1)})")

    if added:
        print("\nNEW:")
        for f in added:
            print(_fmt_finding(f))
    if resolved:
        print("\nRESOLVED:")
        for f in resolved:
            print(_fmt_finding(f))

    blocking = [f for f in added if _RISK.get(str(f.get("severity", "")).lower(), 0) >= rank_limit]
    if blocking:
        print(
            f"\nresult: BLOCKED - {len(blocking)} new finding(s) at or above"
            f" '{fail_on}'",
            file=sys.stderr,
        )
        return 1
    print("\nresult: PASS - no new findings at or above "
          f"'{fail_on}'")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="masanalyzer-diff",
        description="Diff two masanalyzer report.json documents.",
    )
    p.add_argument("old", help="reference report.json (previous build)")
    p.add_argument("new", help="candidate report.json (new build)")
    p.add_argument(
        "--fail-on",
        default="high",
        choices=SEV_ORDER,
        help="severity at-or-above which NEW findings make this fail "
        "(default: high)",
    )
    args = p.parse_args(argv)

    try:
        old = load_report(args.old)
        new = load_report(args.new)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return print_diff(diff_reports(old, new), fail_on=args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

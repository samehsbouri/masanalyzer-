"""Analyzer registry: runs every OWASP Mobile Top 10 2024 analyzer.

``run_analyzers`` is the single entry point invoked by
:mod:`masanalyzer.scanner`:

>>> covered, failures, count = run_analyzers(target, collector)

* ``covered``: OWASP 2024 category ids ("M1".."M10") that had at least one
  analyzer executed, so scoring only judges assessed categories.
* ``failures``: list of ``"<module>:<error>"`` strings for analyzers that
  raised an unexpected exception.
* ``count``: how many analyzers ran.

An analyzer is any function ``analyze(target) -> Iterable[Finding]``; each
must import its own rules and never raise on malformed input (a finding
collection must be best effort).
"""

from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Tuple

from ..model import FindingCollector, Target
from ..owasp import ORDER

from . import m01, m02, m03, m04, m05, m06, m07, m08, m09, m10

#: OWASP id -> analyzer callable
ANALYZERS: List[Tuple[str, Callable]] = [
    ("M1", m01.analyze),
    ("M2", m02.analyze),
    ("M3", m03.analyze),
    ("M4", m04.analyze),
    ("M5", m05.analyze),
    ("M6", m06.analyze),
    ("M7", m07.analyze),
    ("M8", m08.analyze),
    ("M9", m09.analyze),
    ("M10", m10.analyze),
]


def get_analyzers(
    platform: Optional[str] = None,
) -> List[Tuple[str, Callable]]:
    """Analyzers relevant for ``platform`` (all, in OWASP order)."""
    return list(ANALYZERS)


def run_analyzers(target: Target, collector: FindingCollector):
    """Run every analyzer, feed the collector, report per-category coverage."""
    covered: List[str] = []
    failures: List[str] = []
    ran = 0
    for owasp_id, analyze in ANALYZERS:
        try:
            findings = list(analyze(target) or [])
        except Exception as exc:                      # noqa: BLE001 - scan must go on
            failures.append(f"M{owasp_id}:{type(exc).__name__}: {exc}")
            continue
        ran += 1
        if owasp_id not in covered:
            covered.append(owasp_id)
        collector.extend(findings)
    covered = [cid for cid in ORDER if cid in covered]
    return covered, failures, ran


def rule_catalog() -> List["Rule"]:
    """Every declared :class:`model.Rule`, in OWASP / id order.

    Includes rules from any *loaded* user rule packs (see
    :mod:`masanalyzer.rulepack`); built-ins are always ordered first so the
    catalog is stable for a given pack set.
    """
    from ..model import Rule
    from ..rulepack import rule_catalog_extra

    modules = [m01, m02, m03, m04, m05, m06, m07, m08, m09, m10]
    rules: List[Rule] = []
    seen = set()
    for mod in modules:
        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, Rule) and obj.rule_id not in seen:
                seen.add(obj.rule_id)
                rules.append(obj)
    for obj in rule_catalog_extra():
        if obj.rule_id not in seen:
            seen.add(obj.rule_id)
            rules.append(obj)
    # dynamic-session rules (masanalyzer.runtime) are declared beside their
    # collectors, so they are listed explicitly rather than discovered here
    try:
        from ..runtime import RULES as _DYN_RULES

        for obj in _DYN_RULES:
            if obj.rule_id not in seen:
                seen.add(obj.rule_id)
                rules.append(obj)
    except Exception:  # noqa: BLE001 - catalog must never break on import
        pass
    rules.sort(key=lambda r: (r.owasp, r.rule_id))
    return rules

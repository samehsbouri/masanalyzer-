"""Compliance scoring.

The score is a 0-100 number derived from the OWASP Mobile Top 10 2024
findings of a scan.  Every finding subtracts a severity-weighted number of
points *from its category only* (capped at 100 within the category), and the
overall score is the average across all **in-scope** categories.

A category is *in scope* for a platform scan when at least one analyzer ran
for it (every category is in scope except when the platform simply has no
data - e.g. ``M9`` storage rules that only apply to Android).  In practice:
in-scope = categories covered by the rule set + categories with findings;
categories never assessed by the analyzer set are excluded so an app can
still score 100 without "perfect" storage rules that never ran.

Grades:  >= 97 A+ | >= 90 A | >= 80 B | >= 68 C | >= 55 D | else F.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..model import SEVERITY_WEIGHT, Finding, Severity
from ..owasp import CATEGORIES, ORDER


@dataclass
class CategoryScore:
    """Score card for one OWASP category."""

    id: str
    name: str
    short: str = ""
    summary: str = ""
    legacy: Optional[str] = None
    in_scope: bool = True
    findings: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    deduction: float = 0.0
    score: float = 100.0

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "legacy": self.legacy,
            "in_scope": self.in_scope,
            "findings": self.findings,
            "by_severity": {k: v for k, v in self.by_severity.items() if v},
            "deduction": round(self.deduction, 1),
            "score": round(self.score, 1),
            "grade": self.grade,
        }


@dataclass
class ComplianceScore:
    """The result of scoring one scan."""

    total: float = 100.0
    grade: str = "A+"
    scope: int = 10                     # number of in-scope categories
    findings: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_owasp: Dict[str, CategoryScore] = field(default_factory=dict)
    counts: Dict[str, int] = field(default_factory=dict)

    def category(self, owasp_id: str) -> Optional[CategoryScore]:
        return self.by_owasp.get(owasp_id.upper())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": round(self.total, 1),
            "grade": self.grade,
            "categories": [self.by_owasp[cid].to_dict() for cid in ORDER if cid in self.by_owasp],
            "by_severity": {k: v for k, v in self.by_severity.items() if v},
            "findings": self.findings,
            "counts": dict(self.counts),
        }


GRADE_BANDS: Sequence[tuple] = (
    (97.0, "A+"),
    (90.0, "A"),
    (80.0, "B"),
    (68.0, "C"),
    (55.0, "D"),
)


def score_to_grade(score: float) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def compute_score(
    findings: Iterable[Finding],
    covered_categories: Optional[List[str]] = None,
) -> ComplianceScore:
    """Score findings per OWASP Mobile Top 10 2024 category.

    ``covered_categories`` lists categories that had at least one configured
    analyzer (even if it fired nothing) - only these count towards the total.
    When omitted, every category with findings plus all categories counts.
    """
    cats: Dict[str, CategoryScore] = {}
    for cid in ORDER:
        meta = CATEGORIES[cid]
        cats[cid] = CategoryScore(
            id=cid,
            name=meta.name,
            short=meta.short,
            summary=meta.summary,
            legacy=meta.legacy,
        )

    findings = list(findings)
    for f in findings:
        card = cats.get((f.owasp or "").upper())
        if card is None:
            continue
        card.findings += 1
        sev = f.severity if isinstance(f.severity, Severity) else Severity(str(f.severity).lower() if str(f.severity).lower() in Severity._value2member_map_ else Severity.INFO)
        card.by_severity[sev.value] = card.by_severity.get(sev.value, 0) + 1
        card.deduction += SEVERITY_WEIGHT[sev]

    if covered_categories is None:
        in_scope = [cid for cid in ORDER if cats[cid].findings > 0] or list(ORDER)
    else:
        covered = {c.upper() for c in covered_categories}
        # categories that actually have findings are always in scope
        in_scope = [cid for cid in ORDER if cid in covered or cats[cid].findings > 0]

    for cid in ORDER:
        card = cats[cid]
        card.in_scope = cid in in_scope
        if card.in_scope:
            card.score = max(0.0, 100.0 - min(card.deduction, 100.0))
        else:
            card.score = float("nan")
            card.findings = card.findings

    scope = len(in_scope)
    total = sum(cats[cid].score for cid in in_scope) / max(scope, 1)

    total_sev: Dict[str, int] = {}
    for f in findings:
        total_sev[f.severity.value] = total_sev.get(f.severity.value, 0) + 1

    counts = {
        "rules_hit": len({f.rule_id for f in findings}),
        "files_with_findings": len({f.evidence.file for f in findings if f.evidence.file}),
        "in_scope_categories": scope,
    }

    return ComplianceScore(
        total=total,
        grade=score_to_grade(total),
        scope=scope,
        findings=len(findings),
        by_severity=total_sev,
        by_owasp=cats,
        counts=counts,
    )

"""Scanner orchestration: input -> Target -> findings -> ScanResult.

This is the highest level pure-API entry point (the CLI is a thin wrapper):

>>> result = masanalyzer.scanner.scan("InsecureBank.apk")
>>> result.score.grade
'C'
"""

from __future__ import annotations

import json
import os
import platform as _pyplatform
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .analysis import run_analyzers
from .model import (
    ALL_SEVERITIES,
    SEVERITY_RANK,
    Finding,
    FindingCollector,
    Target,
)
from .packaging import prepare_target
from .reporting.score import ComplianceScore, compute_score

TOOL_NAME = "masanalyzer"
TOOL_VERSION = "1.1.0"
TOOL_URI = "https://github.com/samehsbouri/masanalyzer-"

#: OWASP categories with at least one analyzer that ran (filled per platform
#: by the analysis registry).
_SHOW_MAX_FINDINGS = 50


@dataclass
class ScanResult:
    """Everything known about one scan, ready for the reporters."""

    target: Target
    findings: List[Finding] = field(default_factory=list)
    score: Optional[ComplianceScore] = None
    started: str = ""
    finished: str = ""
    duration_s: float = 0.0
    analyzers_run: int = 0
    analyzers_failed: List[str] = field(default_factory=list)
    covered_categories: List[str] = field(default_factory=list)
    tool: Dict[str, str] = field(default_factory=lambda: {"name": TOOL_NAME, "version": TOOL_VERSION})

    # -- convenience ------------------------------------------------------
    @property
    def platform(self) -> str:
        return self.target.platform

    def findings_by_severity(self):
        out = {}
        for f in self.findings:
            out.setdefault(f.severity.value, []).append(f)
        return out

    def summary(self) -> Dict[str, Any]:
        sev = {s.value: 0 for s in ALL_SEVERITIES}
        for f in self.findings:
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
        return {
            "tool": dict(self.tool),
            "platform": self.platform,
            "app": self.target.summary(),
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": round(self.duration_s, 2),
            "files_scanned": len(self.target.files),
            "native_libraries": len(self.target.native_libs),
            "analyzers_run": self.analyzers_run,
            "findings": len(self.findings),
            "by_severity": sev,
            "score": (self.score.to_dict() if self.score else None),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.summary(),
            "target": self.target.meta.get("manifest_path") or self.target.input_path,
            "analyzers_failed": list(self.analyzers_failed),
            "covered_categories": list(self.covered_categories),
            "findings_list": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)


@dataclass
class ScanProgress:
    """Tiny callback structure so CLIs can show progress."""

    phase: str = ""
    detail: str = ""


ProgressFn = Callable[[ScanProgress], None]


def scan(
    input_path: str,
    work_root: Optional[str] = None,
    minimum_severity: Optional[str] = None,
    progress: Optional[ProgressFn] = None,
    keep_work_dir: bool = False,
    rule_packs: Optional[List[Any]] = None,
    intel: Optional[Any] = None,
    osv_cache: Optional[Any] = None,
    refresh_intel: bool = True,
) -> ScanResult:
    """Run a full static analysis of ``input_path`` (APK/IPA/directory).

    ``rule_packs`` accepts pre-loaded :class:`masanalyzer.rulepack.RulePack`
    objects (load with :func:`masanalyzer.rulepack.load_rule_pack`); their
    rules run after the built-ins and their findings join the same
    policy/baseline pipeline. ``intel`` accepts a
    :class:`masanalyzer.iocs.IntelBundle` (``iocs.load_intel``).
    ``osv_cache`` accepts a cache path / dict / :class:`masanalyzer.osv.OsvCache`
    (seeded ahead of time by ``masanalyzer-refresh-intel``). When
    ``refresh_intel`` is on (the default), the stale coordinates behind the
    SDKs detected in *this* bundle are re-queried against OSV.dev before
    the SCA rules run — best-effort with a short timeout: without
    connectivity the cached view is kept and every failure is counted in
    ``target.meta["intel_refresh"]``. Set ``refresh_intel=False`` (CLI
    ``--no-intel-refresh``) for a strictly cache-only scan.
    """
    started = datetime.now(timezone.utc)
    if rule_packs:
        # module-level active set: the rule catalog/list-rules/report tool
        # metadata reflect the packs that took part in this scan.
        from .rulepack import activate_packs

        activate_packs(rule_packs)

    def tell(phase: str, detail: str = "") -> None:
        if progress:
            try:
                progress(ScanProgress(phase=phase, detail=detail))
            except Exception:  # pragma: no cover - user callback may misbehave
                pass

    tell("unpack", input_path)
    target = prepare_target(input_path, work_root=work_root, keep_work_dir=keep_work_dir)
    if osv_cache is not None:
        try:
            from .osv import AUTO_REFRESH_TIMEOUT, auto_refresh, cache_from

            cache = cache_from(osv_cache)
            if cache is not None:
                target.meta["osv_intel"] = cache
                # auto-currency: re-query stale coordinates of the SDKs
                # detected in this bundle before the SCA rules run
                if refresh_intel:
                    refreshed, failed = auto_refresh(
                        cache, target.meta.get("sdks") or [],
                        timeout=AUTO_REFRESH_TIMEOUT)
                    target.meta["intel_refresh"] = {
                        "refreshed": refreshed, "failed": failed,
                    }
                    # persist the fresher view when the cache came from disk
                    if refreshed and isinstance(
                            osv_cache, (str, bytes, os.PathLike)):
                        try:
                            cache.save(os.fspath(osv_cache))
                        except OSError:
                            pass
                # deterministic provenance only (built/counts)
                fresh = cache.freshness()
                fresh.pop("stale", None)
                if fresh.get("coordinates"):
                    target.meta["intel_status"] = fresh
        except Exception:  # noqa: BLE001 - intel must never kill a scan
            pass
    tell("analyze", f"{len(target.files)} files")

    result = analyze_target(target, rule_packs=rule_packs, intel=intel)
    result.started = started.isoformat()
    now = datetime.now(timezone.utc)
    result.finished = now.isoformat()
    result.duration_s = max(0.0, now.timestamp() - started.timestamp())

    if minimum_severity:
        floor = minimum_severity.lower()
        order = {s.value: i for s, i in ((s, SEVERITY_RANK[s]) for s in ALL_SEVERITIES)}
        keep = {v: i for v, i in order.items()}
        try:
            limit = next(
                rank
                for sev, rank in sorted(keep.items(), key=lambda kv: kv[1])
                if sev.startswith(floor[0]) or sev.startswith(floor[:2])
            )
        except StopIteration:
            limit = 0
        ceiling = limit if floor in ("info",) else limit
        if floor in ("low", "medium", "high", "critical"):
            minimums = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            lo = minimums[floor]
            result.findings = [
                f for f in result.findings if SEVERITY_RANK[f.severity] >= lo
            ]
            if result.score is not None:
                result.score = compute_score(result.findings, result.covered_categories)
    return result


def analyze_target(
    target: Target,
    rule_packs: Optional[List[Any]] = None,
    intel: Optional[Any] = None,
) -> ScanResult:
    """Static internal: run all analyzers over an already prepared Target."""
    collector = FindingCollector()
    covered, failures, analytic_count = run_analyzers(target, collector)
    packs_run = 0
    for pack in rule_packs or []:
        try:
            collector.extend(pack.analyze(target) or [])
            if pack.owasp not in covered:
                covered.append(pack.owasp)
            packs_run += 1
        except Exception as exc:  # noqa: BLE001 - pack defects must not kill the scan
            failures.append(f"pack {pack.fragment}:{type(exc).__name__}: {exc}")
    if intel:
        # one bundle or several -- normalize to a list of bundles
        bundles = intel if isinstance(intel, (list, tuple)) else [intel]
        for bundle in bundles:
            if getattr(bundle, "active", False):
                try:
                    collector.extend(bundle.analyze(target) or [])
                except Exception as exc:  # noqa: BLE001 - intel is best effort
                    failures.append(f"intel:{type(exc).__name__}: {exc}")
                packs_run += 1
    analytic_count += packs_run
    try:
        from .owasp import ORDER as _ORDER

        covered = [c for c in _ORDER if c in covered] + [
            c for c in covered if c not in _ORDER
        ]
    except Exception:  # pragma: no cover - defensive
        pass
    findings = collector.sorted()
    try:
        from . import assurance

        assurance.annotate(findings)
    except Exception:  # noqa: BLE001 - cosmetic metadata must not kill a scan
        pass
    try:
        from .surface import build_surface

        surface = build_surface(target, findings)
        if surface:
            target.meta["attack_surface"] = surface
    except Exception:  # noqa: BLE001 - synthesis must not kill a scan
        pass
    score = compute_score(findings, covered)
    return ScanResult(
        target=target,
        findings=findings,
        score=score,
        analyzers_run=analytic_count,
        analyzers_failed=failures,
        covered_categories=covered,
    )


def cleanup_target(result: ScanResult, force: bool = False) -> None:
    """Remove the temporary work directory, if one was created."""
    meta = result.target.meta
    if not meta.get("container"):
        return
    work = result.target.work_dir
    if force and meta.get("keep_work_dir"):
        shutil.rmtree(work, ignore_errors=True)
        return
    if meta.get("keep_work_dir") and not force:
        return
    head = os.path.basename(work)
    if head.startswith("masan_"):
        shutil.rmtree(work, ignore_errors=True)


def interactive_enabled() -> bool:  # pragma: no cover - trivial
    return sys.stdout.isatty() and not os.environ.get("MASANALYZER_NO_COLOR")


def tool_environment() -> Dict[str, str]:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "python": _pyplatform.python_version(),
        "platform": _pyplatform.platform(),
    }

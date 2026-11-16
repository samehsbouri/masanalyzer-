"""Command line interface.

Usage::

    python -m masanalyzer InsecureBank.apk -o report --format all
    python -m masanalyzer samples/InsecureNotes --format md,sarif -o out
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from .scanner import TOOL_NAME, TOOL_VERSION, scan

_FORMAT_HELP = "comma separated: json, md, html, sarif, junit, gitlab (or 'all')"


def _report_intel_refresh(result: Any) -> None:
    """Stderr note about the automatic CVE refresh outcome."""
    try:
        meta = getattr(getattr(result, "target", None), "meta", None) or {}
        info = meta.get("intel_refresh") or {}
        failed = int(info.get("failed", 0))
        refreshed = int(info.get("refreshed", 0))
        if failed:
            print(
                f"warning: {failed} CVE coordinate(s) could not be "
                f"refreshed (offline?); cached advisories still used"
                + (f", {refreshed} refreshed" if refreshed else ""),
                file=sys.stderr,
            )
    except Exception:  # noqa: BLE001 - cosmetic
        pass


def _warn_intel_age(osv_cache: Optional[str], stream) -> None:
    """Stderr notice when the OSV cache is old or partially stale.

    Deliberately NOT part of any rendered report: reports stay
    byte-identical for the same bundle + cache; the age check depends on
    the wall clock, so it lives on operational surfaces only.
    """
    if not osv_cache:
        return
    try:
        from .osv import cache_from

        cache = cache_from(osv_cache)
        if cache is None:
            return
        fresh = cache.freshness()
        if not fresh.get("coordinates"):
            return
        age = cache.age_days()
        if age is None:
            return
        if age >= 7 or fresh.get("stale"):
            print(
                f"warning: CVE cache is {age} day(s) old "
                f"({fresh['stale']}/{fresh['coordinates']} coordinates "
                f"beyond the 24h TTL); refresh with: "
                f"masanalyzer-refresh-intel",
                file=stream,
            )
    except Exception:  # noqa: BLE001 - a stale notice must never fail a scan
        pass


def _parse_formats(value: str) -> List[str]:
    from .reporting import FORMATS

    alias = {"markdown": "md", "markdown_report": "md", "htm": "html"}
    out: List[str] = []
    for token in (value or "json").split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token == "all":
            out.extend(FORMATS)
            continue
        token = alias.get(token, token)
        if token not in FORMATS:
            raise SystemExit(
                f"unknown format {token!r}; valid: {', '.join(FORMATS)} (or 'all')"
            )
        if token not in out:
            out.append(token)
    return out or ["json"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Static security analyzer for Android and iOS application bundles "
            "(APK/IPA/unpacked trees) - pure Python, stdlib only."
        ),
        epilog=(
            "Scoring follows the OWASP Mobile Top 10 2024 categories "
            "(M1..M10). Findings are heuristic and require human triage."
        ),
    )
    p.add_argument("target", nargs="?", help="APK/IPA file or unpacked app directory")
    p.add_argument(
        "-o",
        "--output",
        default=TOOL_NAME + "-report",
        help="output base: file or directory where reports are written "
        "(default: masanalyzer-report)",
    )
    p.add_argument("--format", "-f", default="all", help=_FORMAT_HELP)
    p.add_argument(
        "--min-severity",
        "-s",
        choices=["info", "low", "medium", "high", "critical"],
        help="drop findings below this severity",
    )
    p.add_argument(
        "--config",
        metavar="FILE",
        help="JSON config: exclude_rules, exclude_paths, rule_severity, min_severity",
    )
    p.add_argument(
        "--baseline",
        metavar="FILE",
        help="suppress findings whose identity is listed in this baseline file",
    )
    p.add_argument(
        "--update-baseline",
        metavar="FILE",
        help="after the scan, write every finding to FILE as the new baseline",
    )
    p.add_argument(
        "--keep-workdir",
        action="store_true",
        help="do not delete the temporary unpacked bundle",
    )
    p.add_argument(
        "--fail-on",
        metavar="SEV",
        choices=["info", "low", "medium", "high", "critical"],
        help="exit with code 1 when at least one finding of this severity "
        "or higher survives policy (CI gate); reports are still written",
    )
    p.add_argument(
        "--intel",
        metavar="FILE",
        action="append",
        default=[],
        help="threat-intel IOC file (domains/IPv4/md5-sha1-sha256 digests, "
        "one per line, '#' comments); every hit becomes a high/critical "
        "find-tagged 'intel' finding; repeatable",
    )
    p.add_argument(
        "--rules",
        metavar="FILE",
        action="append",
        default=[],
        help="JSON rule pack with user-defined CUSTOM-* rules; repeat for "
        "several packs (see docs/rules.md#rule-packs)",
    )
    p.add_argument(
        "--osv-cache",
        metavar="FILE",
        default=None,
        help="JSON OSV-dev CVE cache (seeded by 'masanalyzer-refresh-intel'); "
        "advisory matches on detected SDK versions become MAS-SCA-003 "
        "findings. Stale coordinates are re-queried automatically at scan "
        "time (best-effort; offline machines keep their cache)",
    )
    p.add_argument(
        "--no-intel-refresh",
        action="store_true",
        help="skip the automatic OSV re-query; use the cache as-is "
        "(strictly offline / reproducible scans)",
    )
    p.add_argument(
        "--runtime",
        metavar="DIR",
        default=None,
        help="dynamic session bundle (runtime.json plus optional traffic.har "
        "and logcat.txt written by a collector); adds MAS-DYN-* findings and "
        "inventory.runtime to the report",
    )
    p.add_argument(
        "--list-rules",
        action="store_true",
        help="print the rule catalog (id, severity, title) and exit",
    )
    p.add_argument(
        "--verify-identity",
        metavar="SHA256",
        help="verify the bundle's signing certificate(s) against the given "
        "SHA-256 fingerprint ('AA:BB:..' or 'aabb..', repeats comma "
        "separated); exit 1 on mismatch — an anti-repack trust gate for CI",
    )
    p.add_argument(
        "--serve",
        action="store_true",
        help="after the scan, serve the generated reports on "
        "http://127.0.0.1:8080/ until Ctrl-C (use --serve-port to change)",
    )
    p.add_argument(
        "--serve-port",
        type=int,
        default=8080,
        help="port for --serve (default 8080)",
    )
    p.add_argument(
        "--watch",
        metavar="SECONDS",
        type=float,
        help="re-scan the target every SECONDS (min 0.5) and rewrite the "
        "reports; useful while iterating on a dev build",
    )
    q = p.add_mutually_exclusive_group()
    q.add_argument("-v", "--verbose", action="store_true", help="progress chatter")
    q.add_argument("-q", "--quiet", action="store_true", help="print nothing on success")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        if args.rules:
            from .rulepack import activate_packs, load_rule_pack

            packs = []
            for rp in args.rules:
                try:
                    packs.append(load_rule_pack(rp))
                except (OSError, ValueError) as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
            activate_packs(packs)
        return _list_rules()

    if not args.target:
        build_parser().error("the following arguments are required: target")

    formats = _parse_formats(args.format)

    target = args.target
    if not os.path.exists(target):
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return 2

    def progress(phase: str, detail: str = "") -> None:
        if args.verbose and not args.quiet:
            print(f"[{phase}] {detail}", file=sys.stderr)

    try:
        t0 = time.perf_counter()
        from .config import ScanConfig
        from .rulepack import load_rule_pack
        from .iocs import load_intel

        config = ScanConfig.load(args.config)
        bundles = []
        for path in args.intel:
            try:
                bundles.append(load_intel(path))
            except OSError as exc:
                print(f"error: intel: {exc}", file=sys.stderr)
                return 2
        packs = []
        for rp in args.rules:
            try:
                packs.append(load_rule_pack(rp))
            except (OSError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        if args.min_severity:
            eff_floor = args.min_severity
        else:
            eff_floor = config.min_severity.value if config.min_severity else None
        result = scan(
            target,
            minimum_severity=eff_floor,
            progress=lambda p: progress(p.phase, p.detail),
            keep_work_dir=args.keep_workdir,
            rule_packs=packs,
            intel=bundles or None,
            osv_cache=args.osv_cache,
            refresh_intel=not args.no_intel_refresh,
            runtime=args.runtime,
        )
        _report_intel_refresh(result)
        _warn_intel_age(args.osv_cache, sys.stderr)
        elapsed = time.perf_counter() - t0
    except FileNotFoundError:  # pragma: no cover - guarded above
        raise SystemExit(2)
    except Exception as exc:
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    result = _apply_policy(
        result, config,
        baseline_path=args.baseline,
        update_baseline_path=args.update_baseline,
    )

    for bundle in bundles or []:
        for warn in (bundle.errors or [])[:10]:
            print(f"warning: intel: {warn}", file=sys.stderr)

    written = []
    base = args.output
    os.makedirs(base, exist_ok=True) if base.endswith(("/", "\\")) or not _has_ext(
        base
    ) else None
    if os.path.isdir(base) or not _has_ext(base):
        for fmt in formats:
            path = os.path.join(base, f"report.{_ext_for(fmt)}")
            _write_report(result, fmt, path)
            written.append(path)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(base)) or ".", exist_ok=True)
        root, ext = os.path.splitext(base)
        ext = ext.lstrip(".").lower()
        if not formats:
            formats = ["json"]
        if len(formats) == 1:
            _write_report(result, formats[0], base)
            written.append(base)
        else:
            for fmt in formats:
                path = f"{root}.{_ext_for(fmt)}"
                _write_report(result, fmt, path)
                written.append(path)

    if os.environ.get("MASANALYZER_DEMO"):  # pragma: no cover - debug helper
        keep = find_work_dir(result)
        if keep:
            print(f"[workdir kept] {keep}", file=sys.stderr)

    if not args.quiet:
        print_summary(result, elapsed)
        for path in written:
            print(f"  wrote {path}")

    if args.verify_identity:
        rc = _verify_identity(result, args.verify_identity)
        if rc != 0:
            return rc

    if args.serve:
        _serve_reports_cli(args, written)
        return 0

    if args.watch:
        rc = _watch_cli(args)
        return rc or 0

    if args.fail_on:
        from .model import SEVERITY_RANK, Severity

        floor = SEVERITY_RANK[Severity(args.fail_on)]
        hits = [f for f in result.findings if SEVERITY_RANK[f.severity] >= floor]
        if hits:
            top = max(hits, key=lambda f: SEVERITY_RANK[f.severity])
            print(
                f"fail-on threshold '{args.fail_on}' exceeded "
                f"({len(hits)} findings; worst: [{top.severity.value}] "
                f"{top.rule_id})",
                file=sys.stderr,
            )
            return 1
    return 0


def _normalize_fingerprint(raw: str) -> str:
    return raw.replace(":", "").replace(" ", "").strip().lower()


def _serve_reports_cli(args, written) -> None:  # pragma: no cover - loops forever
    """Block on a local HTTP server exposing the report directory."""
    import threading

    from .watchserver import serve_reports

    # pick the directory of the first written report
    directory = os.path.dirname(os.path.abspath(written[0])) if written else "."
    print(f"serving reports from {directory} (Ctrl-C stops)", flush=True)
    server = serve_reports(
        directory, port=max(args.serve_port or 8080, 1),
        on_ready=lambda url: _safe_print(url),
    )
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        t.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        t.join(2)


def _safe_print(msg: str) -> None:  # pragma: no cover
    print(msg, flush=True)


def _watch_cli(args) -> int:  # pragma: no cover - defined main flow
    from .watchserver import watch

    out = args.output
    directory = out if os.path.isdir(out) else os.path.dirname(os.path.abspath(out))
    print(f"watching {args.target}; reports go to {directory}", flush=True)
    watch(
        args.target,
        directory,
        interval=max(args.watch or 5.0, 0.5),
        formats=["html", "json"],
    )
    return 0


def _verify_identity(result, expected: str) -> int:
    """Anti-repack gate: signing-cert fingerprints must cover ``expected``.

    Exit codes: 0 = a signer certificate matches, 1 = none matches, 2 =
    the bundle has no verifiable signing certificate.
    """
    apk = result.target.meta.get("apk")
    expected_fps = {
        _normalize_fingerprint(p) for p in expected.split(",") if p.strip()
    }
    fps = {
        _normalize_fingerprint(fp)
        for fp in getattr(apk, "signer_fingerprints", []) or []
    }
    if not fps:
        ios = result.target.platform == "ios"
        print(
            "error: --verify-identity: no signing-certificate fingerprints "
            + ("in this IPA (iOS CMS extraction is not supported yet)"
               if ios else "were recoverable from this bundle"),
            file=sys.stderr,
        )
        return 2
    matched = expected_fps & fps
    for fp in sorted(fps):
        print(f"identity {'OK' if fp in matched else 'FAIL'}: {fp}")
    if matched:
        return 0
    print(
        f"error: --verify-identity: bundle signed with an unknown "
        f"certificate ({len(fps)} found; expected "
        f"{'/'.join(sorted(expected_fps))})",
        file=sys.stderr,
    )
    return 1


def _list_rules() -> int:
    from .analysis import rule_catalog
    from .model import ALL_SEVERITIES

    print(f"{'ID':<18} {'SEV':<8} {'M#':<4} TITLE")
    for rule in rule_catalog():
        print(
            f"{rule.rule_id:<18} {rule.severity.value:<8} {rule.owasp:<4} {rule.title}"
        )
    count = len(rule_catalog())
    print(f"\n{count} rules; sevs: {', '.join(s.value for s in ALL_SEVERITIES)}")
    return 0


def _has_ext(path: str) -> bool:
    return bool(os.path.splitext(path)[1])


def _apply_policy(result, config, baseline_path: str = "", update_baseline_path: str = ""):
    """Apply config (exclusions / severity overrides) + baseline suppression.

    The score is always recomputed over the surviving findings, and
    ``--update-baseline`` is written from the *filtered* (post-exclusion)
    finding set so a regenerated baseline reflects the current policy.
    """
    from .baseline import Baseline
    from .model import SEVERITY_RANK
    from .reporting.score import compute_score

    baseline = Baseline.load(baseline_path)
    kept = []
    suppressed = 0
    for f in result.findings:
        config.reseverity(f)
        if not config.applies(f) or baseline.suppresses(f):
            suppressed += 1
            continue
        kept.append(f)
    report_findings = kept
    result.findings = kept
    result.score = compute_score(kept, result.covered_categories)

    if update_baseline_path:
        try:
            from .baseline import Baseline as _Baseline

            blob = _Baseline().dump(report_findings)
            with open(update_baseline_path, "w", encoding="utf-8") as fh:
                fh.write(blob)
            if not _quiet_console():  # pragma: no cover - cosmetic
                print(f"  baseline updated: {update_baseline_path} "
                      f"({len(report_findings)} identities)")
        except OSError as exc:
            print(f"error: cannot write baseline: {exc}", file=sys.stderr)
            raise SystemExit(1)
    return result


def _quiet_console() -> bool:  # pragma: no cover - cosmetic
    return os.environ.get("MASANALYZER_QUIET") == "1"


def _ext_for(fmt: str) -> str:
    return {
        "md": "md",
        "html": "html",
        "json": "json",
        "pdf": "pdf",
        "sarif": "sarif",
        "sbom": "cdx.json",
        "audit": "audit.md",
        "csv": "csv",
        "junit": "junit.xml",
        "gitlab": "codequality.json",
    }[fmt]


def _write_report(result, fmt: str, path: str) -> None:
    from .reporting import render

    text = render(result, fmt)
    if isinstance(text, bytes):
        with open(path, "wb") as fh:
            fh.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def find_work_dir(result):  # pragma: no cover - used by env-var debug
    return result.target.work_dir


def print_summary(result, elapsed: float) -> None:
    from .model import ALL_SEVERITIES

    target = result.target
    tsummary = target.summary()
    print(f"{TOOL_NAME} {TOOL_VERSION} - static security analysis")
    print(
        f"  platform : {target.platform}   app: {tsummary.get('name') or tsummary.get('package') or '?'}"
    )
    print(f"  files    : {tsummary.get('files', 0)} analyzed in {elapsed:.1f}s")

    if result.analyzers_failed:
        print(f"  failed   : {', '.join(result.analyzers_failed)}")

    counts = result.score.by_severity if result.score else {}
    sev_line = "  findings : "
    bits = []
    for s in ALL_SEVERITIES:
        n = counts.get(s.value, 0)
        if n:
            bits.append(f"{n} {s.value}")
    if not bits:
        print(sev_line + "none")
    elif result.score:
        sev_line += ", ".join(bits)
        print(f"{sev_line}  (score {result.score.total:.0f}/100, grade {result.score.grade})")
    else:
        print(sev_line + ", ".join(bits))

    top = result.findings[:8]
    if top:
        print("  top findings:")
        for f in top:
            where = f.evidence.location
            print(f"    [{f.severity.value:>8}] {f.owasp} {f.rule_id} - {f.title}  ({where})")
        if len(result.findings) > len(top):
            print(f"    ... and {len(result.findings) - len(top)} more in the report")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

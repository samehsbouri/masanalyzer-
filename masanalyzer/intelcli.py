"""``masanalyzer-refresh-intel`` — keep the OSV CVE cache current.

Detects the third-party SDKs inside one or more bundles (APK/IPA/tree) and
queries the keyless OSV.dev ``/v1/query`` endpoint once per known package
coordinate (Maven for Android SDKs, Swift pods for iOS SDKs), merging
trimmed advisories into a JSON cache on disk.  The
scan side (``masanalyzer ... --osv-cache PATH``) then reads the cache
read-only, so scans stay offline and deterministic while the advisory
data keeps aging forward.

Exit codes: 0 refreshed / nothing to do; 2 usage or refresh failure.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, List, Optional

from .osv import (
    OsvCache,
    TTL_SECONDS,
    cache_from,
    default_cache_path,
    osv_package,
)


def main(argv: Optional[List[str]] = None, fetch: Any = None) -> int:
    """CLI entry point.  ``fetch`` mirrors :func:`masanalyzer.osv.query_osv`
    (tests inject stubs here; production uses the real network call)."""
    parser = argparse.ArgumentParser(
        prog="masanalyzer-refresh-intel",
        description=(
            "Refresh the OSV-dev CVE cache from a bundle's detected SDKs "
            "(reads the bundle locally; only the SDK-coordinate queries "
            "touch the network)."
        ),
    )
    parser.add_argument(
        "inputs", nargs="+",
        help="APK/IPA/.aab/.apks/directory to detect SDKs in",
    )
    parser.add_argument(
        "--cache", default=None,
        help=f"cache path (default: {default_cache_path()})",
    )
    parser.add_argument(
        "--ttl", type=int, default=TTL_SECONDS,
        help="seconds a cached entry stays valid (default: 86400)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="re-query even if a fresh entry already exists",
    )
    args = parser.parse_args(argv)

    from .scanner import scan
    from .sdks import detect_sdks

    cache_path = args.cache or default_cache_path()
    cache = OsvCache()
    if os.path.exists(cache_path):
        try:
            cache = cache_from(cache_path)
        except Exception as exc:  # noqa: BLE001 - corrupt cache: start empty
            print(f"warning: cache unreadable ({exc}); starting empty",
                  file=sys.stderr)

    exit_code = 0
    for input_path in args.inputs:
        # a full scan result is reused purely for its prepared target
        result = scan(input_path)
        target = result.target
        try:
            hits = detect_sdks(target)
        except Exception as exc:  # noqa: BLE001 - best effort per input
            hits = []
            print(f"warning: {input_path}: sdk detection failed: {exc}",
                  file=sys.stderr)
        print(f"== {input_path}: {len(hits)} SDKs detected")
        refreshed = 0
        for hit in hits:
            package = osv_package(hit)
            if package is None:
                print(f"   {hit.get('id')}: no maven/pod coordinate - skipped")
                continue
            coordinate, ecosystem = package
            try:
                did = cache.refresh(
                    coordinate, fetch=fetch, ttl=args.ttl, force=args.force,
                    ecosystem=ecosystem,
                )
            except Exception as exc:  # noqa: BLE001 - network is best effort
                did = False
                exit_code = 2
                print(f"   {hit.get('id')} {coordinate}: query failed: {exc}",
                      file=sys.stderr)
            if did:
                refreshed += 1
            advisories = cache.advisories_for(coordinate)
            version = hit.get("version") or "?"
            from .osv import matches_version

            affected = [
                a for a in advisories if matches_version(a, version)
            ]
            state = "refreshed" if did else "cached"
            print(
                f"   {hit.get('id')} {coordinate} ({ecosystem}) "
                f"({version}): {state}, "
                f"{len(advisories)} advisory(ies)"
                + (f", {len(affected)} matched for this version"
                   if affected else "")
            )
            for advisory in affected[:8]:
                print(f"      {advisory.get('id')}: "
                      f"{str(advisory.get('summary'))[:100]}")
        try:
            saved = cache.save(cache_path)
        except OSError as exc:
            print(f"error: cannot write cache {cache_path}: {exc}",
                  file=sys.stderr)
            return 2
        if refreshed:
            print(f"   {refreshed} coordinate(s) refreshed; cache: {saved}")
    fresh = cache.freshness()
    print(f"cache now: {fresh['coordinates']} coordinate(s), "
          f"{fresh['advisories']} advisory(ies), newest fetch "
          f"{fresh['built'] or 'n/a'}"
          + (f", {fresh['stale']} beyond TTL" if fresh["stale"] else ""))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

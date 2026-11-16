"""Release-gate delta: compare two masanalyzer reports, gate the release.

Extends the :mod:`masanalyzer.diffcli` findings-only view with the bundle
facts a release must not silently change:

* version                bundle identity movement (versionName/versionCode)
* size                   artifact size delta (contract/roll-out budget)
* permissions            dangerous permission set added/removed
* signers                signing-certificate set changes (key rotation
                         without v3 lineage = repackaging signal)
* endpoints              inventory hosts added/removed/re-classified
* surface                attack-surface doors added/removed, unguarded
                         doors added, browsable deep links added/removed
* findings               NEW / RESOLVED / unchanged (via diffcli)

Exit code ``1`` when new findings at/above ``--fail-on`` exist, or when a
requested gate fires: ``--gate-permissions`` (a dangerous permission was
add), ``--gate-signers`` (the signing identity changed), ``--gate-surface``
(the externally-reachable attack surface grew: an unguarded entry point
or browsable deep link was added). Usage errors -> 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Tuple

from .diffcli import (
    SEV_ORDER,
    _RISK,
    _fmt_finding,
    diff_reports,
    load_report,
    fail_on_rank,
)


def _bundle(doc: Dict[str, Any]) -> Dict[str, Any]:
    inv = doc.get("inventory") or {}
    bundle = inv.get("bundle") or {}
    return bundle if isinstance(bundle, dict) else {}


def bundle_deltas(
    old: Dict[str, Any], new: Dict[str, Any]
) -> Dict[str, Any]:
    """Compute bundle-fact deltas beyond the findings ledger."""
    b_old, b_new = _bundle(old), _bundle(new)
    out: Dict[str, Any] = {}

    versions = (b_old.get("version"), b_new.get("version"))
    if versions[0] or versions[1]:
        out["version"] = versions

    sizes = (b_old.get("size_bytes"), b_new.get("size_bytes"))
    if sizes[0] is not None and sizes[1] is not None:
        out["size"] = {
            "old": sizes[0], "new": sizes[1], "delta": sizes[1] - sizes[0],
        }

    perm_old = set(b_old.get("permissions") or [])
    perm_new = set(b_new.get("permissions") or [])
    if perm_old or perm_new:
        out["permissions"] = {
            "added": sorted(perm_new - perm_old),
            "removed": sorted(perm_old - perm_new),
        }

    sign_old = set(b_old.get("signers") or [])
    sign_new = set(b_new.get("signers") or [])
    if sign_old or sign_new:
        out["signers"] = {
            "added": sorted(sign_new - sign_old),
            "removed": sorted(sign_old - sign_new),
            "changed": bool(sign_new) and sign_old != sign_new,
        }

    endpoints_old = _endpoint_map(old)
    endpoints_new = _endpoint_map(new)
    out["endpoints"] = {
        "added": sorted(set(endpoints_new) - set(endpoints_old)),
        "removed": sorted(set(endpoints_old) - set(endpoints_new)),
        "reclassified": sorted(
            host for host in set(endpoints_new) & set(endpoints_old)
            if endpoints_old[host] != endpoints_new[host]
        ),
    }

    surf_old, surf_new = _surface(old), _surface(new)
    if surf_old["available"] and surf_new["available"]:
        doors_o, links_o = surf_old["doors"], surf_old["links"]
        doors_n, links_n = surf_new["doors"], surf_new["links"]
        added = sorted(set(doors_n) - set(doors_o))
        out["surface"] = {
            "added": added,
            "removed": sorted(set(doors_o) - set(doors_n)),
            "unguarded_added": [d for d in added if not doors_n[d]],
            "deep_links_added": sorted(links_n - links_o),
            "deep_links_removed": sorted(links_o - links_n),
        }
    else:
        out["surface"] = {"comparable": False}
    return out


def _surface(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract attack-surface doors + browsable links from a report.

    Returns ``{"available": False}`` when the report predates the
    attack-surface layer (the surface gate then stays silent — it needs
    a baseline from the same feature to judge a regression).
    """
    inv = doc.get("inventory") or {}
    surf = inv.get("attack_surface") or {}
    eps = surf.get("entry_points")
    if not isinstance(eps, list):
        return {"available": False}
    doors: Dict[str, str] = {}
    links: set = set()
    for e in eps:
        if not isinstance(e, dict):
            continue
        name = str(e.get("component") or "")
        if not name:
            continue
        doors[name] = str(e.get("permission") or "")
        for l in e.get("browsable_links") or []:
            if isinstance(l, dict):
                links.add("|".join(
                    str(l.get(k) or "")
                    for k in ("scheme", "host", "path_prefix")))
    return {"available": True, "doors": doors, "links": links}


def _endpoint_map(doc: Dict[str, Any]) -> Dict[str, str]:
    inv = doc.get("inventory") or {}
    ep = inv.get("endpoints") or {}
    rows = ep.get("rows") or []
    return {
        str(r.get("host") or r.get("value") or ""): str(
            r.get("classification") or ""
        )
        for r in rows
        if isinstance(r, dict)
    }


def print_delta(deltas: Dict[str, Any]) -> None:
    """Human output for the bundle-fact deltas."""
    if "version" in deltas:
        old, new = deltas["version"]
        if old != new:
            print(f"version  : {old or '?'} -> {new or '?'}")

    if "size" in deltas:
        s = deltas["size"]
        delta = s["delta"]
        human = f"{abs(delta) / 1024:.1f} KiB" if abs(delta) < 1 << 20 else \
            f"{abs(delta) / (1 << 20):.2f} MiB"
        print(
            f"size     : {s['old']} -> {s['new']} bytes "
            f"({'+' if delta >= 0 else ''}{delta}; +/-={human})"
        )

    perms = deltas.get("permissions") or {}
    if perms.get("added") or perms.get("removed"):
        print("permissions:")
        for p in perms["added"]:
            print(f"    ADDED    {p}")
        for p in perms["removed"]:
            print(f"    REMOVED  {p}")

    signers = deltas.get("signers") or {}
    if signers.get("changed"):
        print("signers  : CHANGE DETECTED (identity differs between builds)")
        for fp in signers["added"]:
            print(f"    ADDED    {fp[:32]}...")
        for fp in signers["removed"]:
            print(f"    REMOVED  {fp[:32]}...")

    eps = deltas.get("endpoints") or {}
    if eps["added"] or eps["removed"] or eps["reclassified"]:
        print("endpoints:")
        for host in eps["added"]:
            print(f"    ADDED          {host}")
        for host in eps["removed"]:
            print(f"    REMOVED        {host}")
        for host in eps["reclassified"]:
            print(f"    RECLASSIFIED   {host}")

    surf = deltas.get("surface") or {}
    if surf.get("comparable") is False:
        return
    if any(surf.get(k) for k in (
            "added", "removed", "unguarded_added",
            "deep_links_added", "deep_links_removed")):
        print("surface :")
        for d in surf.get("unguarded_added") or []:
            print(f"    UNGUARDED ADDED   {d}")
        for d in surf.get("added") or []:
            print(f"    ADDED             {d}")
        for d in surf.get("removed") or []:
            print(f"    REMOVED           {d}")
        for l in surf.get("deep_links_added") or []:
            print(f"    DEEP LINK ADDED   {_human_link(l)}")
        for l in surf.get("deep_links_removed") or []:
            print(f"    DEEP LINK REMOVED {_human_link(l)}")


def _human_link(key: str) -> str:
    """`scheme|host|path` storage form back to `scheme://host/path`."""
    scheme, host, path = (key.split("|") + ["", ""])[:3]
    return f"{scheme or 'any'}://{host}{path}"


def print_findings_diff(diff: Dict[str, Any]) -> None:
    """Findings ledger summary (shared conventions with diffcli)."""
    print(
        f"findings : {diff['old_count']} -> {diff['new_count']} "
        f"({len(diff['added'])} new, {len(diff['resolved'])} resolved, "
        f"{diff['kept']} unchanged)"
    )
    if diff["old_total"] is not None and diff["new_total"] is not None:
        arrow = "+" if diff["new_total"] >= diff["old_total"] else ""
        print(
            f"score    : {diff['old_total']} -> {diff['new_total']} "
            f"({arrow}{round(diff['new_total'] - diff['old_total'], 1)})"
        )
    if diff["added"]:
        print("\nNEW:")
        for f in diff["added"]:
            print(_fmt_finding(f))
    if diff["resolved"]:
        print("\nRESOLVED:")
        for f in diff["resolved"]:
            print(_fmt_finding(f))


def fail_reasons(
    deltas: Dict[str, Any],
    diff: Dict[str, Any],
    fail_on: str,
    gate_permissions: bool,
    gate_signers: bool,
    gate_surface: bool = False,
) -> List[str]:
    """Exit-code-1 reasons given the requested gates."""
    reasons: List[str] = []
    rank = fail_on_rank(fail_on)
    blocking = [
        f for f in diff["added"]
        if _RISK.get(str(f.get("severity", "")).lower(), 0) >= rank
    ]
    if blocking:
        reasons.append(
            f"{len(blocking)} new finding(s) at or above '{fail_on}'"
        )
    if gate_permissions:
        perms = (deltas.get("permissions") or {}).get("added") or []
        if perms:
            reasons.append(f"{len(perms)} permission(s) added: {', '.join(perms)}")
    if gate_signers:
        if (deltas.get("signers") or {}).get("changed"):
            reasons.append("signing identity changed between builds")
    if gate_surface:
        surf = deltas.get("surface") or {}
        unguarded = surf.get("unguarded_added") or []
        links = surf.get("deep_links_added") or []
        if unguarded:
            reasons.append(
                f"{len(unguarded)} unguarded entry point(s) added: "
                f"{', '.join(unguarded)}"
            )
        if links:
            reasons.append(
                f"{len(links)} browsable deep link(s) added: "
                f"{', '.join(_human_link(l) for l in links)}"
            )
    return reasons


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="masanalyzer-delta",
        description=(
            "Release gate: diff bundle facts (version, size, permissions, "
            "signers, endpoints, attack surface) + findings between two "
            "report.json files."
        ),
    )
    p.add_argument("old", help="reference report.json (previous release)")
    p.add_argument("new", help="candidate report.json (new build)")
    p.add_argument(
        "--fail-on", default="high", choices=SEV_ORDER,
        help="severity at-or-above which NEW findings fail the gate "
        "(default: high)",
    )
    p.add_argument(
        "--gate-permissions", action="store_true",
        help="also fail when a permission is added",
    )
    p.add_argument(
        "--gate-signers", action="store_true",
        help="also fail when the signing identity changed",
    )
    p.add_argument(
        "--gate-surface", action="store_true",
        help="also fail when the externally-reachable attack surface "
        "grew: an unguarded entry point or browsable deep link was "
        "added (needs an attack-surface section in both reports)",
    )
    args = p.parse_args(argv)

    try:
        old = load_report(args.old)
        new = load_report(args.new)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    diff = diff_reports(old, new)
    deltas = bundle_deltas(old, new)
    print_delta(deltas)
    print_findings_diff(diff)

    reasons = fail_reasons(
        deltas, diff, args.fail_on,
        args.gate_permissions, args.gate_signers, args.gate_surface,
    )
    if reasons:
        print("\nresult: BLOCKED - " + "; ".join(reasons), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

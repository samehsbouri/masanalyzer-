"""Rules and inventory over an ingested dynamic session.

Four observations, all graded ``observed`` (they happened on a device):

``MAS-DYN-001``  an ``http://`` request was actually sent
``MAS-DYN-002``  credential material crossed the wire
``MAS-DYN-003``  a tracker host was actually contacted
``MAS-DYN-004``  a host appeared that static analysis never saw

The last one is the reason dynamic analysis exists in this tool: it points
at configuration fetched at runtime, obfuscated strings and hardcoded
fallbacks -- endpoints no amount of string scanning can enumerate. The
inventory also carries the reverse list (static hosts never contacted), so
a reviewer can see both blind spots on one line.

Nothing here raises on a weird bundle: a rule that cannot read a field
skips that entry. A dynamic session is evidence, not a certifier -- the
report says which flows were exercised and never claims absence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..analysis.common import make_rule
from ..endpoints import TRACKER_SUFFIXES, _classify_host, host_is_trivial
from ..model import Confidence, Finding, Severity, redact

#: a cleartext request that was actually sent
R_CLEARTEXT = make_rule(
    "MAS-DYN-001",
    "M5",
    "Cleartext traffic observed at runtime",
    "An http:// request left the device during the captured session, so "
    "the payload was readable to anyone on the network path. Static "
    "scanning can only point at http:// constants; this is the request "
    "that was sent.",
    Severity.HIGH,
    "Move the endpoint to HTTPS and add a network security config that "
    "forbids cleartext, then re-run the session to confirm the request "
    "is gone.",
    cwe="CWE-319",
    confidence=Confidence.HIGH,
    cvss=7.4,
    platform="android",
)

R_CREDENTIALS = make_rule(
    "MAS-DYN-002",
    "M5",
    "Credential material observed in network traffic",
    "A request carried a credential in a header, query string or body "
    "during the captured session (values are redacted in the report). "
    "Because it is transmitted, the material is only as protected as the "
    "channel and the server's logging policy.",
    Severity.HIGH,
    "Send credentials in an Authorization header over TLS only, never in "
    "the query string, and rotate anything that appeared in a capture.",
    cwe="CWE-522",
    confidence=Confidence.HIGH,
    cvss=7.1,
    platform="android",
)

R_TRACKER = make_rule(
    "MAS-DYN-003",
    "M5",
    "Tracker beacon observed at runtime",
    "A host on the third-party tracker list received traffic during the "
    "session. The static inventory flags the endpoint; the session proves "
    "the app actually calls it.",
    Severity.MEDIUM,
    "Remove or gate the SDK that sends the beacon; if it is contractual, "
    "disclose it and check what identifiers it transmits.",
    cwe="CWE-359",
    confidence=Confidence.HIGH,
    cvss=4.3,
    platform="android",
)

R_UNSEEN = make_rule(
    "MAS-DYN-004",
    "M5",
    "Host contacted that static analysis never saw",
    "The session contacted a host that does not appear anywhere in the "
    "static endpoint inventory: the address was assembled at runtime, "
    "decrypted, received from a config endpoint, or never stored as a "
    "literal. Review it by hand before trusting the static inventory's "
    "coverage.",
    Severity.INFO,
    "Confirm the host is expected (config/CDN/first party). If it is not, "
    "trace where the address comes from.",
    cwe="CWE-200",
    confidence=Confidence.HIGH,
    cvss=0.0,
    platform="android",
)

RULES = [R_CLEARTEXT, R_CREDENTIALS, R_TRACKER, R_UNSEEN]

#: secrets that must never reach a report unredacted
_RX_SECRET_PARAM = re.compile(
    r"(?i)\b(access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|"
    r"password|passwd|pwd|client[_-]?secret|session[_-]?id|jwt)=([^&\s\"'#]{3,})"
)
_RX_AUTH_HEADER = re.compile(r"(?i)^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token)$")
_RX_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._\-+/=]{8,})")
_RX_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}")
_RX_HTTP_URL = re.compile(r"https?://[^\s\"'<>,)]+")
_RX_TLS_ERROR = re.compile(
    r"(?i)(SSLHandshake|CertPathValidator|Trust anchor|CERTIFICATE_VERIFY_FAILED|"
    r"SSLPeerUnverified|HostnameVerifier|pin(?:ning)? (?:check )?failed)"
)

#: caps that keep both findings and report.json bounded
MAX_FINDINGS_PER_RULE = 20
MAX_ROWS = 200
MAX_HOST_LIST = 50


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _package_tokens(target: Any) -> Set[str]:
    package = str(getattr(target, "package", "") or "").lower()
    return {t for t in re.split(r"[^a-z0-9]+", package) if len(t) > 2}


def _mask(value: str) -> str:
    return redact(value, keep=3)


def _safe_url(url: str) -> str:
    """URL with query values masked -- safe to put in evidence."""
    return _RX_SECRET_PARAM.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", url)


def _host_stats(bundle: Any, target: Any) -> Dict[str, Dict[str, Any]]:
    tokens = _package_tokens(target)
    stats: Dict[str, Dict[str, Any]] = {}
    for entry in bundle.traffic:
        host = (entry.host or "").lower()
        if not host or host_is_trivial(host):
            continue
        row = stats.setdefault(host, {
            "host": host,
            "requests": 0,
            "schemes": set(),
            "methods": set(),
            "cleartext": False,
            "example": "",
            "classification": _classify_host(host, entry.scheme, tokens),
        })
        row["requests"] += 1
        if entry.scheme:
            row["schemes"].add(entry.scheme)
        row["methods"].add(entry.method)
        row["cleartext"] = row["cleartext"] or entry.cleartext
        if not row["example"]:
            row["example"] = f"{entry.method} {_safe_url(entry.url)}"
    return stats


def _credential_hit(entry: Any) -> Optional[str]:
    """Description of the first credential found in one request, or None."""
    for name, value in (entry.request_headers or {}).items():
        if _RX_AUTH_HEADER.search(name or ""):
            match = _RX_BEARER.search(value or "")
            token = match.group(2) if match else (value or "")
            if len(token.strip()) >= 6:
                return f"{name}: {_mask(token.strip())}"
    match = _RX_SECRET_PARAM.search(entry.url or "")
    if match:
        return f"{match.group(1)}={_mask(match.group(2))}"
    for blob in (entry.post_data, entry.response_body):
        if not blob:
            continue
        match = _RX_SECRET_PARAM.search(blob)
        if match:
            return f"{match.group(1)}={_mask(match.group(2))}"
        match = _RX_JWT.search(blob)
        if match:
            return f"JWT {match.group(0)[:6]}..."
    if _RX_JWT.search(entry.url or ""):
        return f"JWT {_RX_JWT.search(entry.url).group(0)[:6]}..."
    return None


def _counts(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for value in values:
        key = str(value or "")
        if key:
            out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


# --------------------------------------------------------------------------
# findings
# --------------------------------------------------------------------------
def _findings(bundle: Any, stats: Dict[str, Dict[str, Any]],
              static_hosts: Set[str]) -> List[Finding]:
    findings: List[Finding] = []
    session = bundle.session_id
    source = "traffic.har"

    for host, row in sorted(stats.items()):
        if row["cleartext"] and row["classification"] != "local":
            findings.append(R_CLEARTEXT.finding(
                file=source,
                symbol=row["example"],
                note=f"observed on {host} ({row['requests']} request(s), "
                     f"session {session})",
            ))

    credentialed: Dict[str, str] = {}
    for entry in bundle.traffic:
        if not entry.host or entry.host in credentialed:
            continue
        hit = _credential_hit(entry)
        if hit:
            credentialed[entry.host] = f"{entry.method} {entry.path} -> {hit}"
    for host, detail in sorted(credentialed.items())[:MAX_FINDINGS_PER_RULE]:
        findings.append(R_CREDENTIALS.finding(
            file=source,
            symbol=detail,
            note=f"observed on {host} during session {session}",
        ))

    for host, row in sorted(stats.items()):
        if row["classification"] == "tracker":
            findings.append(R_TRACKER.finding(
                file=source,
                symbol=row["example"],
                note=f"{row['requests']} request(s) to tracker {host} "
                     f"(session {session})",
            ))

    unseen = sorted(
        (host, row) for host, row in stats.items()
        if host not in static_hosts
        and row["classification"] not in ("tracker", "local")
    )[:MAX_FINDINGS_PER_RULE]
    for host, row in unseen:
        findings.append(R_UNSEEN.finding(
            file=source,
            symbol=row["example"],
            note=f"{host} is absent from the static endpoint inventory "
                 f"({len(static_hosts)} hosts); seen {row['requests']} time(s) "
                 f"in session {session}",
        ))
    return findings


# --------------------------------------------------------------------------
# inventory
# --------------------------------------------------------------------------
def _logcat_summary(bundle: Any) -> Dict[str, Any]:
    if not bundle.logcat:
        return {}
    errors = 0
    tls_errors = 0
    urls: Set[str] = set()
    tags: Dict[str, int] = {}
    for entry in bundle.logcat:
        if entry.is_error:
            errors += 1
        if entry.tag:
            tags[entry.tag] = tags.get(entry.tag, 0) + 1
        if _RX_TLS_ERROR.search(entry.message or ""):
            tls_errors += 1
        urls.update(_RX_HTTP_URL.findall(entry.message or ""))
    top_tags = [{"tag": tag, "lines": count}
                for tag, count in sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))[:12]]
    return {
        "lines": len(bundle.logcat),
        "errors": errors,
        "tls_errors": tls_errors,
        "urls": len(urls),
        "top_tags": top_tags,
    }


def _inventory(bundle: Any, target: Any, stats: Dict[str, Dict[str, Any]],
               findings: List[Finding]) -> Dict[str, Any]:
    static_rows = ((getattr(target, "meta", {}) or {}).get("endpoints") or {}).get("rows") or []
    static_hosts = {str(r.get("host") or "").lower() for r in static_rows if r.get("host")}
    observed = set(stats)

    out: Dict[str, Any] = {"session": bundle.provenance()}
    if bundle.traffic:
        rows = []
        for host, row in sorted(stats.items(), key=lambda kv: (-kv[1]["requests"], kv[0])):
            rows.append({
                "host": host,
                "classification": row["classification"],
                "requests": row["requests"],
                "cleartext": row["cleartext"],
                "schemes": sorted(row["schemes"]),
                "methods": sorted(row["methods"]),
            })
        out["traffic"] = {
            "total": len(bundle.traffic),
            "hosts": len(rows),
            "cleartext": sum(1 for e in bundle.traffic if e.cleartext),
            "trackers": sum(1 for r in rows if r["classification"] == "tracker"),
            "errors": sum(1 for e in bundle.traffic if e.status >= 400),
            "methods": _counts(e.method for e in bundle.traffic),
            "rows": rows[:MAX_ROWS],
        }
        out["correlation"] = {
            "static_hosts": len(static_hosts),
            "observed_hosts": len(observed),
            "matched": len(observed & static_hosts),
            "runtime_only": sorted(observed - static_hosts)[:MAX_HOST_LIST],
            "static_only": sorted(static_hosts - observed)[:MAX_HOST_LIST],
            "runtime_only_total": len(observed - static_hosts),
            "static_only_total": len(static_hosts - observed),
        }
    logcat = _logcat_summary(bundle)
    if logcat:
        out["logcat"] = logcat
    if bundle.files:
        out["files"] = bundle.files[:200]
    if bundle.hooks:
        out["hooks"] = bundle.hooks[:200]
    if findings:
        out["findings"] = _counts(f.rule_id for f in findings)
    if bundle.warnings:
        out["warnings"] = bundle.warnings[:50]
    return out


def analyze_bundle(bundle: Any, target: Any) -> Tuple[List[Finding], Dict[str, Any]]:
    """``(findings, inventory)`` for one session over ``target``."""
    if bundle is None:
        return [], {}
    stats = _host_stats(bundle, target)
    static_rows = ((getattr(target, "meta", {}) or {}).get("endpoints") or {}).get("rows") or []
    static_hosts = {str(r.get("host") or "").lower() for r in static_rows if r.get("host")}
    findings = _findings(bundle, stats, static_hosts)
    return findings, _inventory(bundle, target, stats, findings)


def tracker_host(host: str) -> bool:
    """True when ``host`` matches the static tracker suffix table."""
    low = (host or "").lower()
    return any(low == t or low.endswith("." + t) for t in TRACKER_SUFFIXES)

"""IOC / threat-intel mode (``--intel FILE``).

One plain-text file, one indicator per line (``#`` comments allowed):

* IPv4 addresses          -> matched against the string pool + file text;
* domains / URLs          -> host extracted, matched the same way;
* md5/sha1/sha256 digests -> matched against every scanned file's digest
  (computed during packaging) with a sha-truncated prefix fallback.

Every hit becomes a HIGH (network indicators) or CRITICAL (digests)
finding tagged with the ``intel`` label, so ``--fail-on high`` gates on
intel matches in CI. Network indicators compile into a *generated user
rule pack* (same engine as ``--rules``: exclusions, severity overrides,
baselines all work on it); digests are matched against the packaging-time
``ScanFile.sha256`` table, where a truncated-entry cron comparison guards
against input mishaps.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_RX_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_RX_DIGEST = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_RX_DOMAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]*\.)+[A-Za-z]{2,}")
_RX_URL_HOST = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/@\s]+)")
_TRIM_HOST = re.compile(r"^[A-Za-z0-9._-]+")
_PREFIX_LINE = re.compile(r"^(host|domain|ip|addr|hash|sha256|sha1|md5):(\S+)$")

MAX_INTEL_LINE = 4096
MAX_TOKENS = 5000
_INTEL_TAGS = ("intel", "ioc")


# --------------------------------------------------------------------------
# indicator parsing / classification
# --------------------------------------------------------------------------
def parse_intel_file(path: str) -> Tuple[Dict[str, List[str]], List[str]]:
    """Read + classify indicator lines.

    Returns ``(by_type, errors)`` with ``domain``/``ip``/``hash`` buckets;
    malformed lines are *reported*, never fatal.
    """
    by_type: Dict[str, List[str]] = {"domain": [], "ip": [], "hash": []}
    errors: List[str] = []
    seen: set = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if len(line) > MAX_INTEL_LINE:
                errors.append(f"line {lineno}: too long, skipped")
                continue
            m = _PREFIX_LINE.match(line)
            if m:
                line = m.group(2)
            token = line.strip().rstrip(",;")
            cls = classify_token(token)
            if cls is None:
                errors.append(
                    f"line {lineno}: unrecognized indicator {line[:60]!r}"
                )
                continue
            key = (cls, token.lower())
            if key in seen:
                continue
            seen.add(key)
            bucket = by_type[cls]
            if len(bucket) >= MAX_TOKENS:
                errors.append(f"line {lineno}: intel limit ({MAX_TOKENS}) reached")
                continue
            if cls == "hash":
                bucket.append(token.lower())
            else:
                # URLs are stored as their bare host so pool matching and
                # the generated regex both operate on the hostname
                bucket.append(_host_of(token) if cls == "domain" else token)
    return by_type, errors


def _host_of(token: str) -> str:
    """Reduce a URL/domain token to its bare hostname (lowercased)."""
    host = token
    scheme = _RX_URL_HOST.match(token)
    if scheme:
        host = scheme.group(1)
    return (_TRIM_HOST.match(host) or [""])[0].rstrip(".").lower()


def classify_token(token: str) -> Optional[str]:
    """Classify one indicator token: ``ip`` | ``hash`` | ``domain`` | None."""
    token = token.strip().rstrip(",;")
    if not token:
        return None
    if _RX_IPV4.fullmatch(token):
        ok = all(0 <= int(part) <= 255 for part in token.split("."))
        return "ip" if ok else None
    if _RX_DIGEST.fullmatch(token):
        return "hash"
    host = _host_of(token)
    if not host:
        return None
    if _RX_IPV4.fullmatch(host):
        ok = all(0 <= int(part) <= 255 for part in host.split("."))
        return "ip" if ok else None
    if _RX_DOMAIN.fullmatch(host):
        return "domain"
    return None


# --------------------------------------------------------------------------
# compile to the shared rule-pack engine
# --------------------------------------------------------------------------
def build_ioc_pack(by_type: Dict[str, List[str]]) -> Optional["RulePack"]:
    """Compile the domain/ip tables into a generated user rule pack."""
    from .rulepack import build_rule_pack

    patterns: List[str] = []
    for group in ("domain", "ip"):
        for token in sorted(by_type[group])[:MAX_TOKENS]:
            patterns.append(re.escape(token.lower()))
    rules: List[Dict[str, Any]] = []
    if patterns:
        rules.append(
            {
                "id": "network-indicator",
                "title": "Threat-intel indicator matched (network)",
                "description": (
                    "A domain or address listed in the supplied intel file "
                    "appears in the bundle's strings or text content. Fit "
                    "the context: requests to intel-listed hosts are the "
                    "signature of C2 callbacks, tracking fraud or "
                    "exfiltration paths."
                ),
                "severity": "high",
                "owasp": "M2",
                "cwe": "CWE-807",
                "confidence": "medium",
                "max_matches": 100,
                "scopes": ["strings", "files"],
                "patterns": [{"kind": "regex", "value": "|".join(patterns)}],
            }
        )
    if not rules:
        return None
    pack = build_rule_pack(
        {
            "name": "ioc",
            "description": "generated threat-intel pack (--intel)",
            "owasp": "M2",
            "rules": rules,
        },
        source="<intel>",
    )
    for compiled in pack.rules:
        compiled.rule.tags.extend(_INTEL_TAGS)
    return pack


# --------------------------------------------------------------------------
# digest matching + the analyzer surface
# --------------------------------------------------------------------------
class IntelBundle:
    """Ready-to-run intel: generated pack + digest table."""

    def __init__(self, by_type: Dict[str, List[str]], errors: List[str]):
        self.by_type = by_type
        self.errors = list(errors)
        self.pack = build_ioc_pack(by_type)
        self.digests: Dict[str, int] = {}
        for token in by_type["hash"]:
            # hex-char length: 32 = md5, 40 = sha1, 64 = sha256
            self.digests[token.lower()] = len(token)

    @property
    def active(self) -> bool:
        return bool(self.pack or self.digests)

    def analyze(self, target) -> List:
        """Run network indicator rules + file digest matching on a target."""
        out: List = []
        if self.pack is not None:
            out.extend(self.pack.analyze(target))
        out.extend(_digest_findings(self.digests, target))
        return out


_DIGEST_ALGOS = {32: "md5", 40: "sha1", 64: "sha256"}


def _digest_findings(digests: Dict[str, int], target) -> List:
    from .analysis.common import OWASP_URL
    from .model import Confidence, Evidence, Finding, Severity

    if not digests:
        return []
    wanted: Dict[int, List[str]] = {}
    for token, size in digests.items():
        wanted.setdefault(size, []).append(token)

    out: List = []

    def emit(sf, token: str, algo: str, digest: str) -> None:
        out.append(
            Finding(
                rule_id="CUSTOM-IOC-DIGEST",
                title="Threat-intel indicator matched (file digest)",
                description=(
                    "A file digest listed in the supplied intel file "
                    "matches a scanned artifact: the bundle carries "
                    "intel-listed content. Investigate provenance and "
                    "consider the artifact compromised."
                ),
                severity=Severity("critical"),
                owasp="M2",
                category="Inadequate Supply Chain Security",
                platform="any",
                remediation=(
                    "Remove/quarantine the intel-listed artifact and "
                    "confirm the build source; digests on intel lists are "
                    "usually known-malware or leaked artifacts."
                ),
                cwe="CWE-494",
                cvss=9.1,
                confidence=Confidence.HIGH,
                tags=list(_INTEL_TAGS),
                references=[OWASP_URL],
                evidence=Evidence(
                    file=sf.relpath,
                    symbol=token,
                    note=f"file digest matches intel ({algo} {digest[:16]}...)",
                ),
            )
        )

    for sf in getattr(target, "files", []) or []:
        sha = (getattr(sf, "sha256", "") or "").lower()
        if 64 in wanted and sha in wanted[64]:
            emit(sf, sha, "sha256", sha)
        for algo in ("md5", "sha1"):
            tokens = wanted.get(_len_of(algo), [])
            if not tokens:
                continue
            digest = _hash_file(sf.path, algo)
            for token in tokens:
                if digest == token:
                    emit(sf, token, algo, digest)
    return out


def _len_of(algo: str) -> int:
    return {"md5": 32, "sha1": 40, "sha256": 64}[algo]


def _hash_file(path: str, algo: str) -> str:
    import hashlib

    h = hashlib.new(algo)
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# --------------------------------------------------------------------------
# loader
# --------------------------------------------------------------------------
def load_intel(path: str) -> IntelBundle:
    """Parse an intel file; a bundle with no valid indicators is inert."""
    by_type, errors = parse_intel_file(path)
    return IntelBundle(by_type, errors)

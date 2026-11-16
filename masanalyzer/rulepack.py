"""User-defined rule packs (declarative custom intel for scans).

A rule pack is a small JSON document the user authors once and passes to
``masanalyzer --rules FILE`` (repeatable). Every rule compiles to a
``CUSTOM-<PACK>-<ID>`` finding rule wired into the analyzer pipeline, so
policy features (``config.exclude_rules``, severity overrides, baselines,
``--min-severity``) treat it like any built-in rule.

Schema (all keys optional except ``name`` and ``patterns``; unknown keys
error out so typos never silently disable a rule)::

    {
      "name": "acme-brand",
      "description": "acme internal intel",
      "owasp": "M8",                     // default M8; M1..M10 accepted
      "rules": [
        {
          "id": "backend-key",           // -> CUSTOM-ACMEBRAND-BACKENDKEY
          "title": "Leftover backend key",
          "description": "...",          // reused as remediation guidance
          "severity": "high",            // info..critical, default medium
          "owasp": "M1",                 // overrides pack-level bucket
          "cwe": "CWE-798",
          "cvss": 7.2,                   // optional 0-10
          "confidence": "high",          // low|medium|high, default medium
          "redact": false,               // mask captured evidence
          "max_matches": 20,             // per-rule cap, default 50
          "scopes": ["strings", "files", "code", "manifest", "binary"],
          "patterns": [
            {"kind": "regex",  "value": "https?://[A-Za-z0-9.-]+acme[.]io/"},
            {"kind": "string", "value": "ACME_BACKEND_TOKEN", "ci": true},
            {"kind": "bytes_hex", "value": "deadbeef"}       // raw bytes scan
          ]
        }
      ]
    }

Scopes:

* ``strings``  - the shared string pool (DEX strings, arsc, native blobs);
* ``files``    - every text-classified file, line by line;
* ``code``     - code + smali files only (same iteration as analyzers);
* ``manifest`` - the decoded Android manifest surface (fields joined);
* ``binary``   - raw byte patterns across every scanned file.

The engine is deliberately tiny and stdlib-only: compiled ``re`` objects
plus substring / bytes finds. Packs validate at load time (bad regex ->
``ValueError``, never a crash mid-scan) and everything is deterministic:
matches are reported in target file order, capped per rule.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

PACK_MAX_MATCHES_DEFAULT = 50
PACK_MAX_FILE_BYTES = 32 * 1024 * 1024  # byte-pattern scope guard
_ID_FRAGMENT_MAX = 24

_SEVERITIES = ("info", "low", "medium", "high", "critical")
_CONFIDENCE = ("low", "medium", "high")
_VALID_SCOPES = ("strings", "files", "code", "manifest", "binary")
_PATTERN_KINDS = ("regex", "string", "bytes_hex")
_DEFAULT_OWASP = "M8"
_OWASP_IDS = tuple(f"M{i}" for i in range(1, 11))


# --------------------------------------------------------------------------
# load + compile
# --------------------------------------------------------------------------
def load_rule_pack(path: str) -> "RulePack":
    """Load + validate one JSON rule pack file."""
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"rule pack {path}: invalid JSON: {exc}") from exc
    return build_rule_pack(data, source=path)


def build_rule_pack(data: Dict[str, Any], source: str = "<memory>") -> "RulePack":
    """Validate + compile an in-memory pack definition."""
    if not isinstance(data, dict):
        raise ValueError(f"rule pack {source}: top level must be a JSON object")
    unknown = set(data) - {"name", "description", "owasp", "rules"}
    if unknown:
        raise ValueError(
            f"rule pack {source}: unknown top-level key(s): {sorted(unknown)}"
        )
    name = data.get("name")
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{1,31}", name
    ):
        raise ValueError(
            f"rule pack {source}: 'name' must be a 2-32 char string of "
            "letters, digits, '_' and '-'"
        )
    owasp = str(data.get("owasp", _DEFAULT_OWASP)).upper()
    if owasp not in _OWASP_IDS:
        raise ValueError(f"rule pack {source}: 'owasp' must be one of M1..M10")

    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ValueError(f"rule pack {source}: 'rules' must be a non-empty list")

    pack_fragment = _fragment(name)
    compiled: List[CompiledRule] = []
    seen_ids: set = set()
    for idx, raw in enumerate(rules_raw, start=1):
        compiled.append(
            _compile_rule(
                raw,
                pack_fragment=pack_fragment,
                default_owasp=owasp,
                index=idx,
                source=source,
                seen_ids=seen_ids,
            )
        )
    return RulePack(
        fragment=pack_fragment,
        title=name,
        description=str(data.get("description", "")),
        source=source,
        owasp=owasp,
        rules=compiled,
    )


def _fragment(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", text.upper()).strip("-")[:_ID_FRAGMENT_MAX]


class CompiledRule:
    """One validated, compiled custom rule (immutable-ish struct)."""

    __slots__ = (
        "rule", "regexes", "literals", "byte_patterns",
        "scopes", "max_matches", "redact",
    )

    def __init__(self, **kwargs):
        for key in self.__slots__:
            setattr(self, key, kwargs[key])


def _compile_rule(
    raw: Any,
    *,
    pack_fragment: str,
    default_owasp: str,
    index: int,
    source: str,
    seen_ids: set,
) -> CompiledRule:
    where = f"rule #{index}"
    if not isinstance(raw, dict):
        raise ValueError(f"rule pack {source}: {where} must be an object")
    unknown = set(raw) - {
        "id", "title", "description", "severity", "owasp", "cwe", "cvss",
        "confidence", "scopes", "patterns", "max_matches", "redact",
    }
    if unknown:
        raise ValueError(
            f"rule pack {source}: {where}: unknown key(s) {sorted(unknown)}"
        )

    id_fragment = _fragment(str(raw.get("id") or f"r{index:02d}"))
    rule_id = f"CUSTOM-{pack_fragment}-{id_fragment}"
    if rule_id in seen_ids:
        raise ValueError(f"rule pack {source}: {where}: duplicate rule id {rule_id}")
    seen_ids.add(rule_id)

    severity_raw = str(raw.get("severity", "medium")).lower()
    if severity_raw not in _SEVERITIES:
        raise ValueError(
            f"rule pack {source}: {where}: severity must be one of {_SEVERITIES}"
        )
    confidence_raw = str(raw.get("confidence", "medium")).lower()
    if confidence_raw not in _CONFIDENCE:
        raise ValueError(
            f"rule pack {source}: {where}: confidence must be one of {_CONFIDENCE}"
        )
    cvss = raw.get("cvss")
    if cvss is not None and not (
        isinstance(cvss, (int, float)) and not isinstance(cvss, bool)
        and 0 <= cvss <= 10
    ):
        raise ValueError(f"rule pack {source}: {where}: cvss must be a number 0-10")
    cwe = raw.get("cwe")
    if cwe is not None and not str(cwe).upper().startswith("CWE-"):
        raise ValueError(f"rule pack {source}: {where}: cwe must look like 'CWE-123'")

    scopes_raw = raw.get("scopes") or ["files"]
    if isinstance(scopes_raw, str):
        scopes_raw = [scopes_raw]
    if not isinstance(scopes_raw, list):
        raise ValueError(f"rule pack {source}: {where}: scopes must be a list")
    scopes = {str(s).lower() for s in scopes_raw}
    bad = scopes - set(_VALID_SCOPES)
    if bad:
        raise ValueError(
            f"rule pack {source}: {where}: unknown scope(s) {sorted(bad)}; "
            f"valid: {_VALID_SCOPES}"
        )

    patterns_raw = raw.get("patterns")
    if not isinstance(patterns_raw, list) or not patterns_raw:
        raise ValueError(
            f"rule pack {source}: {where}: 'patterns' must be a non-empty list"
        )

    regexes: List[re.Pattern] = []
    literals: List[Tuple[str, bool]] = []  # (value, ignore_case)
    byte_patterns: List[bytes] = []
    for p_raw in patterns_raw:
        if not isinstance(p_raw, dict):
            raise ValueError(
                f"rule pack {source}: {where}: each pattern must be an object"
            )
        p_unknown = set(p_raw) - {"kind", "value", "ci"}
        if p_unknown:
            raise ValueError(
                f"rule pack {source}: {where}: pattern key(s) {sorted(p_unknown)}"
            )
        kind = p_raw.get("kind")
        value = p_raw.get("value")
        if kind not in _PATTERN_KINDS:
            raise ValueError(
                f"rule pack {source}: {where}: pattern kind must be one of "
                f"{_PATTERN_KINDS}"
            )
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"rule pack {source}: {where}: pattern 'value' must be a "
                "non-empty string"
            )
        if kind == "regex":
            try:
                regexes.append(re.compile(value))
            except re.error as exc:
                raise ValueError(
                    f"rule pack {source}: {where}: bad regex {value!r}: {exc}"
                ) from exc
        elif kind == "string":
            literals.append((value, bool(p_raw.get("ci", False))))
        else:
            try:
                blob = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(
                    f"rule pack {source}: {where}: bytes_hex must be hex digits"
                ) from exc
            if not blob:
                raise ValueError(f"rule pack {source}: {where}: bytes_hex is empty")
            scopes.add("binary")  # byte patterns ride the binary pass
            byte_patterns.append(blob)

    max_matches = raw.get("max_matches", PACK_MAX_MATCHES_DEFAULT)
    if not isinstance(max_matches, int) or isinstance(max_matches, bool) or not (
        1 <= max_matches <= 1000
    ):
        raise ValueError(f"rule pack {source}: {where}: max_matches must be 1..1000")

    owasp = str(raw.get("owasp", default_owasp)).upper()
    if owasp not in _OWASP_IDS:
        raise ValueError(f"rule pack {source}: {where}: owasp must be one of M1..M10")

    from .model import Confidence, Rule, Severity
    from .owasp import category_name
    from .analysis.common import OWASP_URL

    title = str(raw.get("title") or f"Custom intel match ({id_fragment})")
    description = str(raw.get("description") or rule_id)
    references = [OWASP_URL]
    if cwe:
        references.append(
            "https://cwe.mitre.org/data/definitions/%s.html"
            % str(cwe).split("-", 1)[1]
        )
    rule = Rule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=Severity(severity_raw),
        owasp=owasp,
        category=category_name(owasp),
        remediation=(
            "Manual triage of a user rule-pack hit: confirm relevance or "
            "exclude the rule via the scan config."
        ),
        cwe=str(cwe) if cwe else None,
        cvss=cvss,
        confidence=Confidence(confidence_raw),
        platform="any",
        references=references,
    )
    return CompiledRule(
        rule=rule,
        regexes=regexes,
        literals=literals,
        byte_patterns=byte_patterns,
        scopes=scopes,
        max_matches=max_matches,
        redact=bool(raw.get("redact", False)),
    )


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------
class RulePack:
    """A compiled pack (name, metadata, rules) + its analyzer entry point."""

    def __init__(
        self,
        fragment: str,
        title: str,
        description: str,
        source: str,
        owasp: str,
        rules: List[CompiledRule],
    ):
        self.fragment = fragment
        self.title = title
        self.description = description
        self.source = source
        self.owasp = owasp
        self.rules = rules

    def rule_catalog(self):
        """The rule objects this pack contributes (metadata consumers)."""
        return [c.rule for c in self.rules]

    def analyze(self, target) -> List:
        """Run the pack over a prepared :class:`Target`; returns findings."""
        out: List = []
        for compiled in self.rules:
            out.extend(_run_rule(compiled, target))
        return out


# single shared module state: packs loaded for the current process (CLI or
# API). scanner picks them up through :func:`active_packs`.
_ACTIVE_PACKS: List[RulePack] = []


def activate_packs(packs: List[RulePack]) -> None:
    """Replace the process-wide set of active packs."""
    global _ACTIVE_PACKS
    _ACTIVE_PACKS = list(packs)


def active_packs() -> List[RulePack]:
    return list(_ACTIVE_PACKS)


def rule_catalog_extra():
    """Rule objects from all loaded packs (used by the rule catalog)."""
    out: List = []
    for pack in active_packs():
        out.extend(pack.rule_catalog())
    return out


def _match(text: str, compiled: CompiledRule) -> Optional[str]:
    """Return the matched substring (or None) for text patterns."""
    for rx in compiled.regexes:
        m = rx.search(text)
        if m is not None:
            return m.group(0)
    for literal, ignore_case in compiled.literals:
        if ignore_case:
            hay = text.lower()
            needle = literal.lower()
            pos = hay.find(needle)
        else:
            pos = text.find(literal)
        if pos >= 0:
            return text[pos: pos + len(literal)]
    return None


def _run_rule(compiled: CompiledRule, target) -> List:
    rule = compiled.rule

    def emit(rel: str, symbol: str, line: Optional[int],
             note: str) -> Optional[object]:
        if compiled.redact and symbol:
            from .model import redact

            symbol = redact(symbol)
        return rule.finding(
            file=rel,
            line=line,
            symbol=(symbol or None) if symbol else None,
            note=note,
        )

    out: List = []
    hits = 0
    matched_text = _needs_text(compiled)

    # manifest surface -------------------------------------------------------
    if matched_text and "manifest" in compiled.scopes:
        for rel, text in _manifest_text(target):
            symbol = _match(text, compiled)
            if symbol is None:
                continue
            f = emit(rel, symbol, None, "matched manifest surface")
            if f is None:
                break
            out.append(f)
            hits += 1

    # text file scopes -------------------------------------------------------
    if matched_text:
        for rel, line, text in _text_sources(compiled, target):
            symbol = _match(text, compiled)
            if symbol is None:
                continue
            f = emit(rel, symbol, line, "matched file text")
            if f is None:
                break
            out.append(f)
            hits += 1

    # shared string pool ------------------------------------------------------
    if matched_text and "strings" in compiled.scopes:
        for rel, value in getattr(target, "string_pool", None) or []:
            if not value:
                continue
            symbol = _match(value, compiled)
            if symbol is None:
                continue
            f = emit(rel, symbol, None, "matched string pool")
            if f is None:
                break
            out.append(f)
            hits += 1

    # raw byte patterns -------------------------------------------------------
    if compiled.byte_patterns:
        for sf in getattr(target, "files", []) or []:
            size = getattr(sf, "size", 0) or 0
            if size > 0 and size > PACK_MAX_FILE_BYTES:
                continue
            try:
                with open(sf.path, "rb") as fh:
                    blob = fh.read(max(size, 1))
            except OSError:
                continue
            for pattern in compiled.byte_patterns:
                pos = blob.find(pattern)
                if pos < 0:
                    continue
                offset = getattr(sf, "offset", None)
                f = rule.finding(
                    file=sf.relpath,
                    offset=pos,
                    symbol=pattern.hex(),
                    note="matched raw byte pattern (hex)",
                )
                out.append(f)
                hits += 1
                if hits >= compiled.max_matches:
                    break
            if hits >= compiled.max_matches:
                break
    return out


def _needs_text(compiled: CompiledRule) -> bool:
    return bool(compiled.regexes or compiled.literals)


def _text_sources(compiled: CompiledRule, target) -> Iterator[Tuple[str, int, str]]:
    """Yield ``(relpath, lineno, text)`` per requested text scope."""
    want_files = "files" in compiled.scopes
    want_code = "code" in compiled.scopes
    kinds: Optional[Tuple[str, ...]] = None
    if not want_files:
        kinds = ("code", "smali")
    for sf in getattr(target, "files", []) or []:
        if kinds is None:
            if not getattr(sf, "is_text", False):
                continue
        elif sf.kind not in kinds:
            continue
        try:
            with open(sf.path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    yield sf.relpath, lineno, line
        except OSError:
            continue


def _manifest_text(target) -> Iterator[Tuple[str, str]]:
    """A searchable textual surface for the decoded Android manifest."""
    manifest = getattr(target, "manifest", None)
    if manifest is None:
        return
    rel = (target.meta or {}).get("manifest_path") or "AndroidManifest.xml"
    parts: List[str] = []
    for attr in ("package", "version_name", "application_label",
                 "shared_user_id", "backup_agent", "application_class",
                 "network_security_config"):
        val = getattr(manifest, attr, None)
        if val is not None and str(val):
            parts.append(f"{attr}={val}")
    parts.extend(f"uses-permission:{p}" for p in manifest.uses_permissions)
    parts.extend(f"custom-permission:{p.name}" for p in manifest.custom_permissions)
    parts.extend(f"uses-library:{lib}" for lib in manifest.uses_libraries)
    for component in manifest.all_components():
        parts.append(f"{component.kind}:{component.name}")
        for f in component.filters:
            parts.extend(f"host:{h}" for h in f.hosts)
            parts.extend(f"scheme:{s}" for s in f.schemes)
    yield rel, " ".join(parts)

"""JUnit XML report - CI gate for every serious pipeline.

One ``<testsuite>`` per scan (deterministic content order = finding order,
already severity-sorted upstream). Under the CI convention:

* ``medium``/``high``/``critical`` findings emit ``<failure>`` elements so a
  finding-bearing scan breaks the build (the ``--fail-on`` gate story);
* ``low``/``info`` findings emit ``<skipped>`` so they are visible in the
  CI UI without voting on the gate.

Scan metadata (grade, score, target identity) travels as ``<properties>``
so dashboards can render it without re-parsing the console output.

Same rules as the other renderers: stdlib only (``xml.etree``), fully
deterministic, duck-typed over ``result`` (no analysis imports).
"""

from __future__ import annotations

from typing import Any, Dict, List

import xml.etree.ElementTree as ET

#: severities that should fail the CI build
_FAILING = ("medium", "high", "critical")

_TS_NAME = "masanalyzer.findings"


def render_junit(result: Any) -> str:
    """Render one scan result as a JUnit XML document string."""
    findings = list(getattr(result, "findings", None) or [])
    failures = sum(1 for f in findings if _severity(f) in _FAILING)
    skipped = len(findings) - failures

    score = getattr(result, "score", None)
    target = getattr(result, "target", None)

    root = ET.Element(
        "testsuites",
        {
            "name": str(getattr(result, "tool", {}).get("name", "masanalyzer")),
            "tests": str(len(findings)),
            "failures": str(failures),
            "skipped": str(skipped),
            "time": f"{getattr(result, 'duration_s', 0.0):.2f}",
        },
    )
    suite = ET.SubElement(
        root,
        "testsuite",
        {
            "name": _TS_NAME,
            "id": _TS_NAME,
            "tests": str(len(findings)),
            "failures": str(failures),
            "skipped": str(skipped),
            "time": f"{getattr(result, 'duration_s', 0.0):.2f}",
            "timestamp": str(getattr(result, "started", "") or ""),
        },
    )

    props = ET.SubElement(suite, "properties")
    for name, value in (
        ("tool", str((getattr(result, "tool", {}) or {}).get("name", "masanalyzer"))),
        ("tool_version", str((getattr(result, "tool", {}) or {}).get("version", ""))),
        ("target", str(getattr(target, "input_path", "") or "")),
        ("platform", str(getattr(target, "platform", "") or "")),
        ("grade", str(getattr(score, "grade", "") or "")),
        ("score", f"{getattr(score, 'value', 0.0):.1f}" if score is not None else ""),
        ("analyzers_run", str(getattr(result, "analyzers_run", 0) or 0)),
    ):
        ET.SubElement(props, "property", {"name": name, "value": value})

    # unique, human-traceable testcase names: rule title @ location, with a
    # deterministic identity suffix only where two findings would collide
    # (same rule + same location - the component then lives in evidence)
    names: Dict[str, List[Finding]] = {}
    for f in findings:
        ev = f.evidence
        base = "[%s] %s @ %s" % (
            str(getattr(f, "severity", "info")), f.title, ev.location)
        names.setdefault(base, []).append(f)
    unique_names: Dict[Any, str] = {}
    for base, group in names.items():
        if len(group) == 1:
            unique_names[id(group[0])] = base
        else:
            for f in group:
                unique_names[id(f)] = "%s #%s" % (base, f.identity)

    for f in findings:
        d = f.to_dict()
        ev = d.get("evidence") if isinstance(d.get("evidence"), dict) else {}
        sev = str(d.get("severity", "info"))
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": str(d.get("rule_id", "?")),
                "name": unique_names[id(f)],
                "file": str(ev.get("file", "") or ""),
                "time": "0.00",
            },
        )
        line = ev.get("line")
        if line:
            testcase.set("line", str(line))
        body = "\n".join(
            part
            for part in (
                str(d.get("description", "") or ""),
                ("Matched: " + str(ev.get("symbol"))) if ev.get("symbol") else "",
                ("How detected: " + str(ev.get("note"))) if ev.get("note") else "",
                ("Exact code:\n" + str(ev.get("snippet"))) if ev.get("snippet") else "",
                str(d.get("remediation", "") or ""),
            )
            if part
        )
        if sev in _FAILING:
            ET.SubElement(
                testcase,
                "failure",
                {
                    "message": str(d.get("title", "finding")),
                    "type": sev,
                },
            ).text = body or "security finding"
        else:
            ET.SubElement(
                testcase,
                "skipped",
                {"message": str(d.get("title", "finding")), "type": sev},
            )

    # deterministic, single-line XML declaration
    ET.indent(root, space="  ")
    return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + ET.tostring(
        root, encoding="unicode"
    )


def _severity(finding: Any) -> str:
    return str(getattr(finding, "severity", "info"))

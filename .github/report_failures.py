"""Print pytest's failures as GitHub Actions annotations.

Job logs are only downloadable by repository admins, so a failing matrix leg
would otherwise be invisible from the outside. Annotations are public, so the
suite is run with ``--junitxml`` and this step re-emits each failure as an
``::error`` annotation (file/line plus the first lines of the traceback).
"""

from __future__ import annotations

import glob
import sys
import xml.etree.ElementTree as ET

REPORT = "pytest-report.xml"
MAX_LINES = 8
MAX_CHARS = 1200


def main() -> int:
    emitted = 0
    for path in glob.glob(REPORT):
        for case in ET.parse(path).iter("testcase"):
            node = case.find("failure")
            if node is None:
                node = case.find("error")
            if node is None:
                continue
            text = (node.get("message") or node.text or "").strip()
            head = " | ".join(
                line.strip() for line in text.splitlines()[:MAX_LINES]
            )[:MAX_CHARS]
            print(
                f"::error title={case.get('classname', '')}::{case.get('name', '')}: {head}"
            )
            emitted += 1
    if not emitted:
        print("::error title=pytest::suite failed without a JUnit failure record")
    return 0


if __name__ == "__main__":
    sys.exit(main())

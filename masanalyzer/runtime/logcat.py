"""``adb logcat`` reader.

Two line shapes are accepted: the ``threadtime`` format (date, pid/tid,
level, tag, message) and the short ``V/Tag( 1234): message`` form. Anything
else -- a stack-trace continuation, a stray banner line -- is kept as part
of the previous message so exception text is not lost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

#: capture is capped: a chatty app can produce millions of lines and the
#: report only needs a bounded summary
MAX_LINES = 200_000

_RX_THREADTIME = re.compile(
    r"^(?P<ts>\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+"
    r"(?P<tag>.*?)\s*:\s(?P<msg>.*)$"
)
_RX_BRIEF = re.compile(
    r"^(?P<level>[VDIWEF])/(?P<tag>.*?)\(\s*(?P<pid>\d+)\):\s(?P<msg>.*)$"
)


@dataclass
class LogEntry:
    level: str = ""
    tag: str = ""
    pid: int = 0
    message: str = ""
    ts: str = ""

    @property
    def is_error(self) -> bool:
        return self.level in ("E", "F")


def parse_logcat(text: str) -> Tuple[List[LogEntry], List[str]]:
    """``(entries, warnings)`` from a raw logcat capture."""
    entries: List[LogEntry] = []
    warnings: List[str] = []
    skipped = 0
    for line in (text or "").splitlines()[:MAX_LINES]:
        if not line.strip():
            continue
        match = _RX_THREADTIME.match(line) or _RX_BRIEF.match(line)
        if match is None:
            # continuation of the previous entry (stack trace, JSON dump)
            if entries:
                entries[-1].message += "\n" + line
            else:
                skipped += 1
            continue
        group = match.groupdict()
        try:
            pid = int(group.get("pid") or 0)
        except ValueError:
            pid = 0
        entries.append(
            LogEntry(
                level=group.get("level") or "",
                tag=(group.get("tag") or "").strip(),
                pid=pid,
                message=group.get("msg") or "",
                ts=group.get("ts") or "",
            )
        )
    if skipped:
        warnings.append(f"logcat.txt: {skipped} line(s) before the first entry")
    return entries, warnings

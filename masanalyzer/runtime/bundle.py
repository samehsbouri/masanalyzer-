"""The session bundle: the on-disk contract between a collector and this tool.

A dynamic run is captured *outside* masanalyzer (an emulator, ``adb`` and a
proxy) and handed over as a directory::

    session/
      runtime.json     required - provenance, filesystem and hook observations
      traffic.har      optional - HAR 1.2 export from the MITM proxy
      logcat.txt       optional - ``adb logcat -v threadtime`` capture

``runtime.json``::

    {
      "schema": "masanalyzer.runtime/1",
      "session": {
        "id": "2026-11-16T10-12-00-login",
        "device": "emulator-5554",
        "api_level": 33,
        "image": "aosp_atd_x86_64",
        "flow": "login",
        "started": "...", "finished": "...",
        "tls_interception": "system-ca",
        "rooted": true,
        "notes": "proxy CA installed via -writable-system"
      },
      "files":  [{"path": "/sdcard/app.db", "sha256": "...", "size": 12288}],
      "hooks":  [{"hook": "Cipher#init", "args": ["AES/ECB/PKCS5Padding"],
                  "count": 3, "surface": "com.example.Login"}]
    }

Loading is defensive: a broken member becomes a ``warnings`` entry and the
rest still loads, the same never-abort contract the static parsers follow.
Only ``runtime.json`` is mandatory -- an unlabelled session is worthless,
so a missing or unparsable provenance file is a real error.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .har import TrafficEntry, parse_har
from .logcat import LogEntry, parse_logcat

SCHEMA = "masanalyzer.runtime/1"
SESSION_FILE = "runtime.json"
TRAFFIC_FILE = "traffic.har"
LOGCAT_FILE = "logcat.txt"


class BundleError(Exception):
    """The bundle cannot be used: no provenance or unreadable JSON."""


@dataclass
class RuntimeBundle:
    """One ingested dynamic session."""

    path: str = ""
    session: Dict[str, Any] = field(default_factory=dict)
    files: List[Dict[str, Any]] = field(default_factory=list)
    hooks: List[Dict[str, Any]] = field(default_factory=list)
    traffic: List[TrafficEntry] = field(default_factory=list)
    logcat: List[LogEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def session_id(self) -> str:
        return str(self.session.get("id") or os.path.basename(self.path) or "session")

    @property
    def has_data(self) -> bool:
        return bool(self.traffic or self.logcat or self.files or self.hooks)

    def provenance(self) -> Dict[str, Any]:
        """Session facts as they appear in the report (sorted, JSON-ready)."""
        keep = (
            "id", "device", "api_level", "image", "flow", "started", "finished",
            "tls_interception", "rooted", "collector", "notes",
        )
        return {k: self.session[k] for k in keep if k in self.session}


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def load_bundle(path: str) -> RuntimeBundle:
    """Load a session directory (or a bare ``runtime.json``)."""
    if not path:
        raise BundleError("no runtime bundle path given")
    root = os.path.abspath(path)
    if os.path.isfile(root):
        session_path = root
        base = os.path.dirname(root)
    else:
        session_path = os.path.join(root, SESSION_FILE)
        base = root
    if not os.path.exists(session_path):
        raise BundleError(f"no {SESSION_FILE} in {path!r}")

    bundle = RuntimeBundle(path=base)
    try:
        doc = _read_json(session_path)
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot read {SESSION_FILE}: {exc}") from exc
    if not isinstance(doc, dict):
        raise BundleError(f"{SESSION_FILE} must contain an object")

    schema = str(doc.get("schema") or "")
    if schema and not schema.startswith("masanalyzer.runtime/"):
        bundle.warnings.append(f"unknown bundle schema {schema!r}")
    session = doc.get("session")
    if not isinstance(session, dict) or not session:
        raise BundleError("runtime.json has no 'session' provenance object")
    bundle.session = session
    for key, bucket in (("files", bundle.files), ("hooks", bundle.hooks)):
        raw = doc.get(key)
        if isinstance(raw, list):
            bucket.extend(item for item in raw if isinstance(item, dict))

    traffic_path = os.path.join(base, TRAFFIC_FILE)
    if os.path.exists(traffic_path):
        try:
            entries, warnings = parse_har(_read_json(traffic_path))
            bundle.traffic = entries
            bundle.warnings.extend(warnings)
        except (OSError, ValueError) as exc:
            bundle.warnings.append(f"traffic.har: unreadable ({exc})")

    logcat_path = os.path.join(base, LOGCAT_FILE)
    if os.path.exists(logcat_path):
        entries, warnings = parse_logcat(_read_text(logcat_path))
        bundle.logcat = entries
        bundle.warnings.extend(warnings)
    return bundle


def empty_bundle() -> RuntimeBundle:
    """A bundle with provenance but no capture (used by tests/templates)."""
    return RuntimeBundle(path="", session={"id": "empty"})

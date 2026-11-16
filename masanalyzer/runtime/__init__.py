"""Dynamic-analysis session ingestion (thin slice).

The static pipeline reads a bundle; a collector writes one. This package
owns the read half:

>>> from masanalyzer.runtime import load_bundle, analyze_bundle
>>> bundle = load_bundle("session-login")
>>> findings, inventory = analyze_bundle(bundle, target)

Findings use the ``MAS-DYN-*`` ids and carry the ``observed`` assurance
tier (see :mod:`masanalyzer.assurance`); the inventory lands in
``report.json`` as ``inventory.runtime`` and includes the static-vs-observed
host correlation, which is the part the static layer cannot produce.
"""

from __future__ import annotations

from .bundle import (
    LOGCAT_FILE,
    SCHEMA,
    SESSION_FILE,
    TRAFFIC_FILE,
    BundleError,
    RuntimeBundle,
    empty_bundle,
    load_bundle,
)
from .collect import RULES, analyze_bundle

__all__ = [
    "BundleError",
    "RuntimeBundle",
    "SCHEMA",
    "SESSION_FILE",
    "TRAFFIC_FILE",
    "LOGCAT_FILE",
    "RULES",
    "analyze_bundle",
    "empty_bundle",
    "load_bundle",
]

"""MAS Analyzer - dependency free static security analyzer for mobile apps.

The package is intentionally stdlib-only so it can run inside CI images and
locked-down workstations where ``apktool``/``jadx``/``Java`` are unavailable.

High level API::

    import masanalyzer

    result = masanalyzer.scan("BankApp.apk")
    print(result.score.grade)        # "C"
    md = masanalyzer.reporting.render(result, "md")

"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["scan", "analyze_target", "__version__", "TOOL_NAME", "TOOL_VERSION"]


def scan(input_path: str, **kwargs):
    """Run end-to-end analysis; convenience wrapper over :mod:`.scanner`."""
    from .scanner import scan as _scan

    return _scan(input_path, **kwargs)


def analyze_target(target):
    """Analyze an already unpacked/prepared :class:`~.model.Target`."""
    from .scanner import analyze_target as _analyze

    return _analyze(target)


from .scanner import TOOL_NAME, TOOL_VERSION  # noqa: E402,F401

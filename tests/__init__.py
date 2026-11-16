"""Test suite notes.

- test_parsers.py   : dex / axml / apk / plist / macho / ipa layer
- test_packaging.py : prepare_target on synthetic APK/IPA/dir inputs
- test_analysis.py  : OWASP analyzers on synthetic targets
- test_reporting.py : renderers + scoring
- test_e2e.py       : full scan on samples/Insecure{Bank,Notes} (needs the
  sample fixtures; run `python samples/make_samples.py` first)

Every test is stdlib `unittest`; builders used to synthesize APK/IPA
fixtures live in ``masanalyzer/testing/__init__.py`` so tests stay
self-contained (they were adopted from the original smoke scripts).
"""

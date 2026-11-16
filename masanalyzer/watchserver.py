"""Local report server + re-scan watch loop (stdlib ``http.server`` only).

* :func:`serve_reports` - run a tiny local-only HTTP server on a report
  directory (binds to 127.0.0.1 unless a caller insists otherwise) so
  HTML/markdown/AUDIT reports can be browsed without leaving disk.

* :func:`watch` - re-scan the input every ``interval`` seconds and rewrite
  the reports in the output directory; useful during a finding-triage
  loop while the developer re-builds the app.
"""

from __future__ import annotations

import os
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional


def serve_reports(
    directory: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    on_ready: Optional[Callable[[str], None]] = None,
) -> ThreadingHTTPServer:
    """Serve ``directory`` over HTTP (foreground; ``server.shutdown()`` stops).

    ``port=0`` selects a free ephemeral port; callers read the realized
    port from ``server.server_address[1]``.
    """
    import functools

    directory = os.path.abspath(directory)

    class _QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *args, **kwargs):  # silence request logging
            pass

    # ``directory`` must be passed per-instance: SimpleHTTPRequestHandler's
    # __init__ ignores class attributes and defaults to os.getcwd().
    handler = functools.partial(_QuietHandler, directory=directory)
    server = ThreadingHTTPServer((host, port), handler)
    if on_ready is not None:
        on_ready(f"http://{host}:{server.server_address[1]}/")
    return server


def _rescan(
    input_path: str,
    out_dir: str,
    formats: Optional[list] = None,
) -> int:
    """One quiet re-scan writing reports into ``out_dir``."""
    from .cli import main  # local import: the CLI already writes reports

    formats = formats or ["html"]
    argv = [input_path, "-o", out_dir, "-q"]
    for fmt in formats:
        argv += ["--format", fmt]
    return main(argv)


def watch(
    input_path: str,
    out_dir: str,
    interval: float = 5.0,
    formats: Optional[list] = None,
    max_iterations: Optional[int] = None,   # substitutes Ctrl-C in tests
    on_change: Optional[Callable[[int], None]] = None,
):
    """Re-scan ``input_path`` when it (or any sibling in()) changes."""
    if formats is None:
        formats = ["html"]
    stamp = _fingerprint(input_path)
    count = 0
    while True:
        count += 1
        try:
            _rescan(input_path, out_dir, formats)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            print(f"watch: rescan failed: {exc}", flush=True)
        if on_change is not None:
            on_change(count)
        if max_iterations is not None and count >= max_iterations:
            return count
        deadline = time.time() + max(interval, 0.2)
        while time.time() < deadline:
            time.sleep(0.2)
            new_stamp = _fingerprint(input_path)
            if new_stamp != stamp:
                stamp = new_stamp
                deadline = time.time() + max(interval, 0.2)


def _fingerprint(input_path: str) -> float:
    """Mtime of the input (works for apk/ipa/dir alike)."""
    try:
        return os.stat(input_path).st_mtime
    except OSError:
        return 0.0

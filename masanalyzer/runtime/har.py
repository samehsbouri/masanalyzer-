"""HAR 1.2 reader for captured HTTP(S) traffic.

A dynamic collector exports the proxy session as HAR (a JSON document), so
the analyzer never has to parse pcap: every field we care about (method,
URL, request headers, status, body) is already a JSON scalar. Truncation
and redaction happen later, in ``collect.py`` -- this module only
normalises the shapes and never raises on a malformed entry.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

#: request/response bodies are clipped: enough for a token or a JSON key,
#: never enough to bloat report.json
MAX_BODY = 4000


@dataclass
class TrafficEntry:
    """One request/response pair from the capture."""

    method: str = "GET"
    url: str = ""
    host: str = ""
    scheme: str = ""
    path: str = "/"
    status: int = 0
    mime: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    post_data: str = ""
    response_body: str = ""
    started: str = ""

    @property
    def cleartext(self) -> bool:
        return self.scheme == "http"

    @property
    def label(self) -> str:
        """``GET /path`` with the query string stripped (safe to print)."""
        return f"{self.method} {self.path}"


def _headers(raw: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            out[name] = str(item.get("value") or "")
    return out


def _split(url: str) -> Tuple[str, str, str]:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "", "", "/"
    return (parts.hostname or "").lower(), (parts.scheme or "").lower(), (
        parts.path or "/"
    )


def parse_har(doc: Any) -> Tuple[List[TrafficEntry], List[str]]:
    """``(entries, warnings)`` from a parsed HAR document."""
    warnings: List[str] = []
    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict):
        return [], ["traffic.har: no 'log' object"]
    raw = log.get("entries")
    if not isinstance(raw, list):
        return [], ["traffic.har: no 'log.entries' list"]

    entries: List[TrafficEntry] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            warnings.append(f"traffic.har: entry {index} is not an object")
            continue
        request = item.get("request")
        if not isinstance(request, dict):
            warnings.append(f"traffic.har: entry {index} has no request")
            continue
        url = str(request.get("url") or "")
        if not url:
            warnings.append(f"traffic.har: entry {index} has no url")
            continue
        host, scheme, path = _split(url)
        response = item.get("response")
        if not isinstance(response, dict):
            response = {}
        content = response.get("content")
        if not isinstance(content, dict):
            content = {}
        body = content.get("text")
        post = request.get("postData")
        entries.append(
            TrafficEntry(
                method=str(request.get("method") or "GET").upper(),
                url=url,
                host=host,
                scheme=scheme,
                path=path or "/",
                status=int(response.get("status") or 0),
                mime=str(content.get("mimeType") or response.get("mimeType") or ""),
                request_headers=_headers(request.get("headers")),
                post_data=(str(post.get("text") or "") if isinstance(post, dict)
                           else str(post or ""))[:MAX_BODY],
                response_body=(str(body) if body else "")[:MAX_BODY],
                started=str(item.get("startedDateTime") or ""),
            )
        )
    if not entries and raw:
        warnings.append("traffic.har: no usable entries")
    return entries, warnings

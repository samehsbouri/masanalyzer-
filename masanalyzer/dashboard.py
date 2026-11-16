"""Local web dashboard: upload a bundle, run a scan, browse + download reports.

Pure stdlib (``http.server`` + ``ThreadingHTTPServer``).  Binds to
``127.0.0.1`` by default — it is a *local* analyst workbench, not a
multi-user service (no authentication by design; do not expose it).

Layout on disk (``--workdir``, default ``<temp>/masan_dashboard``)::

    jobs/<32-hex-id>/
        upload.<ext>          the uploaded bundle
        report.json|.md|.html|.pdf|.sarif|.sbom|.audit|.csv|.junit|.gitlab
        job.json              job metadata (survives dashboard restarts)

Routes
------
``GET  /``                    board: every scan as a card, live totals
``GET  /upload``              upload page (drop zone + limits + recents)
``GET  /settings``            display preferences (board refresh, reports
                              preview) + read-only runtime facts
``POST /settings``            form-encoded preferences, saved to
                              ``<workdir>/settings.json``, then redirects
``GET  /scanning/<id>``       live progress for a queued/running job
``GET  /reports/<id>``        all ten formats, sizes, previews + downloads
``GET  /jobs``                JSON list of all jobs
``GET  /job/<id>``            JSON for one job
``GET  /overview/<id>``       at-a-glance fact page (file/app/signature/
                              permissions/surface) built from report.json
``POST /upload``              multipart/form-data, field ``file``
``GET  /view/<id>/<fmt>``      styled viewer page for ``json``/``md``/``sarif``
                              (collapsible JSON tree, rendered Markdown,
                              SARIF triage table); raw bodies remain at
                              ``/report/<id>/<fmt>``
``GET  /report/<id>/<fmt>``   render a report inline (fmt from FORMATS)
``GET  /download/<id>/<fmt>`` same body as an attachment download

Every page shares one soft-canvas theme (white rounded cards on a lilac-grey
canvas, pill navigation, a circular icon rail).  No external assets: SVG
icons are inline, avatars are coloured initials.
"""

from __future__ import annotations

import html
import json
import os
import queue
import re
import sys
import tempfile
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs

from . import __version__ as TOOL_VERSION
from .reporting import FORMATS

_EXTENSIONS = (".apk", ".ipa", ".aab", ".apks", ".zip", ".bin")
_MAX_NAME = 150

_STATUS_OK = "done"
_STATUS_ERR = "error"
_STATUS_RUN = "running"
_STATUS_QUEUED = "queued"

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SEV_CLASS = {
    "critical": "red", "high": "red", "medium": "amber",
    "low": "green", "info": "grey",
}
#: endpoint/privacy classification -> pill colour
_ENDPOINT_PILL = {
    "tracker": "red", "cleartext": "amber", "private": "amber",
    "first_party": "blue", "local": "grey", "public": "grey",
}
_FORMAT_LABEL = {
    "json": "JSON", "md": "MD", "html": "HTML", "pdf": "PDF",
    "sarif": "SARIF", "sbom": "SBOM", "audit": "AUDIT",
    "csv": "CSV", "junit": "JUNIT", "gitlab": "GITLAB",
}
_FORMAT_NOTE = {
    "json": "Full machine document — every other format is rendered from it.",
    "md": "Readable report: category table, attack surface, finding cards.",
    "html": "Single-file styled report, safe to open offline.",
    "pdf": "Print-ready cover, score card and severity bars.",
    "sarif": "SARIF 2.1.0 with locations for code scanning.",
    "sbom": "CycloneDX inventory of the bundled components.",
    "audit": "MASVS requirement matrix: pass / fail / n-a.",
    "csv": "One row per finding with stable columns.",
    "junit": "JUnit XML for CI test reporters.",
    "gitlab": "GitLab code-quality JSON with fingerprints.",
}


# --------------------------------------------------------------------------
# shared theme (soft canvas, white cards, pill nav, circular rail)
# --------------------------------------------------------------------------
_B_CSS = r"""
:root{
  --canvas-a:#eceef3; --canvas-b:#d6d8e0; --canvas-c:#e3e5ec;
  --panel:rgba(255,255,255,.45); --panel-2:rgba(255,255,255,.62);
  --card:#ffffff; --ink:#10141A; --ink-2:#3c4048; --muted:#83878f; --faint:#a8abb3;
  --line:#eceef3; --line-2:#f4f5f8;
  --blue:#83A2DB; --blue-deep:#5f7fc4; --blue-soft:#eef2fb;
  --rose:#CE6969; --rose-deep:#b45252; --rose-soft:#fbeaea;
  --mint:#9FC9AE; --mint-deep:#5d8a6d; --sand:#E8C9A0;
  --shadow-card:0 26px 48px -38px rgba(16,20,26,.55),0 2px 6px rgba(16,20,26,.04);
  --shadow-panel:0 40px 80px -60px rgba(16,20,26,.55);
  --sans:"Segoe UI Variable Display","Segoe UI","Avenir Next",system-ui,-apple-system,sans-serif;
  --mono:"JetBrains Mono","Cascadia Code",Consolas,monospace;
  --ease-out:cubic-bezier(.22,.9,.28,1);
  --ease-spring:cubic-bezier(.34,1.4,.64,1);
}
*{box-sizing:border-box}
html,body{margin:0}
body{color:var(--ink);font:13px/1.55 var(--sans);min-height:100vh;
  background:
    radial-gradient(90% 70% at 12% 0%,#f4f5f8 0%,transparent 55%),
    radial-gradient(80% 60% at 88% 6%,#e9ebf1 0%,transparent 60%),
    linear-gradient(168deg,var(--canvas-a) 0%,var(--canvas-c) 45%,var(--canvas-b) 100%);
  -webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
svg{display:block}
code,.mono{font-family:var(--mono)}

.topbar{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:26px;
  padding:16px max(30px,calc(50% - 690px)) 14px max(30px,calc(50% - 624px));
  background:linear-gradient(#eceef3f2,#eceef300);backdrop-filter:blur(6px)}
.brand{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;
  letter-spacing:-.02em;padding-right:20px;white-space:nowrap}
.brand .mark{width:26px;height:26px;display:grid;place-items:center;color:var(--ink)}
.nav{display:flex;align-items:center;gap:4px;margin:0 auto;flex-wrap:nowrap;
  overflow-x:auto;scrollbar-width:none}
.nav::-webkit-scrollbar{display:none}
.nav a{font-size:13px;color:#4d5159;padding:9px 15px;border-radius:999px;
  white-space:nowrap;transition:background .18s,color .18s}
.nav a:hover{background:#ffffffa8}
.nav a.on{background:#10141A;color:#fff;box-shadow:0 10px 22px -16px #10141a}
.actions{display:flex;align-items:center;gap:8px;flex:none}
.circle{width:36px;height:36px;border-radius:50%;background:#ffffffb8;display:grid;
  place-items:center;color:#3c4048;transition:background .18s,transform .18s}
.circle:hover{background:#fff;transform:translateY(-1px)}
.circle .dotred{position:absolute;top:7px;right:8px;width:6px;height:6px;border-radius:50%;
  background:var(--rose);box-shadow:0 0 0 2px #fff}
.me{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;
  background:linear-gradient(150deg,#cfd7e8,#a9b6d3);color:#2c3342;font-size:11px;
  font-weight:600;box-shadow:0 0 0 2px #fff9}

.rail{position:fixed;top:104px;width:52px;border-radius:26px;
  left:max(18px,calc(50% - 702px));
  background:#ffffffa6;box-shadow:var(--shadow-card);backdrop-filter:blur(10px);
  display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 0;
  z-index:35;max-height:calc(100vh - 140px)}
.rail a{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;
  color:#5b6069;position:relative;transition:background .16s,color .16s}
.rail a:hover,.rail a.on{background:#f1f2f6;color:var(--ink)}
.rail .spacer{height:6px;flex:none}
.rail .mode{width:38px;height:38px;border-radius:50%;background:#10141A;color:#fff;
  display:grid;place-items:center}

.wrap{margin:0 auto;max-width:1440px;padding:2px 30px 44px 96px}
.pagehead{display:flex;align-items:flex-end;gap:18px;padding:14px 2px 22px;flex-wrap:wrap}
h1{margin:0;font-size:34px;line-height:1.1;font-weight:600;letter-spacing:-.035em}
.pagehead h1{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.pagehead p{margin:7px 0 0;color:#6d717a;font-size:12.5px}
.pagehead .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.crumb{display:flex;align-items:center;gap:7px;font-size:11px;color:#8a8e96;
  margin-bottom:9px}
.crumb a:hover{color:var(--ink)}
.ghostbtn{height:36px;border-radius:999px;padding:0 16px;background:#ffffffb8;
  font-size:12.5px;color:#3c4048;display:inline-flex;align-items:center;gap:8px}
.ghostbtn:hover{background:#fff}
.darkbtn{height:36px;border-radius:999px;padding:0 18px;background:#10141A;color:#fff;
  font-size:12.5px;display:inline-flex;align-items:center;gap:8px;
  box-shadow:0 14px 26px -18px #10141a}
.darkbtn:hover{background:#1c222c}

.panel{background:var(--panel);border-radius:36px;box-shadow:var(--shadow-panel);
  backdrop-filter:blur(18px);padding:22px 24px 24px;border:1px solid #ffffff70;
  margin-bottom:16px}
.softpanel{background:var(--panel-2);border-radius:30px;box-shadow:var(--shadow-panel);
  backdrop-filter:blur(16px);border:1px solid #ffffff88;padding:18px 20px 16px}
.card{background:#fff;border-radius:26px;box-shadow:var(--shadow-card);padding:17px 18px 16px}
.panel-h{display:flex;align-items:center;gap:14px;padding-bottom:14px;flex-wrap:wrap}
.panel-h h2{margin:0;font-size:15px;font-weight:600;letter-spacing:-.02em}
.panel-h .sub{font-size:11.5px;color:#8a8e96}
.panel-tools{margin-left:auto;display:flex;gap:7px}
.tool{width:32px;height:32px;border-radius:50%;background:#ffffffd0;display:grid;
  place-items:center;color:#4d5159;box-shadow:0 1px 2px #10141a0f}
.tool:hover{background:#fff}
.card h3{margin:0 0 12px;font-size:12.5px;font-weight:600;display:flex;align-items:center;
  gap:8px;flex-wrap:wrap}
.card h3 .pill{margin-left:auto}
.ctog{margin-left:8px;flex:none;width:24px;height:24px;border-radius:50%;
  background:#f4f5f8;display:grid;place-items:center;color:#8a8e96;
  transition:background .16s,transform .2s var(--ease-out)}
.ctog:hover{background:#eceef3;color:var(--ink)}
.ctog:focus-visible{outline:2px solid #83a2db;outline-offset:2px}
.ctog svg{transition:transform .2s var(--ease-out)}
.card.collapsed .ctog svg{transform:rotate(-90deg)}
.card.collapsed > *:not(h3):not(.fndhead){display:none}
.card.collapsed{padding-bottom:14px}

.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;
  font-size:9.5px;font-weight:500;white-space:nowrap}
.pill.red{background:var(--rose-soft);color:var(--rose-deep)}
.pill.blue{background:var(--blue-soft);color:var(--blue-deep)}
.pill.grey{background:#f2f3f6;color:#7b8089}
.pill.green{background:#eaf3ed;color:var(--mint-deep)}
.pill.amber{background:#f8efdf;color:#a97845}
.pill.dark{background:#10141A;color:#fff}
.av{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;
  font-size:10px;font-weight:600;color:#252a33;flex:none;letter-spacing:.02em}
.av.lg{width:58px;height:58px;font-size:14px}
.av.sm{width:26px;height:26px;font-size:8px}
.av.appicon{object-fit:cover;background:#f2f3f6;box-shadow:0 0 0 1px #10141a0f;
  display:block}
.jobicon{border-radius:15px;flex:none;object-fit:cover;display:grid;
  place-items:center;background:#f2f3f6;color:#252a33;font-weight:600;
  box-shadow:0 0 0 1px #10141a0f,0 8px 18px -14px #10141a66;letter-spacing:0}
.b1{background:linear-gradient(150deg,#dfe6f4,#bcc9e4)}
.b2{background:linear-gradient(150deg,#f2dfdc,#d9b3ae)}
.b3{background:linear-gradient(150deg,#e2ecdf,#bfd3bd)}
.b4{background:linear-gradient(150deg,#f4e8d4,#dcc4a2)}
.b5{background:linear-gradient(150deg,#e6e1f4,#c5bce0)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--mint);flex:none}
.mono{font-family:var(--mono);font-size:10.5px;color:#7b8089}
.foot{display:flex;justify-content:space-between;gap:14px;margin:22px 4px 0;
  font-size:10.5px;color:#9aa0a8;flex-wrap:wrap}

.grade{width:40px;height:40px;border-radius:50%;display:grid;place-items:center;
  font-size:15px;font-weight:600;position:relative;flex:none}
.grade.g-a{background:#eaf3ee;color:var(--mint-deep)}
.grade.g-b{background:#f7efe2;color:#a97845}
.grade.g-c{background:#fbeaea;color:var(--rose-deep)}
.grade.g-d{background:#fbeaea;color:var(--rose-deep)}
.grade.g-f{background:#f7dfe0;color:#933f3f}
.grade.g-none{background:#f2f3f6;color:#9aa0a8}
.bar{display:flex;height:6px;border-radius:4px;overflow:hidden;background:#f2f3f6}
.bar i{display:block;height:100%}
.bar .c{background:var(--rose)}.bar .h{background:#d9a173}
.bar .m{background:#e2c98c}.bar .l{background:var(--mint)}
.bar .i{background:#c9cdd6}

.donut{text-align:center}
.donut svg{margin:0 auto}
.donut circle{transform-box:fill-box;transform-origin:center;transform:rotate(-90deg)}
.donut .track{fill:none;stroke:#eef0f5}
.donut .arc{fill:none;stroke-linecap:round}
.donut .cap{font-size:21px;font-weight:600;letter-spacing:-.03em;fill:var(--ink)}
.donut .cap2{font-size:7px;letter-spacing:.08em;fill:#a8abb3}
.donut-label{font-size:10px;color:#8a8e96;margin-top:6px;line-height:1.3}
.donut-label b{display:block;color:var(--ink);font-size:10.5px;font-weight:600}

.factrow{display:grid;grid-template-columns:132px minmax(0,1fr);gap:10px;
  padding:8px 0;border-top:1px solid #f4f5f8;font-size:11.5px}
.factrow:first-child{border-top:0}
.factrow dt{color:#8a8e96;margin:0}
.factrow dd{margin:0;color:#3c4048;overflow-wrap:anywhere;min-width:0}
.factrow dd code{font-family:var(--mono);font-size:10px;color:#4d5159;word-break:break-all}

.tbl{width:100%;border-collapse:collapse;font-size:11.5px}
.tbl th{text-align:left;font-size:9.5px;letter-spacing:.07em;text-transform:uppercase;
  color:#9aa0a8;font-weight:500;padding:6px 8px 9px;border-bottom:1px solid #eceef3}
.tbl td{padding:8px;border-bottom:1px solid #f4f5f8;color:#4d5159;vertical-align:top}
.tbl tr:last-child td{border-bottom:0}
.tbl code{font-family:var(--mono);font-size:10px;color:#3c4048;word-break:break-all}
.tbl b{color:var(--ink);font-weight:600}
.fnd .fndhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fnd .fndhead h3{margin:0;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.fnd .fndmeta{margin:8px 0 0;font-size:10.5px;color:#8a8e96}
.fnd pre{background:#fbfcfe;border:1px solid #f1f3f8;border-radius:12px;padding:10px 12px;
  margin:6px 0 0;font-family:var(--mono);font-size:10.5px;line-height:1.55;
  color:#3c4048;overflow-x:auto}
.fnd b{color:var(--ink);font-weight:600}
.sevbar{display:flex;align-items:center;gap:8px;margin:4px 2px 8px;font-size:10px;
  color:#8a8e96;text-transform:uppercase;letter-spacing:.07em}
.sevbar button{text-transform:none;letter-spacing:0;font-size:10.5px}
.sevfilter{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.sevfilter button{display:inline-flex;align-items:center;gap:5px;cursor:pointer;
  background:#fff;border:1px solid #eceef3;border-radius:999px;padding:4px 10px;
  font-size:10.5px;color:#5c6169;transition:background .16s,color .16s,border-color .16s}
.sevfilter button span{font-family:var(--mono);font-size:9.5px;color:#a8abb3}
.sevfilter button:hover{background:#f7f8fb;color:var(--ink)}
.sevfilter button.on{background:#10141A;border-color:#10141A;color:#fff}
.sevfilter button.on span{color:#c9cdd6}
.sevfilter button:focus-visible{outline:2px solid #83a2db;outline-offset:2px}
.sevgroup{display:block;margin:0 0 12px;position:relative}
.sevgroup summary{position:sticky;top:64px;z-index:12;
  display:flex;align-items:center;gap:9px;cursor:pointer;
  background:#fff;border-radius:16px;padding:10px 14px;list-style:none;
  font-size:12px;color:#4d5159;
  box-shadow:0 2px 6px rgba(16,20,26,.04),0 0 0 1px rgba(16,20,26,.02)}
.sevgroup summary::-webkit-details-marker{display:none}
.sevgroup summary:hover{background:#fff;transform:translateY(-1px)}
.sevgroup summary:focus-visible{outline:2px solid #83a2db;outline-offset:3px}
.sevgroup summary b{color:var(--ink);font-weight:600}
.sevgroup summary .chev{transition:transform .2s var(--ease-out);color:#a8abb3}
.sevgroup:not([open]) summary .chev{transform:rotate(-90deg)}
.sevgroup[open] summary{margin-bottom:10px}
.sevbody{display:flex;flex-direction:column;gap:10px}

.meter{height:6px;border-radius:4px;background:#eef0f5;overflow:hidden}
.meter i{display:block;height:100%;background:linear-gradient(90deg,#9db8e6,#5f7fc4);
  border-radius:4px}
.meter.indet i{width:36%;animation:indet 1.8s ease-in-out infinite}
@keyframes indet{0%{margin-left:-36%}100%{margin-left:100%}}

.jobs{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));
  gap:14px}
.jobcard{display:flex;flex-direction:column;gap:11px;cursor:pointer;
  transition:transform .18s,box-shadow .18s}
.jobcard:focus-visible{outline:2px solid #83a2db;outline-offset:3px}
.jobcard:hover{transform:translateY(-2px);
  box-shadow:0 34px 54px -42px rgba(16,20,26,.6),0 3px 10px rgba(16,20,26,.05)}
.jhead{display:flex;align-items:center;gap:10px;min-width:0}
.jhead .who{min-width:0}
.jhead .who b{display:block;font-size:12.5px;font-weight:600;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.jhead .who span{font-family:var(--mono);font-size:9.5px;color:#a8abb3}
.jhead .pill{margin-left:auto}
.jmid{display:flex;align-items:center;gap:12px}
.jmid .grow{flex:1;min-width:0}
.sevrow{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}
.jfoot{display:flex;align-items:center;gap:8px;border-top:1px solid #f4f5f8;
  padding-top:10px;margin-top:2px;font-size:10.5px;color:#8a8e96}
.jfoot .go{margin-left:auto;color:var(--ink);display:inline-flex;align-items:center;gap:5px}
.jfoot .go:hover{color:var(--blue-deep)}
.jmeta{font-size:10.5px;color:#8a8e96}
.jerr{color:var(--rose-deep)}
.empty{padding:26px 8px;color:#8a8e96;font-size:12px}

.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(188px,1fr));
  gap:12px}
.metrics .m{background:#fff;border-radius:22px;box-shadow:var(--shadow-card);padding:13px 15px}
.metrics .m > span{font-size:8.5px;letter-spacing:.08em;text-transform:uppercase;color:#a8abb3}
.metrics .m b{display:block;font-size:24px;font-weight:600;letter-spacing:-.04em;margin-top:2px}
.metrics .m b small{font-size:10px;color:#a8abb3;font-weight:400;letter-spacing:0}
.metrics .m p{margin:2px 0 0;font-size:10px;color:#a8abb3}

.grid2{display:grid;grid-template-columns:minmax(0,1fr) 322px;gap:16px;align-items:start}
.stack{display:flex;flex-direction:column;gap:16px}
.side{display:flex;flex-direction:column;gap:14px;position:sticky;top:88px}

.dropcard{padding:26px;display:flex;flex-direction:column;align-items:center;text-align:center;
  border:1px dashed #d9dfea;background:radial-gradient(120% 130% at 50% 0%,#fff,#f7f9fc)}
.dropglyph{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;
  background:#f2f5fb;color:var(--blue-deep);margin-bottom:14px;position:relative}
.dropglyph::after{content:"";position:absolute;inset:-8px;border-radius:50%;
  border:1px dashed #dfe4ee}
.dropcard h2{margin:0;font-size:18px;font-weight:600;letter-spacing:-.025em}
.dropcard p{margin:7px 0 0;font-size:11.5px;color:#7b8089;max-width:44ch;line-height:1.55}
.dropcard .filepick{margin-top:12px;font-family:var(--mono);font-size:10px;color:#6d717a}
.formats{display:flex;gap:6px;margin-top:16px;flex-wrap:wrap;justify-content:center}
.fmt{font-family:var(--mono);font-size:9.5px;color:#767a83;background:#fff;
  border:1px solid #e7eaf1;border-radius:6px;padding:3px 8px}
.limits{margin-top:12px;font-size:10px;color:#a8abb3}

.steps{display:grid;grid-template-columns:repeat(4,1fr);margin:2px 0 16px}
.step{position:relative;min-width:0}
.step::before{content:"";position:absolute;top:9px;left:22px;right:0;height:2px;background:#e9ebf2}
.step:last-child::before{display:none}
.step.done::before{background:#cfe3d6}
.sd{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;
  background:#f1f3f8;color:#a8abb3;position:relative;z-index:1}
.step.done .sd{background:var(--mint);color:#fff}
.step.run .sd{background:var(--blue);color:#fff;box-shadow:0 0 0 4px #83a2db2e}
.step b{display:block;font-size:11px;font-weight:600;margin-top:8px}
.step small{display:block;font-size:9px;color:#a8abb3;margin-top:1px}
.step.run b{color:var(--blue-deep)}
.live{display:inline-flex;align-items:center;gap:5px;font-size:9px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--blue-deep)}
.live i{width:5px;height:5px;border-radius:50%;background:var(--blue);
  animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35;transform:scale(.85)}50%{opacity:1;transform:scale(1)}}
.log{background:#fbfcfe;border:1px solid #f1f3f8;border-radius:14px;padding:11px 13px;
  font-family:var(--mono);font-size:10px;line-height:1.9;color:#5c6169;
  max-height:250px;overflow:auto}
.log div{white-space:pre-wrap}
.log .ts{color:#c3c7cf}
.log .ph{color:var(--blue-deep)}
.log .ok{color:var(--mint-deep)}
.log .er{color:var(--rose-deep)}
.log .cursor{display:inline-block;width:6px;height:11px;background:#83A2DB;
  vertical-align:-1px;animation:pulse 1.1s steps(2) infinite}

.fmtgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));
  gap:14px}
.fmtcard{display:flex;flex-direction:column;gap:10px}
.fmtcard .fh{display:flex;align-items:center;gap:9px;min-width:0}
.badge{font-family:var(--mono);font-size:8.5px;letter-spacing:.08em;text-transform:uppercase;
  background:#f2f3f6;border-radius:6px;padding:3px 7px;color:#6a6f78;flex:none}
.badge.dark{background:#10141A;color:#fff}
.fmtcard .fh b{font-size:12.5px;font-weight:600;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.fmtcard .size{margin-left:auto;font-family:var(--mono);font-size:9px;color:#b3b7be}
.fmtcard .note{font-size:10.5px;color:#8a8e96;line-height:1.45}
.fmtcard .acts{display:flex;gap:6px;margin-top:auto;padding-top:2px}
.mini{height:28px;padding:0 12px;border-radius:999px;font-size:10.5px;display:inline-flex;
  align-items:center;gap:6px}
.mini.ghost{background:#f4f5f8;color:#5c6169}
.mini.ghost:hover{background:#eceef3;color:var(--ink)}
.mini.dark{background:#10141A;color:#fff}
.mini.dark:hover{background:#1c222c}
.previewframe{margin-top:16px;background:#fff;border-radius:26px;box-shadow:var(--shadow-card);
  padding:14px;display:flex;flex-direction:column;gap:10px}
.previewframe iframe{width:100%;height:440px;border:1px solid #f1f3f8;border-radius:14px;
  background:#fff}
.previewtabs{display:flex;gap:6px;flex-wrap:wrap}
.previewtabs a{font-family:var(--mono);font-size:9.5px;color:#6a6f78;padding:5px 9px;
  border-radius:8px;background:#f6f7fa}
.previewtabs a.on{background:#10141A;color:#fff}

.md{font-size:13px;line-height:1.72;color:#2f333a}
.md h1{font-size:22px;letter-spacing:-.03em;margin:0 0 10px}
.md h2{font-size:15px;margin:24px 0 8px;padding-bottom:6px;border-bottom:1px solid #f1f2f6}
.md h3{font-size:13px;margin:18px 0 6px;font-weight:600}
.md h4{font-size:12px;margin:14px 0 5px}
.md p{margin:8px 0}
.md code{font-family:var(--mono);font-size:10.5px;background:#f6f7fa;border-radius:4px;
  padding:1px 4px;color:#4d5159}
.md pre{background:#fbfcfe;border:1px solid #f1f3f8;border-radius:12px;padding:10px;
  overflow:auto;font-size:10px}
.md table{width:100%;border-collapse:collapse;font-size:11.5px;margin:10px 0}
.md th{text-align:left;font-size:9.5px;text-transform:uppercase;letter-spacing:.06em;
  color:#9aa0a8;font-weight:500;border-bottom:1px solid #eceef3;padding:6px 8px 8px}
.md td{padding:7px 8px;border-bottom:1px solid #f4f5f8;color:#4d5159;vertical-align:top}
.md ul,.md ol{padding-left:18px;margin:8px 0}
.md li{margin:3px 0}
.md a{color:var(--blue-deep);text-decoration:underline;text-underline-offset:2px}
.md hr{border:0;border-top:1px solid #eef0f5;margin:16px 0}
.md .tw{overflow-x:auto}

.anchorlist{display:flex;flex-direction:column;gap:2px}
.anchorlist a{font-size:11px;color:#5c6169;padding:6px 9px;border-radius:8px;
  display:flex;align-items:center;gap:7px}
.anchorlist a:hover{background:#f6f7fa;color:var(--ink)}
.anchorlist a::before{content:"";width:4px;height:4px;border-radius:50%;background:#c9cdd6}

.tree{font-family:var(--mono);font-size:10.5px;line-height:1.6;color:#3c4048}
.tree .n{display:flex;gap:6px;align-items:baseline;padding:1px 6px;border-radius:6px;cursor:default}
.tree .n:hover{background:#f6f7fa}
.tree .tog{color:#a8abb3;cursor:pointer;user-select:none;width:1em;flex:none}
.tree .tog:hover{color:var(--blue-deep)}
.tree .k{color:#2f3540}
.tree .vs{color:#5d8a6d;white-space:pre-wrap;word-break:break-all}
.tree .vn{color:#a97845}
.tree .vb{color:#7a6bb0}
.tree .v0{color:#a8abb3}
.tree .vp{color:#a8abb3;font-style:italic}
.tree .kids{margin-left:12px;border-left:1px dashed #eef0f5;padding-left:4px}
.tree .more{color:var(--blue-deep);cursor:pointer;padding:2px 6px}
#pathbar{position:sticky;bottom:0;background:#fff;border:1px solid #eef0f5;
  border-radius:10px;padding:6px 10px;font-family:var(--mono);font-size:10px;
  color:#4d5159;white-space:nowrap;overflow-x:auto;margin-top:8px}
#searchres{max-height:16rem;overflow-y:auto;margin-top:6px}
#searchres .sr{padding:4px 8px;border-radius:8px;cursor:pointer;font-family:var(--mono);
  font-size:10px;color:#4d5159}
#searchres .sr:hover{background:#f6f7fa}
#searchres .sr b{color:var(--blue-deep);font-weight:600}
.searchbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.searchbar input{background:#fbfcfe;border:1px solid #eceef3;border-radius:999px;
  padding:8px 14px;font:inherit;font-size:11.5px;min-width:240px;color:var(--ink)}
.searchbar input:focus{outline:2px solid #83a2db55;border-color:#83a2db}
.searchbar button{background:#f4f5f8;border-radius:999px;padding:7px 13px;
  font-size:11px;color:#5c6169}
.searchbar button:hover{background:#eceef3;color:var(--ink)}

.chip{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;
  font-size:9.5px;font-weight:500;background:#f2f3f6;color:#7b8089}
.chip.lv-error{background:var(--rose-soft);color:var(--rose-deep)}
.chip.lv-warning{background:#f8efdf;color:#a97845}
.chip.lv-note{background:#f2f3f6;color:#7b8089}
.chip.gA,.chip.gB{background:#eaf3ed;color:var(--mint-deep)}
.chip.gC{background:#f8efdf;color:#a97845}
.chip.gD,.chip.gE,.chip.gF{background:var(--rose-soft);color:var(--rose-deep)}

details{border:1px solid #f1f3f8;border-radius:14px;padding:8px 12px;margin:8px 0;
  background:#fbfcfe}
details summary{cursor:pointer;font-size:11.5px;color:#4d5159}
details p{font-size:11px;color:#6d717a}

pre{font-family:var(--mono)}

/* ----------------------------------------------------------------------
   motion & interaction
   squash/stretch = press states · anticipation = hover lift before press
   staging = pill nav + staggered rise · pose-to-pose = stepper keyframes
   follow-through = spring settles + toast overshoot · slow in/out = easings
   arcs = toast rotation · secondary actions = shadows, marching dashes
   snappy timing = 120-320 ms · exaggerated feedback = finish toast + pop
   3D = card tilt on hover · Fitts = 44 px targets · Miller = grouped formats
   ---------------------------------------------------------------------- */
@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.985)}
  to{opacity:1;transform:none}}
@keyframes pop{0%{transform:scale(.965)}55%{transform:scale(1.014)}100%{transform:none}}
@keyframes checkin{0%{transform:scale(.4);opacity:0}
  60%{transform:scale(1.16);opacity:1}100%{transform:scale(1)}}
@keyframes toastIn{0%{opacity:0;transform:translate(18px,14px) rotate(2.5deg) scale(.94)}
  60%{opacity:1;transform:translate(-2px,-2px) rotate(-.6deg) scale(1.01)}
  100%{opacity:1;transform:none}}
@keyframes toastOut{to{opacity:0;transform:translateY(6px) scale(.97)}}
@keyframes shimmer{to{background-position:-200% 0}}
@keyframes march{to{background-position:24px 0}}
.stage > *{animation:rise 320ms var(--ease-out) both}
.stage > *:nth-child(2){animation-delay:45ms}
.stage > *:nth-child(3){animation-delay:90ms}
.stage > *:nth-child(4){animation-delay:135ms}
.stage > *:nth-child(5){animation-delay:180ms}
.stage > *:nth-child(n+6){animation-delay:220ms}
.jobcard.pop{animation:pop 340ms var(--ease-spring)}
.ghostbtn,.darkbtn,.mini,.tool,.circle,.nav a,.rail a,.copy,
.previewtabs a{transition:transform 120ms var(--ease-out),
  background 200ms var(--ease-out),box-shadow 200ms var(--ease-out),
  color 160ms var(--ease-out)}
.ghostbtn:hover,.darkbtn:hover,.mini:hover{transform:translateY(-1px)}
.ghostbtn:active,.darkbtn:active,.mini:active,.copy:active,
.previewtabs a:active{transform:translateY(0) scale(.955)}
.darkbtn:active{box-shadow:0 6px 14px -12px #10141a}
.nav a:active{transform:scale(.965)}
.circle:hover,.tool:hover{transform:translateY(-1px) scale(1.03)}
button.circle,button.me{border:0;padding:0;font:inherit;cursor:pointer}
.acc{position:relative;display:flex}
.menu{position:absolute;right:0;top:calc(100% + 10px);width:238px;background:#fff;
  border-radius:16px;padding:6px;z-index:60;box-shadow:0 30px 60px -34px rgba(16,20,26,.5),
  0 2px 6px rgba(16,20,26,.05);animation:pop .18s var(--ease-spring)}
.menu[hidden]{display:none}
.menuhead{display:flex;gap:10px;align-items:center;padding:8px 10px 10px;
  border-bottom:1px solid #f1f3f8;margin-bottom:6px}
.menuhead b{display:block;font-size:12px;color:var(--ink)}
.menuhead span{display:block;font-size:10px;color:#a8abb3}
.menu a,.menu button{display:flex;align-items:center;gap:8px;width:100%;border:0;
  background:transparent;padding:8px 10px;border-radius:10px;font:inherit;font-size:11.5px;
  color:#3c4048;text-align:left;cursor:pointer;transition:background .15s}
.menu a:hover,.menu button:hover{background:#f4f5f8}
.menu .sep{height:1px;background:#f1f3f8;margin:6px 4px}
.me.sm{width:30px;height:30px;font-size:11px;flex:none}
.cmdk{position:fixed;inset:0;z-index:90;display:flex;align-items:flex-start;
  justify-content:center;padding:12vh 20px;background:rgba(16,20,26,.26);
  backdrop-filter:blur(3px)}
.cmdk[hidden]{display:none}
.cmdkbox{width:min(560px,100%);background:#fff;border-radius:20px;overflow:hidden;
  box-shadow:0 40px 80px -30px rgba(16,20,26,.5);animation:pop .22s var(--ease-spring)}
.cmdkhead{display:flex;align-items:center;gap:10px;padding:14px 16px;
  border-bottom:1px solid #f1f3f8;color:#a8abb3}
.cmdkhead input{flex:1;border:0;outline:0;background:transparent;font:inherit;
  font-size:13.5px;color:var(--ink)}
.cmdkl{max-height:320px;overflow:auto;padding:6px}
.cmdkl button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;
  border:0;background:transparent;padding:9px 12px;border-radius:11px;cursor:pointer;
  font:inherit;font-size:12px;color:#3c4048}
.cmdkl button.on,.cmdkl button:hover{background:#f4f5f8}
.cmdkl .k{margin-left:auto;font-family:var(--mono);font-size:9.5px;color:#a8abb3}
.cmdkl .empty{padding:14px 12px;font-size:11.5px;color:#8a8e96}
.cmdktip{border-top:1px solid #f1f3f8;padding:8px 14px;font-size:10px;color:#a8abb3}
.circle:active,.tool:active{transform:scale(.94)}
.rail a:hover{transform:translateY(-1px)}
.rail a:active{transform:scale(.92)}
.card,.metrics .m,.jobcard,.fmtcard{transition:transform 220ms var(--ease-out),
  box-shadow 220ms var(--ease-out)}
.jobcard:hover,.fmtcard:hover{transform:perspective(900px) translateY(-3px)
  rotateX(1.1deg);box-shadow:0 34px 54px -42px rgba(16,20,26,.6),
  0 3px 10px rgba(16,20,26,.05)}
.metrics .m:hover{transform:translateY(-2px)}
.jobcard:active{transform:perspective(900px) translateY(-1px) scale(.995)}
.darkbtn,.ghostbtn,.mini{min-height:36px}
.blackbtn:focus-visible,.nav a:focus-visible,.copy:focus-visible,
.rail a:focus-visible{outline:2px solid #83a2db;outline-offset:2px}
.searchbar input,.panel-tools input{transition:box-shadow 200ms var(--ease-out),
  border-color 200ms var(--ease-out)}
.searchbar input:focus,.panel-tools input:focus{outline:none;
  border-color:#9db8e6;box-shadow:0 0 0 4px #83a2db26}
.skel{height:118px;border-radius:22px;background:linear-gradient(100deg,
  #f6f7fa 28%,#edeff5 48%,#f6f7fa 68%);background-size:200% 100%;
  animation:shimmer 1.15s linear infinite;box-shadow:var(--shadow-card)}
.dropcard{transition:border-color 200ms var(--ease-out),
  transform 200ms var(--ease-out),box-shadow 200ms var(--ease-out)}
.dropcard.over{border-color:#83a2db;border-style:solid;transform:scale(1.006);
  box-shadow:0 30px 60px -44px #5f7fc4}
.dropcard.over .dropglyph{animation:pop 420ms var(--ease-spring)}
.dropglyph{transition:transform 200ms var(--ease-spring)}
.dropcard:active .dropglyph{transform:scale(.94)}
.step.done .sd{animation:checkin 320ms var(--ease-spring)}
.step.run .sd{animation:pulse 1.6s ease-in-out infinite}
.copy{width:30px;height:30px;border-radius:50%;background:#f4f5f8;color:#6a6f78;
  display:inline-grid;place-items:center;margin-left:6px;flex:none}
.copy:hover{background:#eceef3;color:#10141A}
#toasts{position:fixed;right:22px;bottom:22px;z-index:80;display:flex;
  flex-direction:column;gap:8px;align-items:flex-end;pointer-events:none}
.toast{pointer-events:auto;display:flex;align-items:center;gap:9px;
  background:#10141A;color:#fff;border-radius:999px;padding:10px 16px 10px 13px;
  font-size:11.5px;box-shadow:0 24px 40px -24px #10141a99;
  animation:toastIn 380ms var(--ease-spring) both}
.toast svg{color:#9FC9AE;flex:none}
.toast.out{animation:toastOut 200ms var(--ease-out) both}
.grouphead{display:flex;align-items:center;gap:10px;margin:6px 2px 10px;
  font-size:9.5px;letter-spacing:.09em;text-transform:uppercase;color:#9aa0a8}
.grouphead b{font-weight:600;color:#4d5159}
.grouphead i{flex:1;height:1px;background:#e9ebf2;font-style:normal}
.setrow{display:grid;grid-template-columns:200px minmax(0,1fr);gap:14px;
  align-items:center;padding:13px 0;border-top:1px solid #f4f5f8;font-size:11.5px}
.setrow:first-of-type{border-top:0;padding-top:2px}
.setrow label{color:#3c4048}
.setrow small{display:block;color:#a8abb3;font-size:10px;margin-top:2px}
select{font:inherit;font-size:11.5px;color:#3c4048;background:#fbfcfe;
  border:1px solid #eceef3;border-radius:10px;padding:7px 10px;
  min-width:180px;max-width:340px;width:100%}
select:focus{outline:2px solid #83a2db55;border-color:#83a2db}
.setsave{display:flex;align-items:center;gap:12px;margin-top:16px;flex-wrap:wrap}
html{scroll-behavior:smooth}
@media (pointer:coarse){
  .rail a{width:44px;height:44px}
  .ghostbtn,.darkbtn,.mini{min-height:44px}
  .nav a{padding:12px 16px}
}
@media (min-width:1560px){
  .grid2{grid-template-columns:minmax(0,1fr) 360px}
  .jobs{gap:16px}
}
@media (min-width:1600px){
  /* viewers + overview: the rail grows with the window, the reading
     column keeps the rest */
  .grid2{grid-template-columns:minmax(0,1fr) 400px;gap:18px}
  .side{top:96px;gap:16px}
  /* the preview gets real height instead of a fixed 440px strip */
  .previewframe iframe{height:clamp(520px,66vh,900px)}
  .md{font-size:13.5px}
}
@media (min-width:2000px){
  .grid2{grid-template-columns:minmax(0,1fr) 460px}
}
@media (max-width:1240px){.wrap{padding-right:20px}}
@media (max-width:1100px){
  .grid2{grid-template-columns:1fr}
  .side{position:static}
}
@media (max-width:640px){
  .jobs,.fmtgrid,.metrics{grid-template-columns:1fr}
}
@media (max-width:900px){
  .rail{display:none}
  .wrap{margin-left:0;padding:2px 16px 40px}
  .nav{display:none}
  h1{font-size:26px}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
}
"""


# --------------------------------------------------------------------------
# presentation helpers
# --------------------------------------------------------------------------
def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _fmt_bytes(size: Optional[int]) -> str:
    if not size:
        return "0 B"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / (1 << 20):.1f} MB"


def _initials(name: str) -> str:
    """Two-letter initials from a bundle name (avatars are never photos)."""
    stem = os.path.splitext(str(name or ""))[0].strip()
    caps = re.findall(r"[A-Z]", stem)
    if len(caps) >= 2:
        return (caps[0] + caps[1]).upper()
    words = re.findall(r"[A-Za-z0-9]+", stem)
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    if words:
        return words[0][:2].upper()
    return "??"


def _avatar_class(seed: str) -> str:
    return "b%d" % (sum(ord(c) for c in str(seed)) % 5 + 1)


def _grade_class(grade: str) -> str:
    letter = str(grade or "").strip()[:1].upper()
    if letter in ("A", "B", "C", "D", "F"):
        return "g-" + letter.lower()
    return "g-none"


def _status_pill(job: dict) -> str:
    status = str(job.get("status") or "")
    if status == _STATUS_OK:
        return "<span class='pill green'>done</span>"
    if status == _STATUS_ERR:
        return "<span class='pill red'>error</span>"
    if status == _STATUS_RUN:
        return "<span class='pill blue'>scanning</span>"
    return "<span class='pill amber'>queued</span>"


def _sev_pills(severity: Dict[str, Any]) -> str:
    bits = []
    for name in _SEV_ORDER:
        count = int((severity or {}).get(name, 0) or 0)
        if count:
            bits.append(
                f"<span class='pill {_SEV_CLASS[name]}'>{count} {_e(name)}</span>")
    return "".join(bits) or "<span class='pill grey'>no findings</span>"


def _sev_bar(severity: Dict[str, Any]) -> str:
    total = sum(int((severity or {}).get(s, 0) or 0) for s in _SEV_ORDER) or 1
    cls = {"critical": "c", "high": "h", "medium": "m", "low": "l", "info": "i"}
    segs = "".join(
        f"<i class='{cls[s]}' style='width:{int((severity or {}).get(s, 0) or 0) * 100 / total:.1f}%'></i>"
        for s in _SEV_ORDER)
    return f"<div class='bar'>{segs}</div>"


def _donut(score: Optional[float], grade: str, size: int = 96,
           caption: str = "") -> str:
    """Circular score gauge (SVG, no images)."""
    try:
        pct = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        pct = 0.0
    radius = (size / 2) - 6
    circumference = 2 * 3.141592653589793 * radius
    dash = circumference * pct / 100
    tone = {"g-a": "#9FC9AE", "g-b": "#E2C98C", "g-c": "#E09A9A",
            "g-d": "#CE6969", "g-f": "#B45252"}.get(_grade_class(grade), "#c9cdd6")
    center = size / 2
    return (
        "<div class='donut'>"
        f"<svg width='{size}' height='{size}' viewBox='0 0 {size} {size}' role='img' "
        f"aria-label='score {pct:.1f} of 100, grade {_e(grade or '-')}'>"
        f"<circle class='track' cx='{center}' cy='{center}' r='{radius:.1f}' stroke-width='8'/>"
        f"<circle class='arc' cx='{center}' cy='{center}' r='{radius:.1f}' stroke-width='8' "
        f"stroke='{tone}' stroke-dasharray='{dash:.1f} {circumference:.1f}'/>"
        f"<text class='cap' x='{center}' y='{center + 4:.1f}' text-anchor='middle'>"
        f"{pct:.1f}</text>"
        f"<text class='cap2' x='{center}' y='{center + 16:.1f}' text-anchor='middle'>"
        f"SCORE</text>"
        "</svg>"
        + (f"<div class='donut-label'><b>{_e(caption)}</b></div>" if caption else "")
        + "</div>"
    )


def _crumb(*parts: Tuple[str, str]) -> str:
    """Breadcrumb from (label, href) pairs; an empty href renders plain text."""
    bits = []
    for index, (label, href) in enumerate(parts):
        if index:
            bits.append(
                "<svg width='10' height='10' viewBox='0 0 24 24' fill='none' "
                "stroke='currentColor' stroke-width='2.4' stroke-linecap='round'>"
                "<path d='M9 6l6 6-6 6'/></svg>")
        if href:
            bits.append(f"<a href='{_e(href)}'>{_e(label)}</a>")
        else:
            bits.append(f"<span>{_e(label)}</span>")
    return "<div class='crumb'>" + "".join(bits) + "</div>"


_ICON = {
    "board": ("<rect x='3' y='3' width='7' height='7' rx='1.6'/>"
              "<rect x='14' y='3' width='7' height='7' rx='1.6'/>"
              "<rect x='3' y='14' width='7' height='7' rx='1.6'/>"
              "<rect x='14' y='14' width='7' height='7' rx='1.6'/>"),
    "upload": ("<path d='M12 15V4M8 8l4-4 4 4'/>"
               "<path d='M4.5 14v4A1.5 1.5 0 0 0 6 19.5h12a1.5 1.5 0 0 0 "
               "1.5-1.5v-4'/>"),
    "reports": ("<path d='M7 3.8h7l3.8 3.8v12.6H7z'/><path d='M14 3.8v3.8h3.8'/>"),
    "overview": ("<rect x='7' y='3.5' width='10' height='17' rx='2.4'/>"
                 "<path d='M10.5 18h3'/>"),
    "scan": ("<circle cx='11' cy='11' r='6.4'/><path d='M16 16l4.4 4.4'/>"),
    "settings": ("<path d='M4 7h8M18 7h2M4 12h3M13 12h7M4 17h9M19 17h1'/>"
                 "<circle cx='15' cy='7' r='2'/><circle cx='10' cy='12' r='2'/>"
                 "<circle cx='16' cy='17' r='2'/>"),
}


def _icon(name: str, size: int = 15) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='1.7' stroke-linecap='round' "
        f"stroke-linejoin='round'>{_ICON[name]}</svg>")


_UX_JS = r"""
(function(){
  const calm = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (calm) document.documentElement.classList.add('calm');

  window.masToast = function(message, ok){
    const box = document.getElementById('toasts');
    if (!box) return;
    const t = document.createElement('div');
    t.className = 'toast';
    t.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="2.4" stroke-linecap="round" ' +
      'stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7"/></svg><span></span>';
    t.querySelector('span').textContent = message;
    box.appendChild(t);
    setTimeout(function(){
      t.classList.add('out');
      setTimeout(function(){ t.remove(); }, 210);
    }, 2600);
    while (box.children.length > 3) box.firstElementChild.remove();
  };

  // severity groups: collapsed by default, open state remembered per job
  var jobId = (document.body && document.body.getAttribute('data-job')) || '';
  var sevKey = jobId ? 'mas.sev.' + jobId : '';
  var sevState = {};
  try {
    sevState = JSON.parse(window.localStorage.getItem(sevKey) || '{}') || {};
  } catch (e) { sevState = {}; }
  var saveSev = function(){
    if (!sevKey) return;
    try { window.localStorage.setItem(sevKey, JSON.stringify(sevState)); }
    catch (e) { /* storage blocked: groups still toggle for this visit */ }
  };
  var hashId = (window.location.hash || '').replace('#', '');
  var hashTarget = hashId ? document.getElementById(hashId) : null;
  document.querySelectorAll('.sevgroup').forEach(function(group){
    var key = group.id.replace(/^sev-/, '');
    group.addEventListener('toggle', function(){
      sevState[key] = group.open;
      saveSev();
    });
    // a deep link into a finding wins over the remembered state
    if (hashTarget && group.contains(hashTarget)){
      group.open = true;
      return;
    }
    if (Object.prototype.hasOwnProperty.call(sevState, key)){
      group.open = !!sevState[key];
    }
  });
  // deep links: open the group holding the target, then bring it into view
  function revealFromHash() {
    var id = (window.location.hash || '').replace('#', '');
    var node = id ? document.getElementById(id) : null;
    if (!node) return true;
    var group = node.closest ? node.closest('.sevgroup') : null;
    if (group && !group.open) group.open = true;
    var box = node.getBoundingClientRect();
    if (!box.height) return false;  // still collapsed: keep waiting
    window.scrollTo({
      top: Math.max(0, box.top + window.scrollY - 84),
      behavior: 'instant'
    });
    return true;
  }
  if (hashTarget) {
    var revealTries = 0;
    var revealWait = function () {
      if (revealFromHash() || ++revealTries > 24) return;
      window.setTimeout(revealWait, 60);
    };
    window.setTimeout(revealWait, 120);
  }
  window.addEventListener('hashchange', function () {
    var hashTries = 0;
    var hashStep = function () {
      if (revealFromHash() || ++hashTries > 16) return;
      window.setTimeout(hashStep, 50);
    };
    hashStep();
  });

  // severity filter: narrows the summary table and the groups together
  document.addEventListener('click', function(ev){
    const chip = ev.target.closest('.sevfilter [data-filter]');
    if (!chip) return;
    const want = chip.getAttribute('data-filter');
    document.querySelectorAll('.sevfilter [data-filter]').forEach(function(b){
      const on = b === chip;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    document.querySelectorAll('#findings tr[data-sev]').forEach(function(row){
      row.style.display = (!want || row.getAttribute('data-sev') === want) ? '' : 'none';
    });
    document.querySelectorAll('.sevgroup[data-sev]').forEach(function(group){
      group.style.display = (!want || group.getAttribute('data-sev') === want) ? '' : 'none';
    });
  });

  // expand / collapse every severity group at once
  document.addEventListener('click', function(ev){
    const toggle = ev.target.closest('[data-expand]');
    if (!toggle) return;
    const open = toggle.getAttribute('data-expand') === 'all';
    document.querySelectorAll('.sevgroup').forEach(function(d){ d.open = open; });
  });

  document.addEventListener('click', function(ev){
    const btn = ev.target.closest('[data-copy]');
    if (!btn) return;
    const text = btn.getAttribute('data-copy') || '';
    const done = function(){
      window.masToast('Copied · ' + (text.length > 26 ? text.slice(0, 26) + '…' : text), true);
    };
    if (navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done).catch(function(){
        window.masToast('Clipboard is blocked here');
      });
    } else {
      window.masToast('Clipboard is blocked here');
    }
  });

  // ---- collapsible cards --------------------------------------------------
  // every <section class='card'> gets a chevron; the open/closed state is
  // remembered per job so a collapsed Findings card stays collapsed
  (function(){
    var key = jobId ? 'mas.cards.' + jobId : 'mas.cards';
    var state = {};
    try { state = JSON.parse(window.localStorage.getItem(key) || '{}') || {}; }
    catch (e) { state = {}; }
    var save = function(){
      try { window.localStorage.setItem(key, JSON.stringify(state)); }
      catch (e) { /* storage blocked: toggles still work this visit */ }
    };
    document.querySelectorAll('main section.card').forEach(function(card){
      var head = card.querySelector(':scope > h3') ||
        card.querySelector(':scope > .fndhead > h3');
      if (!head) return;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ctog';
      btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" ' +
        'fill="none" stroke="currentColor" stroke-width="2.2" ' +
        'stroke-linecap="round" stroke-linejoin="round">' +
        '<polyline points="6 9 12 15 18 9"/></svg>';
      if (!head.querySelector('.pill')) btn.style.marginLeft = 'auto';
      head.appendChild(btn);
      var setOpen = function(open, remember){
        card.classList.toggle('collapsed', !open);
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        btn.setAttribute('aria-label',
          open ? 'Collapse card' : 'Expand card');
        btn.title = open ? 'Collapse' : 'Expand';
        if (remember && card.id) { state[card.id] = open; save(); }
      };
      btn.addEventListener('click', function(ev){
        ev.preventDefault();
        setOpen(card.classList.contains('collapsed'), true);
      });
      if (card.id && Object.prototype.hasOwnProperty.call(state, card.id)) {
        setOpen(!!state[card.id], false);
      } else {
        setOpen(true, false);
      }
    });
  })();

  // ---- command palette --------------------------------------------------
  var cmdk = document.getElementById('cmdk');
  var cmdq = document.getElementById('cmdkq');
  var cmdl = document.getElementById('cmdkl');
  var searchBtn = document.getElementById('searchbtn');
  var currentJob = (document.body && document.body.getAttribute('data-job')) || '';
  var pages = [
    {t: 'Board', h: '/', k: 'page'},
    {t: 'Upload a bundle', h: '/upload', k: 'page'},
    {t: 'Settings', h: '/settings', k: 'page'}
  ];
  if (currentJob) {
    pages.push({t: 'Overview', h: '/overview/' + currentJob, k: 'page'});
    pages.push({t: 'Reports', h: '/reports/' + currentJob, k: 'page'});
    pages.push({t: 'Findings', h: '/view/' + currentJob + '/md', k: 'page'});
  }
  var jobs = [];
  var findings = [];
  var sel = 0;
  var jobsAsked = false;
  var findingsAsked = false;
  var go = function (href) { window.location.href = href; };

  function loadJobs() {
    if (jobsAsked) return;
    jobsAsked = true;
    fetch('/jobs').then(function (r) { return r.json(); }).then(function (d) {
      jobs = (d.jobs || []).filter(function (j) {
        return j.status === 'done' && j.id !== currentJob;
      }).slice(0, 8).map(function (j) {
        var meta = 'job ' + (j.id || '').slice(0, 8);
        if (j.grade) meta += ' · ' + j.grade;
        if (j.findings) meta += ' · ' + j.findings + ' findings';
        return {t: j.name || j.id, h: '/overview/' + j.id, k: meta};
      });
      render();
    }).catch(function () { jobsAsked = false; });
  }

  // the current job's findings, straight from its report.json
  function loadFindings() {
    if (!currentJob || findingsAsked) return;
    findingsAsked = true;
    fetch('/report/' + currentJob + '/json').then(function (r) {
      return r.json();
    }).then(function (d) {
      findings = (d.findings || []).map(function (f, i) {
        var ev = f.evidence || {};
        var loc = String(ev.location || ev.file || '');
        var sev = String(f.severity || '');
        var rule = String(f.rule_id || '');
        return {
          t: String(f.title || rule || 'finding'),
          h: '/overview/' + currentJob + '#fnd-' + (i + 1),
          k: (sev ? sev + ' · ' : '') + rule,
          s: (String(f.title || '') + ' ' + rule + ' ' + loc + ' ' +
              String(f.cwe || '') + ' ' + String(f.owasp || '')).toLowerCase()
        };
      });
      render();
    }).catch(function () { findingsAsked = false; });
  }

  function render() {
    if (!cmdl) return;
    var q = (cmdq.value || '').trim().toLowerCase();
    var pool = pages.concat(jobs);
    if (q.length >= 2) pool = pages.concat(findings, jobs);
    var list = pool.filter(function (it) {
      if (!q) return true;
      var hay = it.s || (it.t + ' ' + it.k).toLowerCase();
      return hay.indexOf(q) !== -1;
    }).slice(0, 30);
    if (sel >= list.length) sel = 0;
    cmdl.textContent = '';
    if (!list.length) {
      var empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'Nothing matches that search.';
      cmdl.appendChild(empty);
      return;
    }
    list.forEach(function (it, i) {
      var b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('role', 'option');
      b.setAttribute('aria-selected', i === sel ? 'true' : 'false');
      if (i === sel) b.className = 'on';
      var label = document.createElement('span');
      label.textContent = it.t;
      var kind = document.createElement('span');
      kind.className = 'k';
      kind.textContent = it.k;
      b.appendChild(label);
      b.appendChild(kind);
      b.addEventListener('click', function () { go(it.h); });
      cmdl.appendChild(b);
    });
    var active = cmdl.children[sel];
    if (active && active.scrollIntoView) active.scrollIntoView({block: 'nearest'});
  }

  function openPalette() {
    if (!cmdk) return;
    cmdk.hidden = false;
    document.body.style.overflow = 'hidden';
    cmdq.value = '';
    sel = 0;
    render();
    loadJobs();
    loadFindings();
    cmdq.focus();
  }

  function closePalette() {
    if (!cmdk || cmdk.hidden) return;
    cmdk.hidden = true;
    document.body.style.overflow = '';
    if (searchBtn) searchBtn.focus();
  }

  if (searchBtn) searchBtn.addEventListener('click', openPalette);
  if (cmdk) {
    cmdk.addEventListener('click', function (ev) {
      if (ev.target === cmdk) closePalette();
    });
    cmdq.addEventListener('input', function () { sel = 0; render(); });
    cmdq.addEventListener('keydown', function (ev) {
      var rows = cmdl.querySelectorAll('button');
      if (!rows.length) return;
      if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        sel = (sel + 1) % rows.length;
        render();
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        sel = (sel - 1 + rows.length) % rows.length;
        render();
      } else if (ev.key === 'Enter') {
        ev.preventDefault();
        rows[sel].click();
      }
    });
  }
  document.addEventListener('keydown', function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      if (cmdk && cmdk.hidden) openPalette(); else closePalette();
    }
  });

  // ---- account menu -----------------------------------------------------
  var accBtn = document.getElementById('accbtn');
  var accMenu = document.getElementById('accmenu');
  function closeMenu() {
    if (!accMenu || !accBtn) return;
    accMenu.hidden = true;
    accBtn.setAttribute('aria-expanded', 'false');
  }
  if (accBtn && accMenu) {
    accBtn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      var open = accMenu.hidden;
      accMenu.hidden = !open;
      accBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('click', function (ev) {
      if (!accMenu.hidden && !accMenu.contains(ev.target) && ev.target !== accBtn) {
        closeMenu();
      }
    });
    var forget = document.getElementById('forgetbtn');
    if (forget) forget.addEventListener('click', function () {
      try {
        Object.keys(localStorage).forEach(function (k) {
          if (k.indexOf('mas.') === 0) localStorage.removeItem(k);
        });
      } catch (e) { /* storage blocked */ }
      closeMenu();
      window.masToast('Saved view state cleared', true);
    });
  }
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') { closeMenu(); closePalette(); }
  });
})();
"""


def _shell(active: str, body: str, job: Optional[dict] = None,
           title: str = "masanalyzer") -> str:
    """Shared page chrome: top bar, pill nav, circular rail, footer."""
    jid = _e(str((job or {}).get("id") or ""))
    nav = [("Board", "/", "board"), ("Upload", "/upload", "upload"),
           ("Settings", "/settings", "settings")]
    if jid:
        nav += [
            ("Overview", f"/overview/{jid}", "overview"),
            ("Reports", f"/reports/{jid}", "reports"),
            ("Findings", f"/view/{jid}/md", "md"),
        ]
    nav_links = []
    for label, href, key in nav:
        cls = "on" if key == active else ""
        nav_links.append(
            f'<a class="{cls}" href="{_e(href)}">{_e(label)}</a>')
    nav_html = "".join(nav_links)
    rail = [
        (f"/", "board", "Board"),
        (f"/upload", "upload", "New scan"),
        (f"/settings", "settings", "Settings"),
    ]
    if jid:
        rail += [
            (f"/reports/{jid}", "reports", "Reports"),
            (f"/overview/{jid}", "overview", "Overview"),
        ]
    rail_html = "".join(
        f"<a class='{'on' if key == active else ''}' href='{_e(href)}' title='{_e(label)}'>"
        f"{_icon(key, 16)}</a>"
        for href, key, label in rail)
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_e(title)}</title><style>{_B_CSS}</style></head>"
        + (f"<body data-job='{jid}'>" if jid else "<body>")
        + "<header class='topbar'>"
        "<a class='brand' href='/'>"
        "<span class='mark'><svg width='22' height='22' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'>"
        "<path d='M4 15.5l8-4 8 4'/><path d='M4 11l8-4 8 4'/>"
        "<path d='M4 19l8-3.6L20 19'/></svg></span>"
        "masanalyzer</a>"
        f"<nav class='nav' aria-label='Primary'>{nav_html}</nav>"
        "<div class='actions'>"
        "<button type='button' class='circle' id='searchbtn' aria-haspopup='dialog' "
        "aria-label='Search jobs and pages' title='Search (Ctrl+K)'>"
        "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
        "stroke-width='1.9' stroke-linecap='round'><circle cx='11' cy='11' r='6.4'/>"
        "<path d='M16 16l4.4 4.4'/></svg></button>"
        "<div class='acc'>"
        "<button type='button' class='me' id='accbtn' aria-haspopup='menu' "
        "aria-expanded='false' aria-controls='accmenu' "
        "title='Local workbench'>M</button>"
        "<div class='menu' id='accmenu' role='menu' hidden>"
        "<div class='menuhead'><span class='me sm'>M</span>"
        "<div><b>Local workbench</b>"
        "<span>no sign-in &middot; 127.0.0.1</span></div></div>"
        + (f"<a role='menuitem' href='/overview/{jid}'>Overview</a>"
           f"<a role='menuitem' href='/reports/{jid}'>Reports</a>"
           f"<a role='menuitem' href='/view/{jid}/md'>Findings</a>"
           "<div class='sep'></div>" if jid else "") +
        "<a role='menuitem' href='/'>Board</a>"
        "<a role='menuitem' href='/upload'>Scan a bundle</a>"
        "<a role='menuitem' href='/settings'>Settings</a>"
        "<div class='sep'></div>"
        "<button type='button' role='menuitem' id='forgetbtn'>"
        "Forget saved view state</button>"
        "</div></div>"
        "</div></header>"
        "<aside class='rail' aria-label='Workbench'>" + rail_html +
        "<span class='spacer'></span>"
        "<a class='mode' href='/upload' title='New scan'>"
        "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
        "stroke-width='1.9' stroke-linecap='round'><path d='M12 5.5v13M5.5 12h13'/></svg>"
        "</a></aside>"
        "<main class='wrap'>" + body +
        "<div class='foot'><span>Local workbench &middot; 127.0.0.1 &middot; "
        "reports never leave this machine</span>"
        "<span>masanalyzer &middot; ten report formats</span></div>"
        "</main>"
        "<div id='cmdk' class='cmdk' hidden>"
        "<div class='cmdkbox' role='dialog' aria-modal='true' aria-label='Search'>"
        "<div class='cmdkhead'>"
        "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
        "stroke-width='1.9' stroke-linecap='round'><circle cx='11' cy='11' r='6.4'/>"
        "<path d='M16 16l4.4 4.4'/></svg>"
        "<input id='cmdkq' type='search' placeholder='Search jobs and pages' "
        "autocomplete='off' spellcheck='false' aria-label='Search jobs and pages'>"
        "</div>"
        "<div id='cmdkl' class='cmdkl' role='listbox' aria-label='Results'></div>"
        "<div class='cmdktip'>Up/Down to move &middot; Enter to open "
        "&middot; Esc to close</div>"
        "</div></div>"
        "<div id='toasts' aria-live='polite'></div>"
        "<script>" + _UX_JS + "</script></body></html>"
    )


# --------------------------------------------------------------------------
# job storage
# --------------------------------------------------------------------------
class _Jobs:
    """In-memory job registry mirrored into ``job.json`` per job dir."""

    def __init__(self, root: str) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._jobs: Dict[str, dict] = {}
        os.makedirs(root, exist_ok=True)
        self._load()

    # -- persistence --------------------------------------------------------
    def _load(self) -> None:
        for job_id in sorted(os.listdir(self.root)):
            meta = os.path.join(self.root, job_id, "job.json")
            if not os.path.isfile(meta):
                continue
            try:
                with open(meta, "rb") as fh:
                    job = json.loads(fh.read().decode("utf-8"))
                if job.get("status") in (_STATUS_QUEUED, _STATUS_RUN):
                    # a server restart orphans in-flight work
                    job["status"] = _STATUS_ERR
                    job["error"] = "dashboard restarted mid-scan"
                self._jobs[job_id] = job
            except (OSError, ValueError):
                continue

    def _save(self, job: dict) -> None:
        path = os.path.join(self.root, job["id"], "job.json")
        try:
            with open(path, "wb") as fh:
                fh.write(json.dumps(job, indent=1).encode("utf-8"))
        except OSError:  # pragma: no cover - dashboard stays up regardless
            pass

    # -- CRUD ----------------------------------------------------------------
    def create(self, display_name: str, upload_name: str) -> dict:
        job_id = uuid.uuid4().hex
        os.makedirs(os.path.join(self.root, job_id), exist_ok=True)
        job = {
            "id": job_id,
            "name": display_name,
            "upload_name": upload_name,
            "status": _STATUS_QUEUED,
            "phase": "",
            "detail": "",
            "error": "",
            "grade": "",
            "score": None,
            "findings": None,
            "severity": {},
            "assurance": {},
            "surface": {},
            "icon": "",
            "submitted": datetime.now(timezone.utc).isoformat(),
            "finished": "",
            "formats": [],
        }
        with self._lock:
            self._jobs[job_id] = job
        self._save(job)
        return job

    def get(self, job_id: str) -> Optional[dict]:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.update(fields)
            snapshot = dict(job)
        self._save(snapshot)

    def list(self) -> list:
        with self._lock:
            return sorted(
                self._jobs.values(),
                key=lambda j: j.get("submitted", ""),
                reverse=True,
            )

    def dir(self, job_id: str) -> str:
        return os.path.join(self.root, job_id)


# --------------------------------------------------------------------------
# upload multipart parsing (stdlib only; 'cgi' is gone in py3.13+)
# --------------------------------------------------------------------------
def extract_upload(headers: Any, body: bytes,
                   field: str = "file") -> Tuple[str, bytes]:
    """Return ``(filename, content)`` from a multipart/form-data body.

    Only the ``field`` form field is accepted; any other part (with or
    without a ``filename``) is ignored.
    """
    ctype = str(headers.get("Content-Type", "") if hasattr(headers, "get")
                else headers.get("content-type", ""))
    m = re.search(r'boundary="?([^";,]+)"?', ctype)
    if not m:
        raise ValueError("expected multipart/form-data with a boundary")
    boundary = ("--" + m.group(1)).encode("utf-8")
    marker = f'name="{field}"'.encode("utf-8")
    for segment in body.split(boundary):
        if marker not in segment[:2048] or b"filename=" not in segment[:2048]:
            continue
        idx = segment.find(b"\r\n\r\n")
        if idx < 0:
            continue
        content = segment[idx + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        disp = segment[:idx].decode("utf-8", "replace")
        fn = re.search(r'filename="([^"]*)"', disp)
        if fn is None:
            fn = re.search(r"filename=([^\r\n;]+)", disp)
        filename = (fn.group(1) if fn else "upload.bin").strip() or "upload.bin"
        return os.path.basename(filename.replace("\\", "/")), content
    raise ValueError("no file part found (use form field 'file')")


def sanitize_upload_name(name: str) -> str:
    base = os.path.basename(str(name or "").replace("\\", "/")).strip()
    base = re.sub(r"[^A-Za-z0-9._ ()-]", "_", base)[:_MAX_NAME]
    if not base or base.startswith("."):
        base = "upload" + (os.path.splitext(base)[1] or "")
    ext = os.path.splitext(base)[1].lower()
    if ext and ext not in _EXTENSIONS:
        base = os.path.splitext(base)[0] + ".bin"
    return base


# --------------------------------------------------------------------------
# scan worker
# --------------------------------------------------------------------------
class _Scanner:
    """Worker pool turning queued uploads into rendered reports."""

    def __init__(self, jobs: _Jobs, workers: int = 2,
                 osv_cache: Optional[str] = None,
                 refresh_intel: bool = True) -> None:
        self.jobs = jobs
        self.osv_cache = osv_cache
        self.refresh_intel = refresh_intel
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._threads = [
            threading.Thread(target=self._work, daemon=True,
                             name=f"masan-scan-{i}")
            for i in range(max(1, workers))
        ]
        for t in self._threads:
            t.start()

    def enqueue(self, job_id: str, path: str) -> None:
        self._queue.put((job_id, path))  # type: ignore[arg-type]

    def _work(self) -> None:
        while True:
            job_id, path = self._queue.get()
            if job_id is None:  # pragma: no cover - pool runs forever
                return
            try:
                self._scan(job_id, path)
            except Exception as exc:  # noqa: BLE001 - a scan must not kill the pool
                self.jobs.update(
                    job_id, status=_STATUS_ERR, finished=_now(),
                    error=f"{type(exc).__name__}: {exc}",
                )

    def _scan(self, job_id: str, path: str) -> None:
        from .scanner import scan

        self.jobs.update(job_id, status=_STATUS_RUN, phase="unpack")

        def tell(p: Any) -> None:
            self.jobs.update(job_id, phase=str(getattr(p, "phase", "")),
                             detail=str(getattr(p, "detail", "")))

        result = scan(path, progress=tell, osv_cache=self.osv_cache,
                      refresh_intel=self.refresh_intel)
        job_dir = self.jobs.dir(job_id)
        written: list = []
        from .reporting import render

        for fmt in FORMATS:
            try:
                text = render(result, fmt)
            except Exception as exc:  # noqa: BLE001 - one bad renderer skips one file
                self.jobs.update(
                    job_id, error=f"render {fmt}: {type(exc).__name__}: {exc}")
                continue
            fname = f"report.{fmt}"
            with open(os.path.join(job_dir, fname), "wb") as fh:
                fh.write(text.encode("utf-8") if isinstance(text, str)
                         else bytes(text))
            written.append(fname)

        # the bundle's own launcher icon, best-effort (decoration never
        # fails a scan: a missing icon just leaves the initials avatar)
        icon_name = ""
        try:
            from .android.icons import extract_icon

            hit = extract_icon(path)
        except Exception:  # noqa: BLE001 - never let an icon break a scan
            hit = None
        if hit:
            blob, ext = hit
            icon_name = f"icon.{ext}"
            try:
                with open(os.path.join(job_dir, icon_name), "wb") as fh:
                    fh.write(blob)
            except OSError:
                icon_name = ""

        findings = list(result.findings)
        severity: Dict[str, int] = {}
        assurance: Dict[str, int] = {}
        for f in findings:
            sev = str(getattr(f, "severity", "info"))
            severity[sev] = severity.get(sev, 0) + 1
            tier = str(getattr(f, "assurance", "") or "ungraded").lower()
            assurance[tier] = assurance.get(tier, 0) + 1
        # attack-surface synthesis summary (surface.py, if produced)
        target = getattr(result, "target", None)
        surface = (getattr(target, "meta", None) or {}).get(
            "attack_surface") or {}
        surface_summary = dict(surface.get("summary") or {})
        # CVE-cache currency (operational only; reports stay deterministic)
        intel_status = dict(
            (getattr(target, "meta", None) or {}).get("intel_status") or {})
        intel_age = None
        try:
            from .osv import cache_from

            _c = cache_from(target.meta.get("osv_intel"))
            if _c is not None:
                intel_age = _c.age_days()
        except Exception:  # noqa: BLE001
            intel_age = None
        score = getattr(result, "score", None)
        prev = self.jobs.get(job_id) or {}
        self.jobs.update(
            job_id,
            status=_STATUS_ERR if not written else _STATUS_OK,
            finished=_now(),
            phase="",
            detail="",
            grade=str(getattr(score, "grade", "") or ""),
            score=(round(float(getattr(score, "total", 0.0)), 2)
                   if score is not None and getattr(score, "total", None) is not None
                   else None),
            findings=len(findings),
            severity=severity,
            assurance=assurance,
            surface=surface_summary,
            intel={"age_days": intel_age, **intel_status} if intel_status else {},
            formats=written,
            icon=icon_name,
            error=prev.get("error", ""),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

# --------------------------------------------------------------------------
# board page (/)
# --------------------------------------------------------------------------
_BOARD_JS = r"""
const sevOrder = ["critical","high","medium","low","info"];
const sevClass = {critical:"red",high:"red",medium:"amber",low:"green",info:"grey"};
const tierOrder = ["verified","structural","heuristic"];
const tierClass = {verified:"green",structural:"blue",heuristic:"grey"};
const seen = new Map();
let firstPaint = true;

function toast(msg){ if (window.masToast) window.masToast(msg, true); }

function esc(s){const d = document.createElement("div");
  d.textContent = s == null ? "" : String(s); return d.innerHTML;}

function gradeClass(g){
  const l = String(g || "").charAt(0).toUpperCase();
  return ["A","B","C","D","F"].includes(l) ? "g-" + l.toLowerCase() : "g-none";
}

function tierChips(t){
  return tierOrder.filter(k => t && t[k] > 0).map(k =>
    `<span class="pill ${tierClass[k]}">${esc(k)} ${t[k]}</span>`).join("");
}

function sevPills(sev){
  return sevOrder.filter(k => sev && sev[k] > 0).map(k =>
    `<span class="pill ${sevClass[k]}">${sev[k]} ${esc(k)}</span>`).join("")
    || `<span class="pill grey">no findings</span>`;
}

function sevBar(sev){
  const total = sevOrder.reduce((a,k) => a + ((sev && sev[k]) || 0), 0) || 1;
  const cls = {critical:"c",high:"h",medium:"m",low:"l",info:"i"};
  return `<div class="bar">` + sevOrder.map(k => {
    const n = (sev && sev[k]) || 0;
    return n ? `<i class="${cls[k]}" style="width:${n * 100 / total}%"></i>` : "";
  }).join("") + `</div>`;
}

function shortName(name){
  const parts = String(name || "").split(".");
  return parts.length > 1 ? parts.slice(-2).join(".") : name;
}

function surfTxt(s){
  if (!s || !s.external_entry_points) return "";
  let txt = `${s.external_entry_points} exported` +
    (s.unprotected_entry_points
      ? ` &middot; ${s.unprotected_entry_points} unguarded` : "");
  const q = s.fix_first || [];
  if (q.length){
    txt += ` &middot; <span title="${esc((q[0].why || []).join("; "))}">` +
      `fix first: ${esc(shortName(q[0].component))} (${esc(q[0].score)})</span>`;
  }
  return txt;
}

function initials(name){
  const stem = String(name || "").replace(/\.[A-Za-z0-9]+$/, "");
  const caps = stem.match(/[A-Z]/g) || [];
  if (caps.length >= 2) return (caps[0] + caps[1]).toUpperCase();
  const words = stem.match(/[A-Za-z0-9]+/g) || [];
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return words.length ? words[0].slice(0, 2).toUpperCase() : "??";
}

function avatarClass(seed){
  let n = 0; for (const ch of String(seed || "")) n += ch.charCodeAt(0);
  return "b" + (n % 5 + 1);
}

function metaLine(j){
  if (j.status === "done")
    return `${esc(j.score)} / 100 &middot; ${esc(j.findings)} findings`;
  if (j.status === "error") return esc(j.error || "scan failed");
  return esc(j.phase || j.status) +
    (j.detail ? " &middot; " + esc(j.detail) : "");
}

function cardHtml(j, fresh){
  const done = j.status === "done";
  const pill = done ? `<span class="pill green">done</span>`
    : j.status === "error" ? `<span class="pill red">error</span>`
    : j.status === "running" ? `<span class="pill blue">scanning</span>`
    : `<span class="pill amber">queued</span>`;
  const av = j.icon
    ? `<img class="av sm appicon" src="/icon/${esc(j.id)}" alt="" ` +
      `loading="lazy" onerror="this.replaceWith(document.createTextNode(''))">`
    : `<span class="av sm ${avatarClass(j.name)}">` +
      `${esc(initials(j.name))}</span>`;
  let inner = `<div class="jhead">${av}<div class="who">` +
    `<b>${esc(j.name || "bundle")}</b><span>${metaLine(j)}</span></div>${pill}</div>`;
  if (done){
    inner += `<div class="jmid">` +
      `<div class="grade ${gradeClass(j.grade)}" title="risk score ${esc(j.score)}">` +
      `${esc(j.grade || "-")}</div><div class="grow">${sevBar(j.severity)}` +
      `<div class="sevrow">${sevPills(j.severity)}</div></div></div>` +
      `<div class="jfoot"><span>${tierChips(j.assurance)}</span>` +
      `<a class="go" style="margin-left:auto" ` +
      `href="/view/${esc(j.id)}/md">Findings</a>` +
      `<a class="go" style="margin-left:8px" ` +
      `href="/overview/${esc(j.id)}">Open ` +
      `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" ` +
      `stroke="currentColor" stroke-width="2" stroke-linecap="round">` +
      `<path d="M5 12h13M12 5l7 7-7 7"/></svg></a></div>`;
    const surf = surfTxt(j.surface);
    if (surf) inner += `<div class="jmeta">${surf}</div>`;
  } else {
    inner += `<div class="jmeta">` + (j.status === "error"
      ? `<span class="jerr">${esc(j.error || "scan failed")}</span>`
      : `waiting for a worker &middot; reports appear when the scan ends`) + `</div>`;
  }
  return `<article class="card jobcard${fresh ? " pop" : ""}" ` +
    `data-href="/overview/${esc(j.id)}" tabindex="0" role="link" ` +
    `aria-label="Open the overview for ${esc(j.name || 'bundle')}">${inner}</article>`;
}

function render(jobs){
  const wrap = document.getElementById("joblist");
  const q = (document.getElementById("filter").value || "").toLowerCase();
  let bundles = 0, findings = 0, critical = 0, verified = 0, graded = 0;
  const scores = [];
  let shown = 0, out = "";
  for (const j of jobs){
    bundles++;
    let fresh = false;
    const before = seen.get(j.id);
    if (before && before !== "done" && j.status === "done"){
      fresh = true;
      toast((j.name || "bundle") + " finished · grade " + (j.grade || "-"));
    }
    seen.set(j.id, j.status);
    if (typeof j.findings === "number") findings += j.findings;
    critical += (j.severity && j.severity.critical) || 0;
    if (typeof j.score === "number") scores.push(j.score);
    for (const k in (j.assurance || {})){
      if (k === "verified") verified += j.assurance[k];
      graded += j.assurance[k];
    }
    if (q && !String(j.name || "").toLowerCase().includes(q)) continue;
    out += cardHtml(j, fresh); shown++;
  }
  wrap.innerHTML = shown ? out :
    `<p class="empty">${q ? "No scans match this filter."
      : "No scans yet. Start with a bundle on the upload page."}</p>`;
  if (firstPaint){
    wrap.classList.remove("stage");
    firstPaint = false;
  }
  document.getElementById("tBundles").textContent = bundles;
  document.getElementById("tFindings").textContent = findings;
  document.getElementById("tCritical").textContent = critical;
  document.getElementById("tMean").textContent = scores.length
    ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1) : "-";
  document.getElementById("tVerified").textContent =
    graded ? Math.round(verified * 100 / graded) : 0;
}

async function refresh(){
  try{
    const r = await fetch("/jobs");
    render((await r.json()).jobs || []);
  }catch(e){ /* the board keeps polling */ }
}
// the whole card is the target (Fitts): inner links keep their own jobs
document.addEventListener("click", (ev) => {
  const card = ev.target.closest(".jobcard");
  if (!card || ev.target.closest("a, button")) return;
  if (card.dataset.href) window.location.href = card.dataset.href;
});
document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Enter" && ev.key !== " ") return;
  const card = ev.target.closest && ev.target.closest(".jobcard");
  if (!card || ev.target !== card) return;
  ev.preventDefault();
  if (card.dataset.href) window.location.href = card.dataset.href;
});

document.getElementById("filter").addEventListener("input", refresh);
refresh();
// the interval is a saved preference (/settings); 0 means manual only
const REFRESH_MS = 3000;
if (REFRESH_MS > 0) setInterval(refresh, REFRESH_MS);
"""


def _refresh_label(refresh_ms: int) -> str:
    """Human text for the board's refresh interval."""
    if int(refresh_ms) <= 0:
        return "manual refresh only"
    seconds = int(refresh_ms) / 1000.0
    return f"refreshes every {seconds:g} s"


def _board_page(jobs: list, refresh_ms: int = 3000) -> str:
    body = (
        _crumb(("Workbench", ""), ("Board", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        "<div><h1>Scan board</h1>"
        "<p>Every bundle as a card, every score on the surface &mdash; "
        "with the evidence behind each grade one click away.</p></div>"
        "<div class='right'><a class='darkbtn' href='/upload'>"
        "<svg width='13' height='13' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='2' stroke-linecap='round'>"
        "<path d='M12 5.5v13M5.5 12h13'/></svg>New scan</a></div>"
        "</div></div>"
        "<div class='metrics stage'>"
        "<div class='m'><span>Bundles on record</span><b id='tBundles'>0</b>"
        "<p>stored under the workdir</p></div>"
        "<div class='m'><span>Findings</span><b id='tFindings'>0</b>"
        "<p>across every finished scan</p></div>"
        "<div class='m'><span>Critical</span><b id='tCritical'>0</b>"
        "<p>release blockers</p></div>"
        "<div class='m'><span>Mean score</span><b id='tMean'>&ndash;</b>"
        "<p>over the ten categories</p></div>"
        "<div class='m'><span>Assurance</span>"
        "<b><span id='tVerified'>0</span><small>%</small></b>"
        "<p>findings proven, not guessed</p></div>"
        "</div>"
        "<section class='panel' style='margin-top:16px'>"
        "<div class='panel-h'><h2>Bundles</h2>"
        f"<span class='sub'>newest first &middot; "
        f"{_e(_refresh_label(refresh_ms))}</span>"
        "<div class='panel-tools'>"
        "<input id='filter' type='text' placeholder='Filter by name&hellip;' "
        "aria-label='Filter scans' style='height:32px;border:1px solid #eceef3;"
        "border-radius:999px;padding:0 14px;font:inherit;font-size:11.5px;"
        "background:#ffffffd0;color:#3c4048;min-width:190px'>"
        "</div></div>"
        "<div class='jobs stage' id='joblist' aria-live='polite'>"
        "<div class='skel'></div><div class='skel'></div>"
        "<div class='skel'></div><div class='skel'></div></div>"
        "</section>"
        "<div class='foot' style='margin-top:18px'>"
        "<span><b>Assurance</b> grades how each finding was established: "
        "<b>verified</b> cryptographic or binary proof, <b>structural</b> a "
        "parsed config fact, <b>heuristic</b> a pattern match.</span>"
        "<span>Surface counts exported entry points; the amber chip is the top "
        "of the fix-first queue.</span></div>"
    )
    script = _BOARD_JS.replace(
        "const REFRESH_MS = 3000;",
        f"const REFRESH_MS = {max(0, int(refresh_ms))};")
    return _shell("board", body + "<script>" + script + "</script>",
                  title="masanalyzer dashboard")

# --------------------------------------------------------------------------
# upload page (/upload)
# --------------------------------------------------------------------------
_UPLOAD_JS = r"""
const input = document.getElementById("file");
const form = document.getElementById("upform");
const status = document.getElementById("upstatus");
const go = document.getElementById("go");

function chosen(){
  const f = input.files && input.files[0];
  document.getElementById("filename").textContent = f
    ? f.name + " · " + (f.size / (1 << 20)).toFixed(2) + " MB"
    : "no file chosen";
  go.disabled = !f;
}

document.getElementById("pick").addEventListener("click", () => input.click());
input.addEventListener("change", chosen);
form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = input.files && input.files[0];
  if (!f){ status.textContent = "choose a bundle first"; return; }
  const fd = new FormData();
  fd.append("file", f);
  go.disabled = true;
  status.textContent = "uploading…";
  try{
    const r = await fetch("/upload", {method:"POST", body:fd});
    if (!r.ok){
      status.textContent = "upload failed: " + (await r.text());
      go.disabled = false;
      return;
    }
    const job = await r.json();
    status.textContent = "queued — opening the live scan…";
    window.location.href = "/scanning/" + job.id;
  }catch(e){
    status.textContent = "upload failed: " + e;
    go.disabled = false;
  }
});
chosen();

// staging the focus: the whole drop card is a target (Fitts), and the dashed
// border marches while dragging (secondary action) before the bundle lands.
const drop = document.getElementById("drop");
drop.addEventListener("click", (ev) => {
  if (ev.target.closest("button, a, input, label")) return;
  input.click();
});
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault();
  drop.classList.add("over");
}));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault();
  drop.classList.remove("over");
}));
drop.addEventListener("drop", e => {
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (!f) return;
  const dt = new DataTransfer();
  dt.items.add(f);
  input.files = dt.files;
  chosen();
  if (window.masToast) window.masToast("Bundle staged · " + f.name, true);
});
"""


def _upload_page(jobs: list, max_mib: int, workers: int,
                 refresh_intel: bool) -> str:
    recents = ""
    for job in jobs[:5]:
        jid = _e(job.get("id"))
        grade = str(job.get("grade") or "")
        badge = (f"<span class='grade {_grade_class(grade)}'>{_e(grade)}</span>"
                 if grade else "<span class='mono'>&ndash;</span>")
        submitted = str(job.get("submitted") or "")
        recents += (
            "<tr>"
            "<td><div class='jhead' style='gap:8px'>"
            f"<span class='av sm {_avatar_class(job.get('name'))}'>"
            f"{_e(_initials(job.get('name')))}</span>"
            f"<a href='/overview/{jid}'><b>{_e(job.get('name'))}</b></a></div></td>"
            f"<td>{badge}</td>"
            f"<td class='mono'>{_e(job.get('findings'))} findings</td>"
            f"<td class='mono' style='text-align:right'>{_e(submitted[:10])}</td>"
            "</tr>")
    if not recents:
        recents = ("<tr><td colspan='4' class='empty'>No scans yet &mdash; the "
                   "first upload starts the ledger.</td></tr>")

    body = (
        _crumb(("Workbench", "/"), ("New scan", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        "<div><h1>New scan</h1>"
        "<p>Uploads are parsed and analysed on this machine &mdash; nothing "
        "leaves 127.0.0.1.</p></div>"
        "<div class='right'><a class='ghostbtn' href='/'>"
        "<svg width='13' height='13' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='1.9' stroke-linecap='round' "
        "stroke-linejoin='round'><path d='M14 6l-6 6 6 6'/></svg>"
        "Back to board</a></div>"
        "</div></div>"
        "<div class='grid2'><div class='stack stage'>"
        "<section class='card dropcard' id='drop'>"
        "<span class='dropglyph'><svg width='24' height='24' viewBox='0 0 24 24' "
        "fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' "
        "stroke-linejoin='round'><path d='M12 16V4M7 9l5-5 5 5'/>"
        "<path d='M4 15v3.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V15'/>"
        "</svg></span>"
        "<h2>Drop a bundle to scan</h2>"
        "<p>A single APK, IPA, AAB or APKS. The bundle is unpacked, parsed and "
        "graded before a single report is written.</p>"
        "<form id='upform' style='margin:0'>"
        f"<input type='file' id='file' accept='{_e(','.join(_EXTENSIONS))}' hidden>"
        "<div style='display:flex;gap:8px;margin-top:16px;justify-content:center'>"
        "<button type='button' class='darkbtn' id='pick'>Choose file</button>"
        "<button type='submit' class='ghostbtn' id='go' disabled>Start scan</button>"
        "</div>"
        "<div class='filepick' id='filename'>no file chosen</div>"
        "<div class='formats'>"
        + "".join(f"<span class='fmt'>{_e(ext)}</span>" for ext in _EXTENSIONS)
        + "</div>"
        f"<div class='limits'>&le; {int(max_mib)} MiB per file &middot; filenames "
        "sanitised &middot; multipart parsed by hand</div>"
        "<div id='upstatus' class='limits' role='status' "
        "style='color:#5f7fc4'></div>"
        "</form></section>"
        "<section class='card'><h3>Recent uploads"
        f"<span class='pill grey'>{len(jobs)} on record</span></h3>"
        "<table class='tbl'><tr><th>Bundle</th><th>Grade</th><th>Findings</th>"
        "<th style='text-align:right'>Submitted</th></tr>"
        + recents +
        "</table></section></div>"
        "<aside class='side'>"
        "<section class='card'><h3>Scan options</h3>"
        "<dl class='facts' style='margin:0'>"
        "<div class='factrow'><dt>Severity floor</dt><dd>every finding kept</dd></div>"
        "<div class='factrow'><dt>Rule pack</dt><dd>built-in catalogue</dd></div>"
        "<div class='factrow'><dt>OSV intel</dt><dd>"
        + ("refresh stale coordinates" if refresh_intel else "use cache as-is")
        + "</dd></div>"
        f"<div class='factrow'><dt>Reports</dt><dd>{len(FORMATS)} formats per "
        "scan</dd></div>"
        f"<div class='factrow'><dt>Workers</dt><dd>{int(workers)} parallel "
        f"{'scan' if int(workers) == 1 else 'scans'}</dd></div>"
        "</dl></section>"
        "<section class='card'><h3>Limits</h3>"
        "<dl class='facts' style='margin:0'>"
        f"<div class='factrow'><dt>Max upload</dt><dd>{int(max_mib)} MiB</dd></div>"
        "<div class='factrow'><dt>Storage</dt><dd>one directory per job, kept "
        "across restarts</dd></div>"
        "<div class='factrow'><dt>Network</dt><dd>loopback only</dd></div>"
        "</dl></section>"
        "<div class='card' style='display:flex;gap:9px;align-items:flex-start;"
        "font-size:10.5px;color:#8a8e96;line-height:1.5'>"
        "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' "
        "stroke='#5f7fc4' stroke-width='2' style='flex:none;margin-top:1px'>"
        "<rect x='4' y='10' width='16' height='10' rx='2.4'/>"
        "<path d='M8 10V7a4 4 0 0 1 8 0v3'/></svg>"
        "<span><b style='color:#10141A;font-weight:600;display:block;"
        "margin-bottom:2px'>Local only</b>No authentication by design &mdash; the "
        "dashboard binds 127.0.0.1 and is not meant to be exposed on a "
        "network.</span></div>"
        "</aside></div>"
        "<script>" + _UPLOAD_JS + "</script>"
    )
    return _shell("upload", body, title="masanalyzer — new scan")


# --------------------------------------------------------------------------
# live progress (/scanning/<id>)
# --------------------------------------------------------------------------
_PROGRESS_JS = r"""
const jid = document.body.dataset.job;
const started = Date.now();
let lastDetail = "";
let finished = false;

function phaseIndex(j){
  if (j.status === "done") return 4;
  const text = ((j.phase || "") + " " + (j.detail || "")).toLowerCase();
  if (text.includes("render") || text.includes("report")) return 2;
  if (text.includes("analy") || text.includes("scan") || text.includes("rule"))
    return 1;
  return 0;
}

function addLine(text, cls){
  const log = document.getElementById("log");
  const row = document.createElement("div");
  const stamp = new Date().toLocaleTimeString();
  row.innerHTML = `<span class="ts">${stamp}</span> ` +
    `<span class="${cls || "ph"}">${String(text).replace(/[<>&]/g, "")}</span>`;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

function paint(j){
  const idx = phaseIndex(j);
  document.querySelectorAll(".step").forEach((el, i) => {
    el.classList.toggle("done", i < idx);
    el.classList.toggle("run", i === idx && j.status !== "done");
  });
  const label = j.status === "done" ? "finished"
    : j.status === "error" ? "failed" : (j.phase || "queued");
  document.getElementById("phase").textContent = label;
  document.getElementById("status").textContent = j.status;
  document.getElementById("elapsed").textContent =
    ((Date.now() - started) / 1000).toFixed(1) + " s";
  const detail = (j.phase ? j.phase + ": " : "") + (j.detail || "");
  if (detail !== lastDetail && j.status !== "done"){
    if (lastDetail) addLine(detail);
    lastDetail = detail;
  }
  if (j.status === "done" && !finished){
    finished = true;
    addLine("scan finished · grade " + (j.grade || "-") + " · " +
            (j.findings || 0) + " findings", "ok");
    document.querySelectorAll(".step").forEach(el => el.classList.add("done"));
    if (window.masToast)
      window.masToast("Scan finished · grade " + (j.grade || "-"), true);
    document.getElementById("cta").innerHTML =
      `<a class="darkbtn" href="/reports/${jid}">Open reports</a>`;
    document.getElementById("live").style.display = "none";
    setTimeout(() => { window.location.href = "/overview/" + jid; }, 900);
  }
  if (j.status === "error" && !finished){
    finished = true;
    addLine(j.error || "scan failed", "er");
    document.getElementById("cta").innerHTML =
      `<a class="darkbtn" href="/upload">Try another bundle</a>`;
  }
}

async function poll(){
  if (finished) return;
  try{
    const r = await fetch("/job/" + jid);
    if (r.ok) paint(await r.json());
  }catch(e){ /* keep polling */ }
  setTimeout(poll, 900);
}
setInterval(() => {
  document.getElementById("elapsed").textContent =
    ((Date.now() - started) / 1000).toFixed(1) + " s";
}, 100);
poll();
"""


def _phase_index(job: dict) -> int:
    if job.get("status") == _STATUS_OK:
        return 4
    text = f"{job.get('phase') or ''} {job.get('detail') or ''}".lower()
    if "render" in text or "report" in text:
        return 2
    if "analy" in text or "scan" in text or "rule" in text:
        return 1
    return 0


def _scanning_page(job: dict) -> str:
    index = _phase_index(job)
    steps = ""
    for i, (title, note) in enumerate((
            ("Unpack", "bundle directories"),
            ("Analyse", "ten categories"),
            ("Render", f"{len(FORMATS)} formats"),
            ("Ready", "grade on the board"))):
        state = "done" if i < index else ("run" if i == index else "")
        mark = ("<svg width='10' height='10' viewBox='0 0 24 24' fill='none' "
                "stroke='currentColor' stroke-width='3' stroke-linecap='round' "
                "stroke-linejoin='round'><path d='M5 12.5l4.5 4.5L19 7'/></svg>"
                if i < index else
                "<svg width='9' height='9' viewBox='0 0 24 24' fill='currentColor'>"
                "<circle cx='12' cy='12' r='4'/></svg>")
        steps += (f"<div class='step {state}'><span class='sd'>{mark}</span>"
                  f"<b>{_e(title)}</b><small>{_e(note)}</small></div>")

    submitted = str(job.get("submitted") or "").replace("T", " ")[:19]
    upload_name = os.path.basename(
        str(job.get("upload_name") or "").replace("\\", "/"))
    body = (
        _crumb(("Workbench", "/"), (str(job.get("name") or "bundle"), ""),
               ("Scanning", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{_job_icon(job, 44)}"
        f"<span>Scanning {_e(job.get('name') or 'bundle')}</span></h1>"
        "<p>the scanner reports each phase here; the transcript below is its "
        "raw callback text</p></div>"
        "<div class='right' id='cta'><a class='ghostbtn' href='/'>"
        "Back to board</a></div>"
        "</div></div>"
        "<section class='softpanel' style='margin-bottom:16px'>"
        "<div style='display:flex;align-items:center;gap:14px;"
        "margin-bottom:6px;flex-wrap:wrap'>"
        "<span class='live' id='live'><i></i>live</span>"
        "<span class='mono'>phase <b id='phase'>"
        f"{_e(job.get('phase') or job.get('status') or 'queued')}</b> &middot; "
        "<span id='elapsed'>0.0 s</span> &middot; status "
        f"<span id='status'>{_e(job.get('status') or 'queued')}</span></span></div>"
        f"<div class='steps'>{steps}</div>"
        "<div class='meter indet' style='height:5px;background:#e6e8f0'>"
        "<i></i></div>"
        "<p class='mono' style='margin:8px 0 0;font-size:9.5px'>progress follows "
        "the scanner's phase callbacks &mdash; this page polls every 0.9 s</p>"
        "</section>"
        "<div class='grid2'><div class='stack'>"
        "<section class='card'><h3>Output "
        "<span class='mono'>job transcript</span></h3>"
        "<div class='log' id='log'>"
        f"<div><span class='ts'>{_e(submitted[11:19])}</span> "
        f"<span class='ph'>queued</span> {_e(job.get('name'))} accepted</div>"
        f"<div><span class='ts'>{_e(submitted[11:19])}</span> "
        f"<span class='ph'>{_e(job.get('phase') or 'waiting')}</span> "
        f"{_e(job.get('detail') or 'waiting for a worker')}</div>"
        "<div><span class='ts'>&nbsp;</span><span class='cursor'></span></div>"
        "</div></section>"
        "<section class='card'><h3>When it finishes</h3>"
        "<p style='margin:0;font-size:11px;color:#8a8e96;line-height:1.6'>"
        f"All {len(FORMATS)} report formats are written into the job directory, "
        "the grade lands on this board, and the overview becomes available. "
        "Reports survive a restart: job.json carries the metadata.</p></section>"
        "</div><aside class='side'>"
        "<section class='card'><h3>Job</h3><dl class='facts' style='margin:0'>"
        f"<div class='factrow'><dt>Bundle</dt><dd>{_e(job.get('name'))}</dd></div>"
        f"<div class='factrow'><dt>Upload name</dt><dd><code>"
        f"{_e(upload_name)}</code></dd></div>"
        f"<div class='factrow'><dt>Job id</dt><dd><code>{_e(job.get('id'))}"
        "</code></dd></div>"
        f"<div class='factrow'><dt>Submitted</dt><dd>{_e(submitted)}</dd></div>"
        "</dl></section>"
        "<section class='card'><h3>While it runs</h3>"
        "<p style='margin:0;font-size:10.5px;color:#8a8e96;line-height:1.6'>"
        "You can leave this page &mdash; the scan keeps running and the card "
        "updates on the board. Nothing is written outside the job "
        "directory.</p></section>"
        "</aside></div>"
        "<script>" + _PROGRESS_JS + "</script>"
    )
    page = _shell("board", body, job=job,
                  title=f"masanalyzer — scanning {job.get('name') or ''}")
    return page


# --------------------------------------------------------------------------
# reports / downloads (/reports/<id>)
# --------------------------------------------------------------------------
def _reports_page(job: dict, job_dir: str, want: str = "",
                  default_preview: str = "md") -> str:
    jid = _e(job.get("id"))
    # the HTML report lives inline on the overview page, not in this list
    visible = [fmt for fmt in FORMATS if fmt != "html"]
    sizes: Dict[str, int] = {}
    written = []
    for fmt in visible:
        try:
            sizes[fmt] = os.path.getsize(os.path.join(job_dir, f"report.{fmt}"))
            written.append(fmt)
        except OSError:
            sizes[fmt] = 0
    total = sum(sizes.values())
    preferred = default_preview if default_preview in written else "md"
    preview = (want if want in written
               else preferred if preferred in written
               else (written[0] if written else ""))
    cards: Dict[str, str] = {}
    for fmt in visible:
        present = fmt in written
        view = (f"/view/{jid}/{fmt}" if fmt in ("json", "md", "sarif")
                else f"/report/{jid}/{fmt}")
        actions = (
            f"<a class='mini ghost' href='{view}' target='_blank' "
            "rel='noopener'>Preview</a>"
            f"<a class='mini dark' href='/download/{jid}/{fmt}'>Download</a>"
            if present else
            "<span class='mini ghost' style='opacity:.55'>not written</span>")
        cards[fmt] = (
            "<article class='card fmtcard'>"
            "<div class='fh'>"
            f"<span class='badge{' dark' if fmt == 'json' else ''}'>"
            f"{_e(_FORMAT_LABEL.get(fmt, fmt.upper()))}</span>"
            f"<b>report.{_e(fmt)}</b>"
            f"<span class='size'>{_fmt_bytes(sizes[fmt]) if present else '&mdash;'}"
            "</span></div>"
            f"<p class='note'>{_e(_FORMAT_NOTE.get(fmt, ''))}</p>"
            f"<div class='acts'>{actions}</div>"
            "</article>")

    # Miller's law: three small groups instead of one list of ten.
    groups = (
        ("Evidence", ("json", "sarif", "sbom", "csv")),
        ("Readable", ("md", "html", "pdf")),
        ("CI and audit", ("junit", "gitlab", "audit")),
    )
    used = {fmt for _, members in groups for fmt in members}
    extra = [fmt for fmt in visible if fmt not in used]
    if extra:
        groups = groups + (("Other", tuple(extra)),)
    sections = ""
    for name, members in groups:
        present_members = [fmt for fmt in members if fmt in visible]
        if not present_members:
            continue
        sections += (
            "<div class='grouphead'><b>" + _e(name) + "</b>"
            f"<span>{len(present_members)} formats</span><i></i></div>"
            "<div class='fmtgrid stage'>"
            + "".join(cards[fmt] for fmt in present_members)
            + "</div>")

    tabs = "".join(
        f"<a class='{'on' if fmt == preview else ''}' "
        f"href='/reports/{jid}?fmt={fmt}'>{_e(fmt)}</a>" for fmt in written)
    frame = ""
    if preview == "pdf":
        frame = ("<div class='previewframe'><div class='previewtabs'>" + tabs +
                 "</div><p style='margin:0;font-size:11px;color:#8a8e96'>PDF "
                 "previews depend on the browser's viewer &mdash; open it in a "
                 f"tab or <a href='/download/{jid}/pdf'>download it</a>.</p></div>")
    elif preview:
        frame = ("<div class='previewframe'><div class='previewtabs'>" + tabs +
                 "</div><iframe title='report preview' loading='lazy' "
                 f"src='/report/{jid}/{_e(preview)}'></iframe></div>")
    findings = job.get("findings")
    body = (
        _crumb(("Workbench", "/"),
               (str(job.get("name") or "bundle"), f"/overview/{jid}"),
               ("Reports", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{_job_icon(job, 44)}<span>Reports</span></h1>"
        f"<p>{len(written)} of {len(visible)} formats written &middot; "
        f"{_e(findings if findings is not None else 0)} findings &middot; "
        f"{_fmt_bytes(total)} on disk</p></div>"
        "<div class='right'>"
        f"<a class='ghostbtn' href='/overview/{jid}'>Overview</a>"
        f"<a class='darkbtn' href='/download/{jid}/pdf'>Download PDF</a>"
        "</div></div></div>"
        "<div class='panel-h' style='padding:0 2px 14px'>"
        f"<span class='pill {'green' if written else 'red'}'>"
        f"{len(written)} of {len(visible)} written</span>"
        f"<span class='pill grey'>job {_e(str(job.get('id') or '')[:8])}</span>"
        "<span class='pill grey'>deterministic output</span>"
        "<span class='mono' style='margin-left:auto'>inline preview &middot; raw "
        "download</span></div>"
        + sections
        + frame
    )
    return _shell("reports", body, job=job,
                  title=f"masanalyzer — reports · {job.get('name') or ''}")

# --------------------------------------------------------------------------
# overview page (/overview/<id>)
# --------------------------------------------------------------------------
def _pl_pill(level: str) -> str:
    lvl = str(level or "").strip().lower()
    cls = ("red" if lvl == "dangerous"
           else "blue" if lvl == "signature"
           else "grey")
    return f"<span class='pill {cls}'>{_e(level or '-')}</span>"


def _niap_pill(status: str) -> str:
    s = str(status or "").strip().lower()
    cls = "green" if s == "pass" else "amber" if s == "attention" else "grey"
    return f"<span class='pill {cls}'>{_e(status or '-')}</span>"


def _job_icon(job: dict, size: int = 44) -> str:
    """The bundle's extracted icon, or its initials avatar as a fallback."""
    jid = str(job.get("id") or "")
    if str(job.get("icon") or "") and jid:
        return (f"<img class='jobicon' src='/icon/{_e(jid)}' alt='' "
                f"width='{int(size)}' height='{int(size)}' loading='lazy' "
                f"style='width:{int(size)}px;height:{int(size)}px'>")
    name = str(job.get("name") or "bundle")
    return (f"<span class='jobicon {_avatar_class(name)}' aria-hidden='true' "
            f"style='width:{int(size)}px;height:{int(size)}px;"
            f"font-size:{max(9, int(size) // 3)}px'>"
            f"{_e(_initials(name))}</span>")


def _copy_btn(value: str, label: str) -> str:
    """Copy-to-clipboard button (30 px target, toast on click)."""
    safe = _e(value)
    return (
        f"<button class='copy' data-copy='{safe}' title='Copy {_e(label)}' "
        f"aria-label='Copy {_e(label)}'>"
        "<svg width='12' height='12' viewBox='0 0 24 24' fill='none' "
        "stroke='currentColor' stroke-width='1.9' stroke-linejoin='round'>"
        "<rect x='9' y='9' width='11' height='11' rx='2'/>"
        "<path d='M6.5 15H5.5A1.5 1.5 0 0 1 4 13.5v-9A1.5 1.5 0 0 1 5.5 3h9"
        "A1.5 1.5 0 0 1 16 4.5v1'/></svg></button>")


def _rows(value: Any) -> list:
    """The rows of a report section, whatever envelope produced it.

    Inventory sections arrive as ``{"total": n, "rows": [...]}`` in current
    reports, as a bare list in older ones, and a few producers store a single
    bare record.  Iterating the envelope dict itself yields its keys, which
    is exactly the bug that turned the callsite table into two rows named
    "total" and "rows".
    """
    if isinstance(value, dict):
        for key in ("rows", "items", "entries", "records", "values"):
            inner = value.get(key)
            if isinstance(inner, list):
                return inner
        return [value] if value else []
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _facts(rows: list, empty: str = "&mdash;") -> str:
    if not rows:
        return f"<p class='empty'>{empty}</p>"
    return "<dl class='facts' style='margin:0'>" + "".join(
        f"<div class='factrow'><dt>{k}</dt><dd>{v}</dd></div>"
        for k, v in rows) + "</dl>"


def _overview_page(job: dict, ov: dict, inv: Optional[dict] = None,
                   report: Optional[dict] = None) -> str:
    """At-a-glance fact page built from the stored report.json.

    The report's own sections (score table, callsite receipts, findings)
    are rendered as cards in the same visual language as the fact cards,
    so the overview is the report - no nested document.
    """
    file_facts = ov.get("file") or {}
    app = dict(ov.get("app") or {})
    comps = app.pop("components", None) or {}
    sig = ov.get("signature") or {}
    surf = ov.get("surface") or {}
    score = ov.get("score") or {}
    findings = ov.get("findings") or {}
    perms = ov.get("permissions") or []
    trackers = ov.get("trackers") or {}
    inv = inv or {}
    behaviour = (inv.get("behaviour") or ov.get("behaviour") or {})
    niap = (inv.get("niap") or ov.get("niap") or {})
    report = report or {}

    jid = _e(str(job.get("id") or ""))
    name = _e(str(job.get("name") or "bundle"))
    grade = str(score.get("grade") or "")
    total = score.get("total")
    sev = findings.get("by_severity") or {}
    tiers = findings.get("by_assurance") or {}

    # --- file information ---------------------------------------------------
    file_rows: list = []
    if file_facts.get("name"):
        file_rows.append(("File name", _e(file_facts["name"])))
    if file_facts.get("size_bytes") is not None:
        size = int(file_facts["size_bytes"] or 0)
        file_rows.append(("Size", f"{size:,} bytes ({_fmt_bytes(size)})"))
    for key in ("md5", "sha1", "sha256"):
        if file_facts.get(key):
            digest = str(file_facts[key])
            file_rows.append((key.upper(),
                              f"<span style='display:inline-flex;align-items:center;"
                              f"gap:4px;min-width:0'><code style='overflow-wrap:anywhere'>"
                              f"{_e(digest)}</code>{_copy_btn(digest, key.upper())}</span>"))

    # --- app information ----------------------------------------------------
    app_rows = [
        (label, _e(str(app[key])))
        for label, key in (
            ("App name", "app_name"), ("Package", "package"),
            ("Version name", "version_name"), ("Version code", "version_code"),
            ("Min SDK", "min_sdk"), ("Target SDK", "target_sdk"),
            ("Max SDK", "max_sdk"), ("Main activity", "main_activity"),
            ("Application class", "application_class"))
        if app.get(key) not in (None, "")]
    if comps.get("text"):
        app_rows.append(("Components", _e(comps["text"])))
    elif comps:
        app_rows.append((
            "Components",
            f"{comps.get('activities', 0)} activities &middot; "
            f"{comps.get('services', 0)} services &middot; "
            f"{comps.get('receivers', 0)} receivers &middot; "
            f"{comps.get('providers', 0)} providers "
            f"({comps.get('exported', 0)} exported)"))

    # --- signature ----------------------------------------------------------
    sig_rows: list = [("Signed", "<b>yes</b>" if sig.get("signed") else
                       "<b style='color:#b45252'>no</b>")]
    schemes = sig.get("schemes") or {}
    scheme_txt = ", ".join(
        s for s in ("v1", "v2", "v3", "v3.1", "v3.2", "v4")
        if (schemes.get(s) or {}).get("present"))
    if scheme_txt:
        sig_rows.append(("Schemes", _e(scheme_txt)))
    for cert in sig.get("certificates") or []:
        for field, title in (
                ("subject", "Subject"), ("issuer", "Issuer"),
                ("not_before", "Valid from"), ("not_after", "Valid to"),
                ("key_algorithm", "Key algorithm"), ("key_bits", "Key bits"),
                ("signature_algorithm", "Signature algorithm"),
                ("sha256", "Fingerprint")):
            if cert.get(field) in (None, ""):
                continue
            value = str(cert[field])
            sig_rows.append((title,
                             f"<code style='overflow-wrap:anywhere'>{_e(value)}</code>"
                             + _copy_btn(value, "fingerprint")
                             if field == "sha256" else _e(value)))

    # --- attack surface -----------------------------------------------------
    surface_rows: list = []
    queue = surf.get("fix_first") or []
    if surf.get("external_entry_points") is not None:
        surface_rows += [
            ("Exported components",
             f"<b>{int(surf.get('external_entry_points', 0))}</b>"),
            ("Unguarded",
             f"<b>{int(surf.get('unprotected_entry_points', 0))}</b>"),
            ("Browsable deep links",
             f"{int(surf.get('browsable_deep_links', 0))}"),
            ("Findings on the surface",
             f"{int(surf.get('surface_findings', 0))}"),
        ]
    fix_rows = ""
    for item in queue[:4]:
        why = "; ".join(_e(str(w)) for w in (item.get("why") or []))
        fix_rows += (
            "<div class='factrow' style='grid-template-columns:minmax(0,1fr) 54px'>"
            f"<dt style='color:#3c4048'><code>{_e(str(item.get('component', '')))}"
            f"</code><br><span style='font-size:10px;color:#a8abb3'>{why}</span></dt>"
            f"<dd style='text-align:right'><span class='pill amber'>"
            f"{_e(str(item.get('score', '')))}</span></dd></div>")

    # --- permissions --------------------------------------------------------
    perm_rows = "".join(
        "<tr>"
        f"<td><code>{_e(p.get('name', ''))}</code></td>"
        f"<td>{_pl_pill(p.get('protection_level', ''))}</td>"
        f"<td>{_e(p.get('description', ''))}</td>"
        "</tr>" for p in perms)

    # --- assurance matrix ---------------------------------------------------
    niap_rows = "".join(
        "<tr>"
        f"<td><code>{_e(str(r.get('identifier', '')))}</code></td>"
        f"<td>{_e(str(r.get('requirement', '')))}</td>"
        f"<td>{_niap_pill(r.get('status', ''))}</td>"
        f"<td style='font-size:10.5px;color:#8a8e96'>"
        f"{_e(str(r.get('detail', '')))}</td>"
        "</tr>" for r in (niap.get("rows") or []))

    # --- behaviour ----------------------------------------------------------
    beh_rows = ""
    for item in (behaviour.get("behaviours") or [])[:12]:
        methods = "".join(
            f"<code style='font-size:9.5px'>{_e(str(m))}</code> "
            for m in (item.get("methods") or [])[:4])
        beh_rows += (
            "<tr>"
            f"<td><code>{_e(str(item.get('id', '')))}</code></td>"
            f"<td><b>{_e(str(item.get('title', '')))}</b><br>"
            f"<span style='font-size:10px;color:#a8abb3'>"
            f"{_e(str(item.get('description', ''))[:110])}</span></td>"
            f"<td class='mono'>{_e(str(item.get('receipts', 0)))}</td>"
            f"<td>{methods}</td></tr>")

    # --- score table (from the report's own score section) ------------------
    score_rows = ""
    for cat in ((report.get("score") or {}).get("categories") or []):
        if cat.get("in_scope") is False:
            continue
        cat_grade = str(cat.get("grade") or "")
        gcls = ("green" if cat_grade in ("A+", "A", "B")
                else "red" if cat_grade == "F" else "amber")
        score_rows += (
            "<tr>"
            f"<td><code>{_e(str(cat.get('id', '')))}</code></td>"
            f"<td>{_e(str(cat.get('name', '')))}</td>"
            f"<td class='mono' style='text-align:right'>"
            f"{_e(str(cat.get('score', '')))}</td>"
            f"<td><span class='pill {gcls}'>{_e(cat_grade or '-')}</span></td>"
            f"<td class='mono' style='text-align:right'>"
            f"{int(cat.get('findings', 0) or 0)}</td></tr>")

    # --- callsite receipts --------------------------------------------------
    callsite_rows = ""
    # the inventory hands most sections back as {"total": n, "rows": [...]};
    # iterating that dict directly is what once printed "total"/"rows" here
    callsite_section = inv.get("callsites")
    callsites = _rows(callsite_section)
    observed = (callsite_section.get("total")
                if isinstance(callsite_section, dict) else None)
    if not isinstance(observed, int):
        observed = len(callsites)
    for rec in callsites[:10]:
        if not isinstance(rec, dict):
            rec = {"url": rec}
        callsite_rows += (
            "<tr>"
            f"<td><code style='overflow-wrap:anywhere'>"
            f"{_e(str(rec.get('url', '')))}</code></td>"
            f"<td><code>{_e(str(rec.get('method', '')))}</code><br>"
            f"<span style='font-size:10px;color:#a8abb3'>"
            f"{_e(str(rec.get('callee', '')))}</span></td>"
            f"<td class='mono' style='text-align:right'>"
            f"{_e(str(rec.get('offset', '')))}</td></tr>")

    # --- endpoints ----------------------------------------------------------
    endpoint_section = inv.get("endpoints")
    endpoint_data = _rows(endpoint_section)
    endpoint_total = (endpoint_section.get("total")
                      if isinstance(endpoint_section, dict) else None)
    if not isinstance(endpoint_total, int):
        endpoint_total = len(endpoint_data)
    endpoint_counts = (endpoint_section.get("counts") or {}
                       if isinstance(endpoint_section, dict) else {})
    endpoint_rows = ""
    for rec in sorted((r for r in endpoint_data if isinstance(r, dict)),
                      key=lambda r: -int(r.get("occurrences") or 0))[:10]:
        cls = str(rec.get("classification") or rec.get("kind") or "")
        flags = (" <span class='pill amber'>cleartext</span>"
                 if rec.get("cleartext") else "")
        endpoint_rows += (
            "<tr>"
            f"<td><code style='overflow-wrap:anywhere'>"
            f"{_e(str(rec.get('host') or ''))}</code></td>"
            f"<td><span class='pill {_ENDPOINT_PILL.get(cls, 'grey')}'>"
            f"{_e(cls or '-')}</span>{flags}</td>"
            f"<td class='mono' style='text-align:right'>"
            f"{int(rec.get('occurrences') or 0)}</td></tr>")
    # trackers are the tracker-classified endpoint hosts, summed by host
    tracker_hosts: Dict[str, int] = {}
    for rec in endpoint_data:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("classification") or "").lower() != "tracker":
            continue
        host = str(rec.get("host") or "")
        if host:
            tracker_hosts[host] = (tracker_hosts.get(host, 0)
                                   + int(rec.get("occurrences") or 0))
    tracker_rows = "".join(
        "<tr>"
        f"<td><code style='overflow-wrap:anywhere'>{_e(host)}</code></td>"
        f"<td class='mono' style='text-align:right'>{int(count)}</td></tr>"
        for host, count in sorted(tracker_hosts.items(),
                                  key=lambda kv: -kv[1])[:12])
    endpoint_chips = "".join(
        f"<span class='pill {_ENDPOINT_PILL.get(str(k), 'grey')}'>"
        f"{_e(str(k).replace('_', ' '))} {int(v)}</span>"
        for k, v in endpoint_counts.items() if int(v or 0))

    # --- privacy ------------------------------------------------------------
    privacy_section = inv.get("privacy")
    privacy_rows = ""
    for rec in _rows(privacy_section)[:10]:
        if not isinstance(rec, dict):
            continue
        perm = str(rec.get("permission") or "")
        short = perm.replace("android.permission.", "") or perm
        markers = ", ".join(
            str(o.get("marker") or "") if isinstance(o, dict) else str(o)
            for o in (rec.get("observed") or [])[:2])
        status = ("<span class='pill green'>corroborated</span>"
                  if rec.get("corroborated")
                  else "<span class='pill grey'>unconfirmed</span>")
        privacy_rows += (
            "<tr>"
            f"<td><code title='{_e(perm)}'>{_e(short)}</code></td>"
            f"<td class='mono' style='text-align:right'>"
            f"{int(rec.get('signals') or 0)}</td>"
            f"<td><span style='font-size:10px;color:#a8abb3'>"
            f"{_e(markers) if markers else '&mdash;'}</span></td>"
            f"<td>{status}</td></tr>")
    privacy_dangerous = (privacy_section.get("dangerous")
                         if isinstance(privacy_section, dict) else 0) or 0
    privacy_excess = (privacy_section.get("excess")
                      if isinstance(privacy_section, dict) else 0) or 0

    # --- findings -----------------------------------------------------------
    find_rows = ""
    by_sev: Dict[str, list] = {}
    all_findings = list(report.get("findings") or [])
    for index, f in enumerate(all_findings, 1):
        ev = f.get("evidence") or {}
        sev_name = str(f.get("severity") or "")
        loc = str(ev.get("location") or ev.get("file") or "")
        tier = str(f.get("assurance") or "")
        find_rows += (
            f"<tr data-sev='{_e(sev_name or 'info')}'>"
            f"<td><span class='pill {_SEV_CLASS.get(sev_name, 'grey')}'>"
            f"{_e(sev_name)}</span></td>"
            f"<td><a href='#fnd-{index}'><code>{_e(str(f.get('rule_id', '')))}</code></a>"
            f"<br><span style='color:#4d5159'>{_e(str(f.get('title', '')))}</span></td>"
            + (f"<td><span class='pill {'green' if tier == 'verified' else 'blue' if tier == 'structural' else 'grey'}'>"
               f"{_e(tier)}</span></td>" if tier else "<td>&mdash;</td>")
            + (f"<td><code style='overflow-wrap:anywhere;font-size:10px'>"
               f"{_e(loc)}</code></td>" if loc else "<td>&mdash;</td>")
            + "</tr>")
        # full finding card - the same content the HTML/markdown report has
        metas = []
        if f.get("confidence"):
            metas.append(f"confidence: {_e(str(f['confidence']))}")
        if tier:
            metas.append(f"assurance: {_e(tier)}")
        if f.get("owasp"):
            metas.append(f"OWASP {_e(str(f['owasp']))}")
        if f.get("cwe"):
            metas.append(_e(str(f["cwe"])))
        if f.get("cvss") is not None:
            metas.append(f"CVSS {_e(str(f['cvss']))}")
        bits = ""
        if f.get("description"):
            bits += (f"<p style='margin:8px 0 0;font-size:12px'>"
                     f"{_e(str(f['description']))}</p>")
        if loc:
            bits += f"<p style='margin:8px 0 0'><code style='overflow-wrap:anywhere'>{_e(loc)}</code></p>"
        if ev.get("symbol"):
            bits += (f"<p class='fndmeta'>Matched <code>{_e(str(ev['symbol']))}"
                     "</code></p>")
        if ev.get("snippet"):
            where = (f" (line {_e(str(ev.get('line')))})"
                     if ev.get("line") else "")
            bits += (f"<p class='fndmeta'>Exact code{where}</p>"
                     f"<pre><code>{_e(str(ev['snippet'])[:400])}</code></pre>")
        if ev.get("note"):
            bits += f"<p class='fndmeta'>How detected: {_e(str(ev['note']))}</p>"
        if f.get("remediation"):
            bits += (f"<p style='margin:8px 0 0'><b>Remediation:</b> "
                     f"{_e(str(f['remediation']))}</p>")
        if f.get("poc"):
            bits += (f"<p style='margin:8px 0 0'><b>PoC:</b> <code>"
                     f"{_e(str(f['poc'])[:400])}</code></p>")
        if f.get("references"):
            bits += ("<p class='fndmeta'>References: " + ", ".join(
                _e(str(r)) for r in f["references"]) + "</p>")
        by_sev.setdefault(sev_name or "info", []).append(
            f"<section class='card fnd' id='fnd-{index}'>"
            "<div class='fndhead'>"
            f"<span class='pill {_SEV_CLASS.get(sev_name, 'grey')}'>"
            f"{_e(sev_name)}</span>"
            f"<h3>{index}. <code>{_e(str(f.get('rule_id', '')))}</code>"
            f" &mdash; {_e(str(f.get('title', '')))}</h3></div>"
            + (f"<p class='fndmeta'>{' &middot; '.join(metas)}</p>"
               if metas else "")
            + bits + "</section>")

    # severity groups: one collapsible block per severity, worst first
    sev_groups = ""
    sev_order = ["critical", "high", "medium", "low", "info"]
    order = sev_order + [s for s in by_sev if s not in sev_order]
    filter_btns = (
        "<button class='on' data-filter='' aria-pressed='true'>All"
        f"<span>{len(all_findings)}</span></button>")
    for sev_key in order:
        if by_sev.get(sev_key):
            filter_btns += (
                f"<button data-filter='{_e(sev_key)}' aria-pressed='false'>"
                f"{_e(sev_key)}<span>{len(by_sev[sev_key])}</span></button>")
    for sev_key in order:
        group = by_sev.get(sev_key) or []
        if not group:
            continue
        sev_groups += (
            f"<details class='sevgroup' id='sev-{_e(sev_key)}' "
            f"data-sev='{_e(sev_key)}'>"
            "<summary>"
            f"<span class='pill {_SEV_CLASS.get(sev_key, 'grey')}'>"
            f"{_e(sev_key)}</span>"
            f"<b>{_e(sev_key.capitalize())}</b>"
            f"<span class='mono' style='margin-left:auto;font-size:10px'>"
            f"{len(group)} finding{'s' if len(group) != 1 else ''}</span>"
            "<svg class='chev' width='12' height='12' viewBox='0 0 24 24' "
            "fill='none' stroke='currentColor' stroke-width='2.2' "
            "stroke-linecap='round' stroke-linejoin='round'>"
            "<polyline points='6 9 12 15 18 9'/></svg>"
            "</summary>"
            "<div class='sevbody'>" + "".join(group) + "</div></details>")

    # --- hero ---------------------------------------------------------------
    sev_html = "".join(
        f"<span class='pill {_SEV_CLASS.get(k, 'grey')}'>{int(v)} {_e(k)}</span>"
        for k, v in sorted((sev or {}).items(), key=lambda kv: -kv[1])
        if int(v or 0) > 0)
    tier_html = "".join(
        f"<span class='pill {'green' if k == 'verified' else 'blue' if k == 'structural' else 'grey'}'>"
        f"{_e(k)} {int(v)}</span>"
        for k, v in sorted((tiers or {}).items(), key=lambda kv: -kv[1]))
    surface_line = ""
    if surf.get("external_entry_points") is not None:
        surface_line = (
            f"{int(surf.get('external_entry_points', 0))} exported &middot; "
            f"{int(surf.get('unprotected_entry_points', 0))} unguarded &middot; "
            f"{int(surf.get('browsable_deep_links', 0))} deep links")

    hero = (
        "<section class='softpanel' style='display:flex;gap:26px;"
        "align-items:center;flex-wrap:wrap'>"
        "<div style='display:flex;gap:16px;align-items:center'>"
        + _job_icon(job, 56) +
        f"{_donut(total, grade, 104, 'of 100')}"
        f"<div><div style='font-size:22px;font-weight:600;letter-spacing:-.03em'>"
        f"Grade {_e(grade or '-')}</div>"
        f"<div class='mono' style='margin-top:2px'>"
        f"{_e(findings.get('total', 0))} findings</div>"
        f"<div style='display:flex;gap:5px;flex-wrap:wrap;margin-top:8px'>"
        f"{sev_html or '<span class=pill grey>no findings</span>'}</div></div>"
        "</div>"
        "<div style='flex:1;min-width:220px'>"
        "<div class='mono' style='font-size:9px;letter-spacing:.08em;"
        "text-transform:uppercase;color:#a8abb3;margin-bottom:6px'>Assurance</div>"
        f"<div style='display:flex;gap:5px;flex-wrap:wrap'>{tier_html}</div>"
        "<div class='mono' style='font-size:9px;letter-spacing:.08em;"
        "text-transform:uppercase;color:#a8abb3;margin:14px 0 6px'>Attack surface"
        "</div>"
        f"<div style='font-size:11.5px;color:#4d5159'>{surface_line or '&mdash;'}"
        "</div></div>"
        "<div style='display:flex;flex-direction:column;gap:7px'>"
        f"<a class='darkbtn' href='/reports/{jid}'>All reports</a>"
        f"<a class='ghostbtn' href='/view/{jid}/md'>Read report.md</a>"
        "</div></section>")

    body = (
        _crumb(("Workbench", "/"), (str(job.get("name") or "bundle"), ""),
               ("Overview", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{name}</h1>"
        f"<p>{_e(app.get('package') or 'package unknown')}"
        + (f" &middot; {_e(app.get('version_name'))}" if app.get("version_name") else "")
        + f" &middot; {_e(findings.get('total', 0))} findings</p></div>"
        "<div class='right'>"
        f"<a class='ghostbtn' href='/reports/{jid}'>Reports</a>"
        f"<a class='darkbtn' href='/download/{jid}/html'>Download HTML</a>"
        "</div></div></div>"
        + hero +
        "<div class='grid2 stage' style='margin-top:16px'><div class='stack'>"
        "<section class='card' id='file'><h3>File information</h3>"
        + _facts(file_rows, "no file facts in report.json") +
        "</section>"
        "<section class='card' id='app'><h3>App information</h3>"
        + _facts(app_rows, "no manifest facts in report.json") +
        "</section>"
        + (("<section class='card' id='scorecard'><h3>Compliance score"
            f"<span class='pill grey'>{_e(str(total if total is not None else '-'))}"
            " / 100</span></h3>"
            "<table class='tbl'><tr><th>ID</th><th>Category</th><th>Score</th>"
            "<th>Grade</th><th>Findings</th></tr>" + score_rows + "</table>"
            "</section>") if score_rows else "") +
        "<section class='card' id='perms'><h3>Permissions"
        f"<span class='pill grey'>{len(perms)} declared</span></h3>"
        + ("<table class='tbl'><tr><th>Permission</th><th>Protection</th>"
           "<th>Description</th></tr>" + perm_rows + "</table>"
           if perms else "<p class='empty'>No permissions declared.</p>") +
        "<p class='mono' style='margin:10px 0 0;font-size:9.5px'>dangerous "
        "permissions need a runtime grant on modern Android</p></section>"
        "<section class='card' id='surface'><h3>Attack surface"
        f"<span class='pill grey'>"
        f"{int(surf.get('external_entry_points', 0) or 0)} exported</span></h3>"
        + _facts(surface_rows) +
        ("<h3 style='margin-top:14px'>Fix first</h3>"
         "<dl class='facts' style='margin:0'>" + fix_rows + "</dl>"
         if fix_rows else "") +
        "</section>"
        + (("<section class='card' id='assurance'><h3>Assurance matrix"
            f"<span class='pill grey'>{len(niap.get('rows') or [])} rows"
            "</span></h3>"
            "<table class='tbl'><tr><th>ID</th><th>Requirement</th><th>Status</th>"
            "<th>Detail</th></tr>" + niap_rows + "</table>"
            + (f"<p class='mono' style='margin:10px 0 0;font-size:9.5px'>"
               f"{_e(str(niap.get('note', '')))}</p>" if niap.get("note") else "")
            + "</section>") if niap_rows else "")
        + (("<section class='card' id='behaviour'><h3>Behaviour analysis"
            f"<span class='pill grey'>{int(behaviour.get('total_receipts', 0) or 0)} receipts"
            "</span></h3>"
            "<table class='tbl'><tr><th>ID</th><th>Behaviour</th><th>Hits</th>"
            "<th>Declaring methods</th></tr>" + beh_rows + "</table>"
            "</section>") if beh_rows else "")
        + (("<section class='card' id='callsites'><h3>Callsite receipts"
            f"<span class='pill grey'>{int(observed)} observed</span></h3>"
            "<table class='tbl'><tr><th>URL</th><th>Method &middot; callee</th>"
            "<th>Offset</th></tr>" + callsite_rows + "</table>"
            + (f"<p class='mono' style='margin:10px 0 0;font-size:9.5px'>"
               f"showing 10 of {int(observed)}"
               f" &middot; full list in report.json</p>"
               if len(callsites) > 10 else "")
            + "</section>") if callsite_rows else "")
        + (("<section class='card' id='endpoints'><h3>Endpoints"
            f"<span class='pill grey'>{int(endpoint_total)} hosts</span></h3>"
            + (f"<div style='display:flex;gap:5px;flex-wrap:wrap;"
               f"margin-bottom:10px'>{endpoint_chips}</div>"
               if endpoint_chips else "")
            + "<table class='tbl'><tr><th>Host</th><th>Class</th>"
            "<th>Occurrences</th></tr>" + endpoint_rows + "</table>"
            + (f"<p class='mono' style='margin:10px 0 0;font-size:9.5px'>"
               f"top 10 of {int(endpoint_total)} &middot; full list in "
               "report.json</p>" if len(endpoint_data) > 10 else "")
            + "</section>") if endpoint_rows else "")
        + (("<section class='card' id='trackers'><h3>Trackers"
            f"<span class='pill red'>{len(tracker_hosts)} hosts</span></h3>"
            "<table class='tbl'><tr><th>Host</th><th>Calls</th></tr>"
            + tracker_rows + "</table>"
            + (f"<p class='mono' style='margin:10px 0 0;font-size:9.5px'>"
               f"showing 12 of {len(tracker_hosts)}"
               " &middot; full list in report.json</p>"
               if len(tracker_hosts) > 12 else "")
            + "</section>") if tracker_rows else "")
        + (("<section class='card' id='privacy'><h3>Privacy"
            f"<span class='pill grey'>{int(privacy_dangerous)} dangerous"
            f" &middot; {int(privacy_excess)} excess</span></h3>"
            "<table class='tbl'><tr><th>Permission</th><th>Signals</th>"
            "<th>Observed</th><th>Status</th></tr>" + privacy_rows
            + "</table>"
            "<p class='mono' style='margin:10px 0 0;font-size:9.5px'>"
            "a permission is <b>excess</b> when it is declared but no "
            "marker in the code uses it &middot; corroborated = seen on "
            "more than one surface</p></section>") if privacy_rows else "")
        + (("<section class='card' id='findings'><h3>Findings"
            f"<span class='pill grey'>{len(all_findings)} total</span></h3>"
            "<table class='tbl'><tr><th>Severity</th><th>Rule &middot; title</th>"
            "<th>Assurance</th><th>Location</th></tr>" + find_rows + "</table>"
            f"<p class='mono' style='margin:8px 0 0;font-size:9.5px'>"
            f"<a href='/view/{jid}/md'>read the full report.md</a></p>"
            "</section>") if find_rows else "")
        + (("<div class='sevbar'>"
            f"<span class='mono'>{len(all_findings)} findings by severity</span>"
            f"<div class='sevfilter' role='group' aria-label='Filter by severity'>"
            f"{filter_btns}</div>"
            "<button class='mini ghost' data-expand='all'>Expand all</button>"
            "<button class='mini ghost' data-expand='none'>Collapse all</button>"
            "</div>") if sev_groups else "")
        + sev_groups
        + (f"<section class='card'><h3>Trackers</h3>"
           f"<p style='margin:0;font-size:12px'><b>{int(trackers.get('count', 0))}</b> "
           f"{_e(str(trackers.get('note') or 'tracker endpoints observed'))}</p>"
           "</section>" if trackers.get("count") and not tracker_rows else "")
        + "</div><aside class='side'>"
        "<section class='card'><h3>Signer certificate</h3>"
        + _facts(sig_rows, "the bundle is unsigned") +
        "</section>"
        "<section class='card'><h3>Reports</h3>"
        "<div class='anchorlist'>"
        + "".join(
            f"<a href='/download/{jid}/{fmt}'>{_e(_FORMAT_LABEL.get(fmt, fmt))}"
            f" <span class='mono' style='margin-left:auto'>.{_e(fmt)}</span></a>"
            for fmt in FORMATS)
        + "</div></section>"
        "<section class='card'><h3>Job</h3>"
        "<dl class='facts' style='margin:0'>"
        f"<div class='factrow'><dt>Job id</dt><dd style='display:flex;"
        "align-items:center;gap:2px;min-width:0'>"
        f"<code style='overflow-wrap:anywhere'>{jid}</code>"
        f"{_copy_btn(str(job.get('id') or ''), 'job id')}</dd></div>"
        f"<div class='factrow'><dt>Submitted</dt><dd>{_e(str(job.get('submitted') or '')[:19])}</dd></div>"
        f"<div class='factrow'><dt>Status</dt><dd>{_e(job.get('status'))}</dd></div>"
        "</dl></section>"
        "</aside></div>"
    )
    return _shell("overview", body, job=job,
                  title=f"masanalyzer — {job.get('name') or 'overview'}")

# --------------------------------------------------------------------------
# report viewers (/view/<id>/<fmt>) — markdown, json tree, sarif triage
# --------------------------------------------------------------------------
_MD_H = re.compile(r"^(#{1,4})\s+(.*)$")
_MD_TABLE_SEP = re.compile(r"^\|[\s:|-]+\|?$")
_MD_OL = re.compile(r"^\d+\.\s+(.*)$")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")


def _md_inline(text: str) -> str:
    """Inline markdown on already-escaped text (bold, code, links)."""
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    return _MD_LINK.sub(r"<a href='\2'>\1</a>", t)


def _md_to_html(md_text: str) -> Tuple[str, list]:
    """Tiny safe markdown renderer: headings, pipe tables, lists, paragraphs.

    Every source line is HTML-escaped before inline styling, so app-controlled
    text can never inject markup.  Returns (html, nav) where nav lists
    ``(id, plain_title)`` for every h2/h3.
    """
    e = html.escape
    out: list = []
    nav: list = []
    para: list = []

    def flush() -> None:
        if para:
            out.append("<p>" + "<br>".join(_md_inline(x) for x in para) + "</p>")
            para.clear()

    lines = md_text.splitlines()
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            flush()
            i += 1
            continue
        m = _MD_H.match(s)
        if m:
            flush()
            lvl, txt = len(m.group(1)), _md_inline(e(m.group(2)))
            if lvl <= 3:
                hid = f"ms{len(nav)}"
                nav.append((hid, re.sub(r"<[^>]+>", "", m.group(2))[:60]))
                out.append(f"<h{lvl} id='{hid}'>{txt}</h{lvl}>")
            else:
                out.append(f"<h{lvl}>{txt}</h{lvl}>")
            i += 1
            continue
        if s in ("---", "***", "___"):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if s.startswith("|") and i + 1 < len(lines) \
                and _MD_TABLE_SEP.match(lines[i + 1].strip()):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i].strip())
                i += 1
            cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
            out.append("<div class='tw'><table><tr>"
                       + "".join(f"<th>{_md_inline(e(c))}</th>"
                                 for c in cells[0])
                       + "</tr>")
            for r in cells[2:]:
                out.append("<tr>" + "".join(
                    f"<td>{_md_inline(e(c))}</td>" for c in r) + "</tr>")
            out.append("</table></div>")
            continue
        if _MD_OL.match(s):
            flush()
            items = []
            while i < len(lines) and _MD_OL.match(lines[i].strip()):
                items.append(_MD_OL.match(lines[i].strip()).group(1))
                i += 1
            out.append("<ol>" + "".join(
                f"<li>{_md_inline(e(x))}</li>" for x in items) + "</ol>")
            continue
        if s.startswith("- ") or s.startswith("* "):
            flush()
            items = []
            while i < len(lines) and lines[i].strip().startswith(("- ", "* ")):
                items.append(lines[i].strip()[2:])
                i += 1
            out.append("<ul>" + "".join(
                f"<li>{_md_inline(e(x))}</li>" for x in items) + "</ul>")
            continue
        para.append(e(s))
        i += 1
    flush()
    return "\n".join(out), nav


def _formats_card(job: dict, current: str) -> str:
    jid = _e(str(job.get("id") or ""))
    rows = ""
    for fmt in FORMATS:
        href = (f"/view/{jid}/{fmt}" if fmt in ("json", "md", "sarif")
                else f"/report/{jid}/{fmt}")
        active = " style='background:#f6f7fa;color:#10141A'" if fmt == current else ""
        rows += (f"<a href='{href}'{active}>{_e(_FORMAT_LABEL.get(fmt, fmt))}"
                 f"<span class='mono' style='margin-left:auto'>.{_e(fmt)}"
                 "</span></a>")
    return ("<section class='card'><h3>Other formats</h3>"
            "<div class='anchorlist'>" + rows + "</div></section>")


def _view_md_page(job: dict, text: str) -> str:
    jid = _e(str(job.get("id") or ""))
    body_html, nav = _md_to_html(text)
    nav_links = "".join(
        f"<a href='#{hid}'>{_e(title)}</a>" for hid, title in nav[:14])
    body = (
        _crumb(("Workbench", "/"), (str(job.get("name") or "bundle"),
                                    f"/overview/{jid}"), ("report.md", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{_job_icon(job, 44)}<span>report.md</span></h1>"
        "<p>markdown viewer &middot; rendered on the server, escaped line by "
        "line &middot; links open the raw file</p></div>"
        "<div class='right'>"
        f"<a class='ghostbtn' href='/report/{jid}/md' target='_blank' "
        "rel='noopener'>Raw markdown</a>"
        f"<a class='darkbtn' href='/download/{jid}/md'>Download</a>"
        "</div></div></div>"
        "<div class='grid2 stage'><section class='card' style='padding:22px 26px'>"
        f"<div class='md'>{body_html}</div></section>"
        "<aside class='side'>"
        + (f"<section class='card'><h3>On this page</h3>"
           f"<div class='anchorlist'>{nav_links}</div></section>" if nav_links else "")
        + _formats_card(job, "md") +
        "<section class='card'><h3>About</h3>"
        "<p style='margin:0;font-size:10.5px;color:#8a8e96;line-height:1.6'>"
        "The viewer renders the same bytes served at "
        f"<code>/report/{jid}/md</code>; nothing is re-scanned here.</p></section>"
        "</aside></div>"
    )
    return _shell("md", body, job=job,
                  title=f"masanalyzer — {job.get('name') or 'report'} · md")


_JSON_VIEW_JS = r"""
const data = JSON.parse(document.getElementById("payload").textContent);
const tree = document.getElementById("tree");
const pathbar = document.getElementById("pathbar");
const index = new Map();
const CAP = 200;

function typeOf(v){
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}
function preview(v, t){
  if (t === "string") return {cls:"vs",
    text:JSON.stringify(v.length > 220 ? v.slice(0, 220) + "…" : v)};
  if (t === "number") return {cls:"vn", text:String(v)};
  if (t === "boolean") return {cls:"vb", text:String(v)};
  if (t === "null") return {cls:"v0", text:"null"};
  if (t === "array") return {cls:"vp", text:"[ " + v.length + " ]"};
  return {cls:"vp", text:"{ " + Object.keys(v).length + " }"};
}
function build(kids, value, path){
  const isArr = Array.isArray(value);
  const entries = isArr ? value.map((v,i) => [String(i), v]) : Object.entries(value);
  let shown = Math.min(entries.length, CAP);
  for (let i = 0; i < shown; i++){
    const [k, v] = entries[i];
    rowEl(kids, k, v, isArr ? path + "[" + k + "]" : (path ? path + "." + k : k));
  }
  if (entries.length > shown){
    const more = document.createElement("div");
    more.className = "more";
    more.textContent = "… " + (entries.length - shown) + " more";
    more.addEventListener("click", () => {
      const upto = Math.min(entries.length, shown + 1000);
      for (let i = shown; i < upto; i++){
        const [k, v] = entries[i];
        rowEl(kids, k, v, isArr ? path + "[" + k + "]" : (path ? path + "." + k : k));
      }
      shown = upto;
      if (shown >= entries.length) more.remove();
      else more.textContent = "… " + (entries.length - shown) + " more";
    });
    kids.appendChild(more);
  }
}
function rowEl(container, key, value, path){
  const t = typeOf(value);
  const row = document.createElement("div");
  row.className = "n";
  row.dataset.path = path;
  if (t === "object" || t === "array"){
    const tog = document.createElement("span");
    tog.className = "tog"; tog.textContent = "▸";
    const k = document.createElement("span"); k.className = "k";
    k.textContent = key || "root";
    const pv = preview(value, t);
    const ps = document.createElement("span"); ps.className = pv.cls;
    ps.textContent = pv.text;
    row.append(tog, k, ps);
    const kids = document.createElement("div");
    kids.className = "kids"; kids.hidden = true;
    let built = false;
    tog.addEventListener("click", () => {
      if (tog.textContent === "▸"){
        if (!built){ build(kids, value, path); built = true; }
        kids.hidden = false; tog.textContent = "▾";
      } else { kids.hidden = true; tog.textContent = "▸"; }
    });
    row._open = () => {
      if (!built){ build(kids, value, path); built = true; }
      kids.hidden = false; tog.textContent = "▾";
    };
    row._shut = () => { kids.hidden = true; tog.textContent = "▸"; };
    row._tog = tog;
    container.append(row, kids);
  } else {
    const k = document.createElement("span"); k.className = "k";
    k.textContent = key;
    const pv = preview(value, t);
    const ps = document.createElement("span"); ps.className = pv.cls;
    ps.textContent = pv.text; ps.title = String(value);
    row.append(k, ps);
    container.appendChild(row);
  }
  row.addEventListener("click", (ev) => {
    if (ev.target === row._tog) return;
    pathbar.textContent = row.dataset.path || "(root)";
  });
  index.set(path, row);
}

const root = document.createElement("div");
tree.appendChild(root);
rowEl(root, "", data, "");
root.firstChild._open();
for (const kid of root.querySelectorAll(":scope > .kids > .n")){
  if (kid._open){ kid._open(); break; }
}

function segsOf(path){
  const segs = []; let i = 0; let cur = "";
  while (i < path.length){
    const ch = path[i];
    if (ch === "."){
      if (cur !== ""){ segs.push({key: cur}); cur = ""; }
      i++; continue;
    }
    if (ch === "["){
      if (cur !== ""){ segs.push({key: cur}); cur = ""; }
      const j = path.indexOf("]", i);
      if (j < 0) break;
      segs.push({idx: path.slice(i + 1, j)});
      i = j + 1; continue;
    }
    cur += ch; i++;
  }
  if (cur !== "") segs.push({key: cur});
  return segs;
}
function expandPath(path){
  const rootRow = index.get("");
  if (!rootRow) return;
  rootRow._open();
  let cur = "";
  for (const seg of segsOf(path)){
    cur = seg.idx !== undefined ? cur + "[" + seg.idx + "]"
      : (cur ? cur + "." + seg.key : seg.key);
    const row = index.get(cur);
    if (!row) return;
    if (row._open) row._open();
  }
  const target = index.get(path);
  if (target){
    target.scrollIntoView({block: "center"});
    target.style.background = "#eef2fb";
    setTimeout(() => { target.style.background = ""; }, 1200);
  }
}

document.getElementById("search").addEventListener("keydown", (ev) => {
  if (ev.key !== "Enter") return;
  const q = ev.target.value.toLowerCase();
  const res = document.getElementById("searchres");
  res.innerHTML = "";
  document.getElementById("hits").textContent = "";
  if (q.length < 2) return;
  const matches = [];
  (function walk(v, path){
    if (matches.length >= 80 || !v || typeof v !== "object") return;
    const isArr = Array.isArray(v);
    const entries = isArr ? v.map((x,i) => [String(i), x]) : Object.entries(v);
    for (const [k, x] of entries){
      if (matches.length >= 80) return;
      const p = isArr ? path + "[" + k + "]" : (path ? path + "." + k : k);
      if (!x || typeof x !== "object"){
        const s = typeof x === "string" ? x : String(x);
        if (k.toLowerCase().includes(q) || s.toLowerCase().includes(q)){
          matches.push({path: p, text: k + ": " + s.slice(0, 140)});
        }
      } else {
        if (k.toLowerCase().includes(q)) matches.push({path: p, text: k});
        walk(x, p);
      }
    }
  })(data, "");
  document.getElementById("hits").textContent =
    matches.length >= 80 ? "80+ matches" : matches.length + " matches";
  for (const m of matches){
    const d = document.createElement("div");
    d.className = "sr";
    d.innerHTML = "<b>" + m.path.replace(/[<>&]/g, "") + "</b> "
      + m.text.replace(/[<>&]/g, "");
    d.addEventListener("click", () => { res.innerHTML = ""; expandPath(m.path); });
    res.appendChild(d);
  }
});
document.getElementById("exp").addEventListener("click", () => {
  const rootRow = index.get("");
  if (!rootRow) return;
  rootRow._open();
  for (const kid of rootRow.parentElement.querySelectorAll(
      ":scope > .kids > .n")){
    if (kid._open) kid._open();
  }
});
document.getElementById("col").addEventListener("click", () => {
  for (const row of index.values()){ if (row._shut) row._shut(); }
});
"""


def _view_json_page(job: dict, doc: Any) -> str:
    jid = _e(str(job.get("id") or ""))
    payload = json.dumps(doc, ensure_ascii=False, default=str)
    payload = payload.replace("</", "<\\/").replace("<!", "<\\u0021")

    score = doc.get("score") or {} if isinstance(doc, dict) else {}
    summary = doc.get("summary") or {} if isinstance(doc, dict) else {}
    sev = (summary or {}).get("by_severity") or {}
    chips = ""
    if score.get("grade"):
        chips += (f"<span class='pill {'green' if str(score['grade'])[:1] in 'AB' else 'amber' if str(score['grade'])[:1] == 'C' else 'red'}'>"
                  f"grade {_e(score.get('grade'))}</span>")
    if score.get("total") is not None:
        chips += f"<span class='pill grey'>{_e(score.get('total'))} / 100</span>"
    if summary.get("findings") is not None:
        chips += f"<span class='pill blue'>{_e(summary.get('findings'))} findings</span>"
    for name in _SEV_ORDER:
        if int((sev or {}).get(name, 0) or 0):
            chips += (f"<span class='pill {_SEV_CLASS[name]}'>"
                      f"{int(sev[name])} {_e(name)}</span>")

    body = (
        _crumb(("Workbench", "/"), (str(job.get("name") or "bundle"),
                                    f"/overview/{jid}"), ("report.json", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{_job_icon(job, 44)}<span>report.json</span></h1>"
        f"<p>json viewer &middot; {len(payload):,} bytes on disk &middot; lazy "
        "tree, searchable, nothing truncated silently</p></div>"
        "<div class='right'>"
        f"<a class='ghostbtn' href='/report/{jid}/json' target='_blank' "
        "rel='noopener'>Raw JSON</a>"
        f"<a class='darkbtn' href='/download/{jid}/json'>Download</a>"
        "</div></div></div>"
        f"<div class='panel-h' style='padding:0 2px 14px'>{chips}</div>"
        "<div class='grid2 stage'><section class='card'>"
        "<div class='searchbar'>"
        "<input id='search' type='text' placeholder='Search keys &amp; values…' "
        "aria-label='Search the document'>"
        "<button id='exp' type='button'>Expand top level</button>"
        "<button id='col' type='button'>Collapse all</button>"
        "<span class='mono' id='hits'></span></div>"
        "<div id='searchres'></div>"
        "<div class='tree' id='tree'></div>"
        "<div id='pathbar'>&mdash;</div>"
        "</section><aside class='side'>" + _formats_card(job, "json") +
        "<section class='card'><h3>Reading it</h3>"
        "<p style='margin:0;font-size:10.5px;color:#8a8e96;line-height:1.6'>"
        "Every report format is rendered from this document, so the JSON is the "
        "contract. Arrays render lazily in chunks of 200 siblings.</p></section>"
        "</aside></div>"
        "<script type='application/json' id='payload'>" + payload + "</script>"
        "<script>" + _JSON_VIEW_JS + "</script>"
    )
    return _shell("md", body, job=job,
                  title=f"masanalyzer — {job.get('name') or 'report'} · json")


def _view_sarif_page(job: dict, doc: dict) -> str:
    jid = _e(str(job.get("id") or ""))
    runs = doc.get("runs") or [{}]
    run = runs[0] if runs else {}
    rules_list = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    rules = {r.get("id"): r for r in rules_list}
    results = list(run.get("results") or [])
    counts = {"error": 0, "warning": 0, "note": 0}
    by_rule: dict = {}
    for item in results:
        lvl = str(item.get("level", "note"))
        counts[lvl] = counts.get(lvl, 0) + 1
        rid = str(item.get("ruleId", "?"))
        by_rule[rid] = by_rule.get(rid, 0) + 1

    stats = "".join(
        f"<div class='m'><span>{_e(level)}</span><b>{counts.get(level, 0)}</b></div>"
        for level in ("error", "warning", "note"))
    result_rows = []
    for item in results:
        lvl = str(item.get("level", "note"))
        rid = str(item.get("ruleId", "?"))
        rule = rules.get(rid) or {}
        name = ((rule.get("shortDescription") or {}).get("text") or "")
        msg = ((item.get("message") or {}).get("text") or "").replace("\n", " ")
        if len(msg) > 240:
            msg = msg[:240] + "…"
        loc = ""
        region = ""
        locations = item.get("locations") or []
        if locations:
            phys = (locations[0].get("physicalLocation") or {})
            loc = ((phys.get("artifactLocation") or {}).get("uri") or "")
            reg = phys.get("region") or {}
            if reg.get("startLine") is not None:
                region = ":" + str(reg["startLine"])
        sev = (item.get("properties") or {}).get("security-severity")
        result_rows.append(
            "<tr>"
            f"<td><span class='chip lv-{_e(lvl)}'>{_e(lvl)}</span></td>"
            f"<td><code>{_e(rid)}</code><br>"
            f"<span style='font-size:10px;color:#a8abb3'>{_e(name)}</span></td>"
            f"<td>{_e(msg)}</td>"
            f"<td><code>{_e(loc)}{_e(region)}</code></td>"
            f"<td>{_e(str(sev)) if sev is not None else '-'}</td>"
            "</tr>")

    rule_rows = "".join(
        f"<tr><td><code>{_e(rid)}</code></td><td>{int(count)}</td></tr>"
        for rid, count in sorted(by_rule.items(), key=lambda kv: -kv[1]))

    details = []
    for rule in rules_list:
        rid = str(rule.get("id", ""))
        lvl = str((rule.get("defaultConfiguration") or {}).get("level", "note"))
        short = (rule.get("shortDescription") or {}).get("text") or ""
        full = (rule.get("fullDescription") or {}).get("text") or ""
        props = rule.get("properties") or {}
        details.append(
            f"<details><summary><b><code>{_e(rid)}</code> {_e(short)}</b> "
            f"<span class='chip lv-{_e(lvl)}'>{_e(lvl)}</span></summary>"
            f"<p>{_e(full)}</p><p class='mono' style='font-size:9px'>"
            f"{_e(str(props.get('owasp') or ''))} · "
            f"{_e(str(props.get('cwe') or ''))}</p></details>")

    body = (
        _crumb(("Workbench", "/"), (str(job.get("name") or "bundle"),
                                    f"/overview/{jid}"), ("report.sarif", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        f"<div><h1>{_job_icon(job, 44)}<span>report.sarif</span></h1>"
        "<p>sarif viewer &middot; SARIF 2.1.0 &middot; "
        f"{len(results)} results across {len(by_rule)} rules</p></div>"
        "<div class='right'>"
        f"<a class='ghostbtn' href='/report/{jid}/sarif' target='_blank' "
        "rel='noopener'>Raw SARIF</a>"
        f"<a class='darkbtn' href='/download/{jid}/sarif'>Download</a>"
        "</div></div></div>"
        "<div class='metrics' style='grid-template-columns:repeat(4,1fr)'>"
        + stats +
        f"<div class='m'><span>rules hit</span><b>{len(by_rule)}</b></div></div>"
        "<div class='grid2 stage' style='margin-top:16px'><div class='stack'>"
        "<section class='card'><h3>SARIF 2.1.0 triage"
        f"<span class='pill grey'>Results ({len(results)})</span></h3>"
        "<div class='tw' style='overflow-x:auto'><table class='tbl'>"
        "<tr><th>Level</th><th>Rule</th><th>Message</th><th>Location</th>"
        "<th>CVSS</th></tr>" + "".join(result_rows) + "</table></div></section>"
        "<section class='card'><h3>Rule reference"
        f"<span class='pill grey'>{len(rules_list)} rules</span></h3>"
        + "".join(details) + "</section>"
        "</div><aside class='side'>"
        "<section class='card'><h3>Rules hit</h3>"
        "<table class='tbl'><tr><th>Rule</th><th>Results</th></tr>"
        + rule_rows + "</table></section>"
        + _formats_card(job, "sarif") +
        "</aside></div>"
    )
    return _shell("md", body, job=job,
                  title=f"masanalyzer — {job.get('name') or 'report'} · sarif")

# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "masanalyzer-dashboard/1.1"
    dashboard: "Dashboard" = None  # type: ignore[assignment]

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass  # pragma: no cover

    def _send(self, code: int, body: bytes, ctype: str,
              extra: Optional[Dict[str, str]] = None,
              cache: str = "no-store") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.responded = True

    def _html(self, page: str, code: int = 200) -> None:
        self._send(code, page.encode("utf-8"), "text/html; charset=utf-8")

    def _json(self, payload: Any, code: int = 200) -> None:
        self._send(code, json.dumps(payload, indent=1).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _text_error(self, code: int, message: str) -> None:
        self._send(code, html.escape(message).encode("utf-8"),
                   "text/plain; charset=utf-8")

    # -- routes ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        self._guard(self._route_get)

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        self._guard(self._route_post)

    def _guard(self, route) -> None:
        """Run a route; any crash becomes a readable page, not a dropped
        connection.  Without this a rendering bug shows up in the browser
        as "this page isn't working" with nothing to go on."""
        try:
            route()
        except (BrokenPipeError, ConnectionResetError):
            raise  # the client walked away mid-write; nothing to send
        except Exception as exc:  # noqa: BLE001 - that is the point
            traceback.print_exc()
            if getattr(self, "responded", False):
                return
            try:
                path = self.path.split("?", 1)[0]
                if path == "/jobs" or path.startswith("/job/"):
                    self._json({"error": f"{type(exc).__name__}: {exc}",
                                "path": self.path}, code=500)
                else:
                    self._html(_error_page(self.path, exc), code=500)
            except Exception:  # noqa: BLE001 - socket already gone
                pass

    def _route_get(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._html(_board_page(
                self.dashboard.jobs.list(),
                self.dashboard.settings.refresh_ms))
            return
        if path == "/upload":
            self._html(_upload_page(
                self.dashboard.jobs.list(),
                self.dashboard.max_upload_mib,
                self.dashboard.workers,
                self.dashboard.refresh_intel))
            return
        if path == "/settings":
            self._serve_settings()
            return
        if path == "/jobs":
            self._json({"jobs": self.dashboard.jobs.list()})
            return
        m = re.fullmatch(r"/job/([0-9a-f]{32})", path)
        if m:
            job = self.dashboard.jobs.get(m.group(1))
            if job is None:
                self._text_error(404, "unknown job id")
                return
            self._json(job)
            return
        m = re.fullmatch(r"/scanning/([0-9a-f]{32})", path)
        if m:
            job = self.dashboard.jobs.get(m.group(1))
            if job is None:
                self._text_error(404, "unknown job id")
                return
            self._html(_scanning_page(job))
            return
        m = re.fullmatch(r"/reports/([0-9a-f]{32})", path)
        if m:
            self._serve_reports(m.group(1))
            return
        m = re.fullmatch(r"/view/([0-9a-f]{32})/([a-z]+)", path)
        if m:
            self._serve_view(m.group(1), m.group(2))
            return
        m = re.fullmatch(r"/(report|download)/([0-9a-f]{32})/([a-z]+)", path)
        if m:
            self._serve_report(m.group(1) == "download", m.group(2), m.group(3))
            return
        m = re.fullmatch(r"/icon/([0-9a-f]{32})", path)
        if m:
            self._serve_icon(m.group(1))
            return
        m = re.fullmatch(r"/overview/([0-9a-f]{32})", path)
        if m:
            self._serve_overview(m.group(1))
            return
        self._text_error(404, "not found")

    def _route_post(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/settings":
            self._save_settings()
            return
        if path != "/upload":
            self._text_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._text_error(400, "empty body")
            return
        if length > self.dashboard.max_upload:
            # drain the body first so the client can finish sending; a
            # mid-upload close otherwise aborts the connection (WinError
            # 10053) before the 413 reaches it
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._text_error(413, f"upload exceeds "
                             f"{self.dashboard.max_upload // (1024 * 1024)} MiB cap")
            return
        body = self.rfile.read(length)
        try:
            filename, content = extract_upload(self.headers, body)
        except ValueError as exc:
            self._text_error(400, str(exc))
            return
        safe = sanitize_upload_name(filename)
        job = self.dashboard.jobs.create(safe, filename)
        upload_path = os.path.join(self.dashboard.jobs.dir(job["id"]), safe)
        with open(upload_path, "wb") as fh:
            fh.write(content)
        self.dashboard.scanner.enqueue(job["id"], upload_path)
        self._json(job, code=201)

    # -- pages -----------------------------------------------------------------
    _VIEWERS = ("json", "md", "sarif")

    def _serve_view(self, job_id: str, fmt: str) -> None:
        """Styled viewer page for json/md/sarif (raw body on /report/...)."""
        if fmt not in self._VIEWERS:
            self._text_error(
                400, f"fmt must be one of: {', '.join(self._VIEWERS)}")
            return
        job = self.dashboard.jobs.get(job_id)
        if job is None:
            self._text_error(404, "unknown job id")
            return
        path = os.path.join(self.dashboard.jobs.dir(job_id), f"report.{fmt}")
        if not os.path.isfile(path):
            self._text_error(
                404, f"report.{fmt} not ready (job status: {job['status']})")
            return
        with open(path, "rb") as fh:
            raw = fh.read()
        if fmt == "md":
            page = _view_md_page(job, raw.decode("utf-8", "replace"))
        else:
            try:
                doc = json.loads(raw.decode("utf-8"))
            except ValueError:
                self._text_error(500, f"report.{fmt} is not valid JSON")
                return
            if fmt == "json":
                page = _view_json_page(job, doc)
            else:
                if not isinstance(doc, dict) or not doc.get("runs"):
                    self._text_error(500, "report.sarif has no runs array")
                    return
                page = _view_sarif_page(job, doc)
        self._html(page)

    def _serve_reports(self, job_id: str) -> None:
        job = self.dashboard.jobs.get(job_id)
        if job is None:
            self._text_error(404, "unknown job id")
            return
        want = ""
        if "?" in self.path:
            m = re.search(r"(?:^|&)fmt=([a-z0-9]+)", self.path.split("?", 1)[1])
            if m:
                want = m.group(1)
        self._html(_reports_page(
            job, self.dashboard.jobs.dir(job_id), want,
            self.dashboard.settings.preview))

    def _serve_report(self, attachment: bool, job_id: str, fmt: str) -> None:
        if fmt not in FORMATS:
            self._text_error(400, f"fmt must be one of: {', '.join(FORMATS)}")
            return
        job = self.dashboard.jobs.get(job_id)
        if job is None:
            self._text_error(404, "unknown job id")
            return
        path = os.path.join(self.dashboard.jobs.dir(job_id), f"report.{fmt}")
        if not os.path.isfile(path):
            self._text_error(
                404, f"report.{fmt} not ready (job status: {job['status']})")
            return
        with open(path, "rb") as fh:
            body = fh.read()
        ctypes = {
            "html": "text/html; charset=utf-8",
            "json": "application/json; charset=utf-8",
            "md": "text/markdown; charset=utf-8",
            "pdf": "application/pdf",
        }
        extra: Dict[str, str] = {}
        if attachment:
            name = os.path.splitext(job.get("name") or "report")[0]
            extra["Content-Disposition"] = \
                f'attachment; filename="{name}-report.{fmt}"'
        self._send(200, body, ctypes.get(fmt, "text/plain; charset=utf-8"),
                   extra=extra)

    def _serve_settings(self) -> None:
        """Settings page: display preferences plus the read-only runtime."""
        dash = self.dashboard
        host = self.headers.get("Host") or "127.0.0.1"
        runtime = [
            ("Dashboard", f"<code>http://{_e(host)}/</code>"),
            ("Workdir", f"<code>{_e(dash.jobs.root)}</code>"),
            ("Scan workers", str(dash.workers)),
            ("Max upload", f"{dash.max_upload_mib} MiB"),
            ("CVE refresh", "on &mdash; stale coordinates re-queried"
             if dash.refresh_intel else "off &mdash; cache used as-is"),
            ("Tool version", _e(TOOL_VERSION)),
            ("Python", sys.version.split()[0]),
        ]
        saved = "saved=1" in self.path
        self._html(_settings_page(dash.settings, runtime, saved))

    def _save_settings(self) -> None:
        """Persist the posted display preferences, then redirect back."""
        try:
            length = min(int(self.headers.get("Content-Length") or 0),
                         64 * 1024)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        form = {k: v[0] for k, v in parse_qs(
            raw.decode("utf-8", "replace")).items() if v}
        changed = self.dashboard.settings.update(form)
        wanted = (self.headers.get("Accept") or "").lower()
        scripted = (self.headers.get("X-Requested-With") or "").lower()
        if "application/json" in wanted or scripted == "fetch":
            # the live form: answer in place, no navigation, no re-post
            self._json({"saved": True, "changed": changed,
                        "settings": self.dashboard.settings.values,
                        "summary": self.dashboard.settings.summary()})
            return
        self._send(303, b"", "text/plain; charset=utf-8",
                   extra={"Location": "/settings?saved=1"})

    def _serve_icon(self, job_id: str) -> None:
        """The bundle's extracted launcher icon (404 when there is none)."""
        job = self.dashboard.jobs.get(job_id)
        name = str((job or {}).get("icon") or "")
        if not name:
            self._text_error(404, "no icon for this job")
            return
        path = os.path.join(self.dashboard.jobs.dir(job_id), name)
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            self._text_error(404, "no icon for this job")
            return
        ctype = {
            "png": "image/png",
            "webp": "image/webp",
            "jpg": "image/jpeg",
            "svg": "image/svg+xml",
        }.get(name.rsplit(".", 1)[-1].lower(), "application/octet-stream")
        self._send(200, blob, ctype, cache="public, max-age=86400")

    def _serve_overview(self, job_id: str) -> None:
        """At-a-glance fact page built from the stored report.json."""
        job = self.dashboard.jobs.get(job_id)
        if job is None:
            self._text_error(404, "unknown job id")
            return
        path = os.path.join(self.dashboard.jobs.dir(job_id), "report.json")
        if not os.path.isfile(path):
            self._text_error(
                404, f"report.json not ready (job status: {job['status']})")
            return
        try:
            with open(path, "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            ov = (doc.get("inventory") or {}).get("overview") or {}
        except (OSError, ValueError):
            self._text_error(500, "report.json unreadable")
            return
        if not ov:
            self._text_error(
                404, "overview not available for this job "
                     "(scan predates the overview layer)")
            return
        self._html(_overview_page(
            job, ov, doc.get("inventory") or {}, report=doc))


def _error_page(path: str, exc: BaseException) -> str:
    """Readable 500 page: what broke, on which path, and where."""
    name = type(exc).__name__
    message = str(exc) or "(no message)"
    frames = "".join(traceback.format_exception(
        type(exc), exc, exc.__traceback__)[-8:])
    body = (
        _crumb(("Workbench", "/"), ("Error", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        "<div><h1>This page could not be rendered</h1>"
        f"<p>{_e(name)} while building <code>{_e(path)}</code> &mdash; the "
        "rest of the workbench is unaffected</p></div>"
        "<div class='right'><a class='ghostbtn' href='/'>Board</a>"
        f"<a class='darkbtn' href='{_e(path)}'>Try again</a></div>"
        "</div></div>"
        "<section class='card'><h3>What happened"
        f"<span class='pill red'>{_e(name)}</span></h3>"
        + _facts([
            ("Path", f"<code>{_e(path)}</code>"),
            ("Error", f"<code>{_e(message)}</code>"),
            ("Scans on disk", "untouched &mdash; likely causes are an "
             "unexpected shape in a report or a stale job directory"),
        ])
        + "<details style='margin-top:14px'><summary>Traceback (last "
        "frames)</summary>"
        "<pre class='mono' style='margin:8px 0 0;padding:10px 12px;"
        "background:#fbfcfe;border:1px solid #f1f3f8;border-radius:12px;"
        "font-size:10px;line-height:1.6;overflow:auto;white-space:pre-wrap'>"
        f"{_e(frames)}</pre></details>"
        "<p class='mono' style='margin:12px 0 0;font-size:9.5px'>"
        "the full traceback is also printed to the dashboard's terminal"
        "</p></section>")
    return _shell("", body, title="masanalyzer — error")


# --------------------------------------------------------------------------
# settings (/settings)
# --------------------------------------------------------------------------
#: board refresh choices, in seconds (0 = only the filter re-reads /jobs)
REFRESH_CHOICES = (0, 2, 3, 5, 10, 30)
#: formats the reports page can open with ("none" starts with no preview)
PREVIEW_CHOICES = ("md", "json", "html", "csv", "none")
DEFAULT_SETTINGS = {"refresh_seconds": 3, "preview": "md"}


class _Settings:
    """Display preferences, persisted as ``<workdir>/settings.json``.

    Only presentation knobs live here - scan options stay on the command
    line, so a settings page can never widen what the tool will parse.
    """

    def __init__(self, workdir: str) -> None:
        self.path = os.path.join(workdir, "settings.json")
        self.values = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
        except (OSError, ValueError):
            return
        if isinstance(stored, dict):
            self.update(stored, save=False)

    @property
    def refresh_ms(self) -> int:
        return int(self.values["refresh_seconds"]) * 1000

    @property
    def preview(self) -> str:
        return str(self.values["preview"])

    def update(self, form: dict, save: bool = True) -> bool:
        """Validate and store a form (or a stored dict); True when it changed."""
        before = dict(self.values)
        values = dict(self.values)
        seconds = form.get("refresh", form.get("refresh_seconds"))
        try:
            seconds = int(str(seconds).strip())
        except (TypeError, ValueError):
            seconds = int(values["refresh_seconds"])
        values["refresh_seconds"] = seconds if seconds in REFRESH_CHOICES else 3
        preview = str(form.get("preview", values["preview"]) or "").strip().lower()
        values["preview"] = preview if preview in PREVIEW_CHOICES else "md"
        self.values = values
        if save and values != before:
            self.save()
        return values != before

    def summary(self) -> str:
        """One line describing the saved state, for the toast/JSON reply."""
        seconds = int(self.values["refresh_seconds"])
        refresh = ("board refresh off" if seconds == 0
                   else f"board every {seconds} s")
        preview = str(self.values["preview"])
        where = ("no reports preview" if preview == "none"
                 else f"reports open on report.{preview}")
        return f"{refresh} \u00b7 {where}"

    def save(self) -> None:
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.values, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            pass


_SETTINGS_JS = r"""
(function(){
  const form = document.getElementById('setform');
  if (!form) return;
  const status = document.getElementById('setstatus');
  const button = form.querySelector("button[type=submit]");
  const idle = 'saved to settings.json \u2014 the board and reports pick it up ' +
    'on their next load';
  const say = function(text, ok){
    if (status) status.textContent = text;
    if (window.masToast) window.masToast(text, ok);
  };
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const data = new URLSearchParams(new FormData(form));
    const label = button.textContent;
    button.disabled = true;
    button.textContent = 'Saving\u2026';
    try {
      const r = await fetch('/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded',
                  'X-Requested-With': 'fetch'},
        body: data.toString()
      });
      if (!r.ok) throw new Error((await r.text()).slice(0, 120));
      const saved = await r.json();
      history.replaceState(null, '', '/settings');
      say(saved.changed ? 'Saved \u2014 ' + saved.summary
                        : 'Already up to date \u2014 ' + saved.summary, true);
      button.textContent = 'Saved';
      setTimeout(function(){ button.textContent = label; }, 1500);
    } catch (err) {
      button.textContent = label;
      say('Could not save: ' + err.message);
    } finally {
      button.disabled = false;
    }
  });
})();
"""


def _settings_page(settings: "_Settings", runtime: list,
                   saved: bool = False) -> str:
    """Workbench settings: display preferences + the read-only runtime."""
    values = settings.values
    refresh_options = "".join(
        f"<option value='{sec}'"
        f"{' selected' if int(sec) == int(values['refresh_seconds']) else ''}>"
        f"{'off &mdash; manual only' if int(sec) == 0 else f'every {sec} s'}</option>"
        for sec in REFRESH_CHOICES)
    preview_options = "".join(
        f"<option value='{fmt}'"
        f"{' selected' if fmt == values['preview'] else ''}>"
        f"{'no preview' if fmt == 'none' else f'report.{fmt}'}</option>"
        for fmt in PREVIEW_CHOICES)
    body = (
        _crumb(("Workbench", "/"), ("Settings", ""))
        + "<div class='pagehead' style='display:block;padding-top:0'>"
        "<div style='display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap'>"
        "<div><h1>Settings</h1>"
        "<p>Display preferences for this workbench &middot; saved beside the "
        "scans, so every browser sees them</p></div>"
        "<div class='right'>"
        + ("<span class='pill green'>saved</span>" if saved else "") +
        "<a class='ghostbtn' href='/'>Back to board</a>"
        "</div></div></div>"
        "<div class='stack stage'>"
        "<section class='card'><h3>Display"
        "<span class='pill grey'>settings.json</span></h3>"
        "<form method='post' action='/settings' id='setform'>"
        "<div class='setrow'><label for='refresh'>Board refresh"
        "<small>how often the board re-reads /jobs</small></label>"
        f"<select id='refresh' name='refresh'>{refresh_options}</select></div>"
        "<div class='setrow'><label for='preview'>Reports preview"
        "<small>the format the reports page opens with</small></label>"
        f"<select id='preview' name='preview'>{preview_options}</select></div>"
        "<div class='setsave'>"
        "<button class='darkbtn' type='submit'>Save preferences</button>"
        "<span class='mono' id='setstatus' role='status' aria-live='polite' "
        "style='font-size:10px'>saved to settings.json &mdash; the board and "
        "reports pick it up on their next load</span></div></form></section>"
        "<section class='card'><h3>Runtime"
        "<span class='pill grey'>command line</span></h3>"
        + _facts(runtime)
        + "<p class='mono' style='margin:12px 0 0;font-size:9.5px;"
        "line-height:1.7'>runtime values come from the flags this dashboard "
        "was started with &mdash; restart it to change them. Nothing here "
        "widens what the scanner parses.</p></section>"
        "</div>")
    return _shell("settings", body + "<script>" + _SETTINGS_JS + "</script>",
                  title="masanalyzer — settings")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
class Dashboard:
    """Owns the job registry, worker pool and HTTP server."""

    def __init__(self, workdir: Optional[str] = None, workers: int = 2,
                 max_upload_mib: int = 2048,
                 osv_cache: Optional[str] = None,
                 refresh_intel: bool = True) -> None:
        root = workdir or os.path.join(
            tempfile.gettempdir(), "masan_dashboard")
        self.jobs = _Jobs(os.path.join(root, "jobs"))
        self.scanner = _Scanner(self.jobs, workers=workers,
                                osv_cache=osv_cache,
                                refresh_intel=refresh_intel)
        self.max_upload_mib = max(1, max_upload_mib)
        self.max_upload = self.max_upload_mib * 1024 * 1024
        self.workers = max(1, workers)
        self.refresh_intel = refresh_intel
        self.settings = _Settings(root)

    def serve(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        handler = type("BoundHandler", (_Handler,), {"dashboard": self})
        httpd = ThreadingHTTPServer((host, port), handler)
        url = f"http://{host}:{httpd.server_address[1]}/"
        print(f"masanalyzer dashboard on {url} "
              f"(Ctrl-C to stop) - jobs root: {self.jobs.root}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:  # pragma: no cover - interactive stop
            pass
        finally:
            httpd.server_close()


def main(argv: Optional[list] = None) -> int:  # pragma: no cover - serves forever
    import argparse

    p = argparse.ArgumentParser(
        prog="masanalyzer-dashboard",
        description="Local dashboard: upload APK/IPA/.aab/.apks bundles, "
                    "run scans, browse and download the reports.")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default: 127.0.0.1 - keep it local)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--workdir", default=None,
                   help="directory for uploads + reports "
                        "(default: <temp>/masan_dashboard)")
    p.add_argument("--workers", type=int, default=2,
                   help="parallel scan workers (default: 2)")
    p.add_argument("--max-upload-mib", type=int, default=2048,
                   help="reject uploads larger than this (default: 2048)")
    p.add_argument("--osv-cache", default=None,
                   help="JSON OSV-dev CVE cache; every dashboard scan "
                        "auto-refreshes stale coordinates and matches "
                        "advisories (MAS-SCA-003)")
    p.add_argument("--no-intel-refresh", action="store_true",
                   help="use the CVE cache as-is (no re-query)")
    args = p.parse_args(argv)
    dash = Dashboard(workdir=args.workdir, workers=args.workers,
                     max_upload_mib=args.max_upload_mib,
                     osv_cache=args.osv_cache,
                     refresh_intel=not args.no_intel_refresh)
    dash.serve(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

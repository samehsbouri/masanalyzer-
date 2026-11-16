# masanalyzer architecture

## Pipeline overview

```
input (apk / ipa / directory / binary file)
   â”‚
   â–¼
packaging.prepare_target()          [packaging.py]
   1. classify: APK zip / IPA zip / .app tree / app/ source tree / raw file
   2. unpack zip containers into a "masan_*" temp work dir
   3. classify every file into ScanFile(kind, sha256, â€¦)
   4. enrich with platform parsers (below)
   5. build the shared string pool (dex/.so/Mach-O/plist text)
   â”‚
   â–¼
analysis.run_analyzers(target, collector)   [analysis/__init__.py]
   m01..m10  ->  Finding list; never aborts on a broken analyzer
   returns (covered_categories, failures, count)
   â”‚
   â–¼
reporting.compute_score(findings, covered)  [reporting/score.py]
   â”‚
   â–¼
scanner.ScanResult  ->  reporting.render(result, fmt)
                        json | md | html | sarif
```

## Layers

### `masanalyzer.model`
Pure data model â€” `Severity`, `Confidence`, `Evidence`, `Finding` (with
deterministic `identity` sha1 and `risk_score = severity Ã— confidence`),
`Rule.finding(**evidence)`, `FindingCollector` (dedupes by identity, sorts by
risk), `ScanFile` (line iteration, text reads), `NativeLib`, `Target`.

### `masanalyzer.android`
* `axml.py` â€” Android binary XML â†’ Element tree. Handles attribute/value type
  encoding, probe-based attribute addressing with per-entry size validation
  (`v_size == 8`), and a plain-XML fallback that injects missing
  `xmlns:android` / `xmlns:tools` declarations.
* `manifest.py` â€” component model (activity/service/receiver/provider/alias),
  permission levels, exported resolution (`exported` attr, intent-filter
  presence, grantUriPermissions, debuggable/allowBackup/â€¦).
* `dex.py` â€” DEX header, class list, MUTF-8 string extraction, and the
  **callsite receipt walker**: `DexFile.analyze_callsites()` walks
  class_data â†’ code_items and decodes the Dalvik ISA through a pinned
  `INS_LEN` table (AOSP dalvik-bytecode format sizes; payload spans per
  the packed/sparse-switch + fill-array-data formulas) validated at
  100 % method-decode alignment on a 4-dex production bundle. URL-shaped
  `const-string` values register into a linear regâ†’url map (propagated
  through `move-object*`) and pair with `invoke-virtual`(35c) /
  `invoke-*-range`(3rc) calls whose callee class prefix is network-facing
  (`CALL_PREAMBLES`). Receipts (method url callee offset) dedupe on
  (owner, url, callee); decode stats stay in `callsite_stats`. A
  two-candidate method-id resolver also copes with app-store repackage
  class_data that stores absolute indices where the spec diff chain would
  overflow.
* `apk.py` â€” zip walks, V1 (META-INF CNs) / V2-V3 (APK Signing Block)
  signature scheme detection, `wraps` of nested APKs; runs the real v1
  cryptographic chain verification via `apkverify`, the real whole-file
  v2/v3 verification via `apksigv2` (tri-state `v2_verified`/`v3_verified`
  with reasons), the `X-Android-APK-Signed` rollback-banner check for the
  `.SF`, and the ZIP-layout anomaly walk that feeds the Janus rule.
* `pkcs7.py` â€” stdlib-only DER TLV walker/writer, X.509 SubjectPublicKeyInfo
  extraction (RSA + EC P-256), PKCS#7/CMS `SignedData`/`SignerInfo` parsing,
  and the actual verify cores: RSA PKCS#1 v1.5 (`modexp` over EMSA block
  re-encoding) and ECDSA P-256 (pure-Python Jacobian point arithmetic).
  Malformed input raises `Pkcs7Error` â†’ reported as "cannot verify".
* `apkverify.py` â€” the v1 apksig-equivalent verifier: (1) PKCS#7 signature
  over the .SF bytes (attached eContent or detached jarsigner signedAttrs,
  with a messageDigest cross-check), (2) `.SF` whole-manifest digest,
  (3) per-entry digest digesting of the current archive payload,
  (4) coverage â€” every non-signature zip entry must be manifested. Results
  land in `ApkInfo.v1_verified` / `v1_reasons` and drive MAS-SUP-008.
* `apksigv2.py` â€” the v2/v3 apksig-equivalent verifier: signing-block
  discovery (length+magic framing must end exactly at the central
  directory), length-prefixed walk of signers â†’ signed data â†’
  digests/certificates â†’ signatures â†’ public key, 1 MB-chunked content
  digest (`SHA-256(0xa5â€–le32(len)â€–chunk)` panels folded with
  `SHA-256(0x5aâ€–le32(count)â€–â€¦)` over the entry/CD/EOCD sections, EOCD
  CD-offset patched to the block start), RSA PKCS#1 v1.5 + ECDSA P-256
  signature verification, algorithm-list equality and certificate â†” SPKI
  match. Unsupported algorithms surface as explicit reasons.
* `resources.py` â€” arsc string tables (+ a resource-id â†’ default-config
  string resolver, see the overview section), `network_security_config.xml`
  (cleartext policy, trust-anchors, pin-sets).

### `masanalyzer.ios`
* `plist.py` â€” binary bplist â†’ Python objects + `dump_bplist` for fixtures;
  accepts XML plists without the `<?xml` prolog.
* `macho.py` â€” thin/fat binaries, load commands, segment/sections, symtab,
  PIE (`MH_PIE`), executable stack (`MH_ALLOW_STACK_EXECUTION`),
  `LC_CODE_SIGNATURE` handling (dataoff/datasize capture + invocation of the
  CodeDirectory verifier; tri-state `code_signature_verified`/`..._reasons`).
* `codesign.py` â€” SuperBlob (`0xfade0cc0`) / CodeDirectory (`0xfade0c02`)
  parser and verifier: page-wise SHA-256 hashes over the executable record
  (`2**pageSize` per slot up to `codeLimit`); negative special slots are
  deliberately not matched (Apple's slot ordering is unstable across signing
  versions â€” page hashes are the integrity core); the CMS slot's
  `messageDigest` is cross-checked against SHA-256(CodeDirectory) when the
  stdlib-only DER shape is decodable. Drives MAS-BIN-012.
* `ipa.py` â€” Payload detection, embedded.mobileprovision (plist decoding,
  entitlements incl. `get-task-allow`), Info.plist ATS flags, per-app Mach-O
  paths.

### `masanalyzer.packaging`
`prepare_target()` is the only entry analyzers rely on. Contract details:

* `target.platform` âˆˆ `android | ios | unknown`
* guaranteed meta keys per platform: `manifest`, `manifest_path`, `apk`,
  `dex`/`dex_files`, `resources`, `network_security_config`,
  `embedded_apks` (android); `ipa`, `macho`, `provisioning`, `plists` (ios);
  `warnings` for any recovery.
* extra containers: **`.apks`** (APK-Set â€” `base.apk` is the primary
  target, remaining inner APKs merge under `splits/<name>/â€¦` with their
  protobuf-only manifests and META-INF skipped; meta `container`, `base_apk`,
  `splits`) and **`.aab`** (App Bundle â€” flattened `base/` tree scan, `.pb`
  protobuf manifest/resources blocks flagged binary with a
  `meta["aab_proto_manifests"]` warning instead of parse noise).
* `target.string_pool` â€” `(relpath, string)` pairs harvested from binaries so
  regex analyzers see inside compiled artifacts without exec'ing `strings`.
* `target.meta["callsites"]` / `["callsite_stats"]` â€” aggregated across
  every parsed dex (see `dex.py`); consumed by `endpoints.build_inventory`
  to attach `called_from` to URL endpoint rows.
* ELF/Mach-O classification produces `NativeLib.flags` such as `pie` /
  `executable_stack` (`ET_EXEC` â‡’ no PIE; `PT_GNU_STACK` bit 0 â‡’ execstack),
  plus ELF hardening flags from the dynamic table: `relro` (PT_GNU_RELRO
  presence), `bind_now` (`DT_BIND_NOW`, `DT_FLAGS` `DF_BIND_NOW`,
  `DT_FLAGS_1` `DF_1_NOW`), `full_relro` and `writable_text` (`DT_TEXTREL`)
  â€” all feeding MAS-BIN-011. Mach-O entries additionally carry
  `code_signature` and `code_signature_verified`.

### `masanalyzer.analysis`
One module per OWASP category, all sharing `analysis/common.py` helpers:
`make_rule`, `text_scan`/`code_lines` (comment-aware, per-language text
iteration with kinds filter), `iter_pool`/`ev_pool` (string-pool iteration),
`secret_poc` (redaction-bounded PoC text), `matches_in_text`,
`version_lt`. The registry keeps a strict OWASP order, catches exceptions
per-analyzer (`failures: ["M4:RuntimeError: â€¦"]`) and never lets one broken
analyzer abort a scan.

On top of the line-regex rules, **`analysis/taint.py`** adds a light lexical
taint pass consumed by `m04` (MAS-INPUT-006): per code file, top-down,
name-based. Sources (`getStringExtra`/`getQueryParameter`/stream opens/â€¦)
capture into locals, propagation follows copies/concatenations (recording
the ultimate source line), and sink call sites (`execSQL`/`exec`/file
writes/`loadUrl`/component launches) are flagged when a tainted name is
visible and no obvious cleanser (`equals`/`isDigitsOnly`/`Integer.parseInt`)
appears on the statement. This catches multi-line flows the same-statement
regexes cannot express and attaches provenance (`source captured near line
N`) to the note field.

Several rules provide **MobSF static-analysis parity** (the catalog was
diffed against MobSF's public check lists and the gaps were closed
stdlib-only, no APKiD/yara dependency): m07 fingerprints commercial
Android packers/protectors (self-authored signature table over native-lib
names, bundle entries and the string pool â€” MAS-BIN-017) and references
to root tooling (MAS-BIN-018); m05 detects WebView TLS-error bypass and
mixed-content modes (MAS-NET-010/011); m08 detects WebView remote
debugging (MAS-MIS-008); m10 detects raw RSA (NoPadding) transformations
(MAS-CRY-009); m04 detects Jackson default-typing deserialization and
unauthenticated LocalServerSockets (MAS-INPUT-007/008); m01 flags
embedded `firebaseio.com` endpoints (MAS-CRED-009). MobSF features that
rely on external services (VirusTotal) or external tools (APKiD,
class-dump) are deliberately not imitated â€” the conservative-claims
policy requires every claim to rest on evidence parsed from the artifact.

### `masanalyzer.assurance` / `masanalyzer.surface` â€” the differentiators
Two post-analysis steps run inside `_scan_internal` (each guarded so a
failure can never kill a scan):

* **assurance.py** stamps a verification-method tier on every finding:
  `verified` (cryptographic/binary-structure proof: signature chains,
  ELF/Mach-O headers, X.509 parsing, OSV joins), `structural` (parsed
  config facts: manifest, NSC, plists, ZIP layout, inventory) or
  `heuristic` (text-pattern rules, the default). The tier rides
  `Finding.assurance` into every report format; JSON additionally
  exposes a `summary.by_assurance` histogram. Triage can gate on
  `verified` and treat `heuristic` as review tasks.
* **surface.py** synthesizes the attack surface from parsed manifest
  facts: one entry per exported component (fully-qualified name, kind,
  why it is reachable, permission guard, browsable deep links,
  worst severity) with the findings attached by exact component-name
  evidence; manifest-global rules (MIS-003/007) attach to every door;
  MIS-004/005/INPUT-004 evidence files become the WebView integration
  list. Each door also carries a transparent exposure score
  (`fix_score = worst_severity_rank(0â€“5) + 2 Ã— verified findings +
  1 if unguarded + min(deep links, 3)`) and a human `fix_why`
  rationale; doors are sorted by that score and the ranked **fix
  first** queue lands in `summary.fix_first` (`component/score/why`).
  Stored as `target.meta["attack_surface"]`; renderers embed it as the
  first section after the score, with a *Fix first* table (top 5) in
  Markdown/HTML and the full queue in JSON.

### `masanalyzer.overview` â€” the at-a-glance panel
`overview.py::build_overview(result)` assembles the MobSF-style front
page **from already-parsed facts only** (never re-parses, never raises â€”
a degenerate input yields `{}` and renderers skip the section):

* `file` â€” name, size, MD5/SHA1/SHA256 of the scanned artifact;
* `app` â€” package, resolved app label, versions, min/target/**max** SDK,
  main activity (first LAUNCHER activity), application class and
  component counts (plural-correct `components.text` summary);
* `signature` â€” signed yes/no, v1â€“v4 scheme presence (v3.1/v3.2
  rotation blocks included, v3.2 presence-only) and signer certificates
  (subject/issuer/validity/key/serial/self-signed plus the certificate
  DER's md5/sha1/sha512 fingerprints and the signature/hash algorithm
  names parsed from the X.509 tbs signature);
* `permissions` â€” declared uses-permissions with their protection level
  (`normal`/`dangerous`/`signature`, inferred from the manifest model's
  parsed danger flags) plus a **bundled reference description** for
  well-known platform permissions (`android/perm_info.py`,
  official-style wording; unknown permissions stay undescribed â€”
  nothing is invented);
* `trackers` â€” honest count of tracker endpoints observed in the
  network-indicator inventory (no vendor-database denominator);
* `score` / `findings` / `surface` (including the fix-first queue).

It lands in `report.json` as `inventory.overview`, as a fact table in
Markdown/HTML, and powers the dashboard's `/overview/<id>` page. That
page renders the inventory sections as cards - callsite receipts,
endpoints (classification chips + top hosts), trackers (tracker-classified
hosts with summed calls), privacy (permission signals and corroboration),
assurance, behaviour, findings - each read through `_rows()`, which
unwraps the `{"total": n, "rows": [...]}` envelopes those sections use.
Every card carries a chevron that collapses it, with the open/closed
state remembered per job in `localStorage` (`mas.cards.<job>`).

### `masanalyzer.behaviour` â€” quark-style API behaviours

`behaviour.py` defines 15 behaviour rules (`BEH-001`â€¦`BEH-015`,
dynamic execution, reflection, crypto/hash requests, WebView loading
and JS bridges, SMS, location, runtime receivers, HTTP, device
identifiers, clipboard, global settings, shared-prefs writes, key
material), each bound to **exact** `Lclass;#method` matchers. The
matching runs on receipts from the generalized DEX walker
(`dex.DexFile.collect_api_calls`, extracted class_data walk shared with
`analyze_callsites`): every invoke (35c and 3rc) is decoded and
attributed to its declaring method with the bytecode offset. Results
land in `target.meta["behaviour"]` and render in the JSON/HTML/MD
reports and the dashboard. Presence of an API is reported, never
intent â€” cipher-mode *quality* stays with the OWASP crypto rules that
carry literal string evidence.

### `masanalyzer.niap` â€” assurance matrix (honest subset)

`niap.py::niap_matrix(result)` emits 13 requirement rows (`NIA-01`â€¦
`NIA-13`: identity/provenance, code-signing, debug builds, dependency
currency, secret hygiene, attack surface, input validation, transport,
storage, crypto primitives, binary hardening, privacy surface,
privilege surface) each mapped to the concrete masanalyzer rule ids
whose findings satisfy or violate it, plus `NIA-SIG`/`NIA-ROT` rows
computed from the parsed v2/v3 verification flags. Statuses are
`pass` (mapped checks ran, no finding), `attention` (finding(s) exist,
worst severity named), `not applicable` (platform) and `not assessed`
(unknown platform / unverifiable block) â€” never a silent pass. The
rendered note states this is a NIAP-*style* subset, not a
certification. It lives in `inventory.niap` and in dedicated HTML/MD
sections and the dashboard overview page.

### `masanalyzer.android.resources` â€” `resources.arsc` resolver
Beyond parsing the global string pool, `resource_strings(data)` walks
`RES_TABLE_PACKAGE` â†’ `RES_TABLE_TYPE` chunks and maps full resource ids
(`0x7f14006b`) to their **default-config string values** (first
all-zero-config occurrence wins; simple STRING-type entries only).
Best-effort: malformed tables resolve to `{}`, never raise.
`packaging._android_info` stores the map as
`target.meta["resource_strings"]` and resolves a manifest label of the
form `@res/0xâ€¦` in place, so `application_label` (and the overview
panel) show the real string. `testing.build_arsc(entries)` compiles a
synthetic aapt-shaped table for tests.

### `masanalyzer.config` / `baseline` / `diffcli`
Team-policy layer, all best-effort (broken file â‡’ inert + stderr warning):

* `config.ScanConfig.load()` â€” `exclude_rules`, `exclude_paths` (forward-slash
  regexes), `rule_severity` overrides, `min_severity` default floor. Applied
  by the CLI right after the scan; `--min-severity` on the command line wins.
* `baseline.Baseline` â€” JSON list of finding-identity hashes; `filter()`
  suppresses everything already accepted so later scans show only new work.
  `--update-baseline` writes identities from the *post-policy* kept set.
* `diffcli` â€” `masanalyzer-diff old.json new.json [--fail-on sev]`: NEW /
  RESOLVED sets plus score delta; exit 1 gates CI when new findings reach
  the `--fail-on` severity (default `high`).
* `deltacli` â€” `masanalyzer-delta --gate-permissions/--gate-signers/
  --gate-surface/--fail-on` release gate over a single scan bundle
  export: blocks on the permission set / signer set / new severity
  growth, and â€” with `--gate-surface` â€” on attack-surface regressions
  (`surface_deltas()` diffs the entry-point and browsable deep-link
  sets between the two reports' `inventory.attack_surface`; an added
  *unguarded* door or any added deep link fails the build). Reports
  predating the surface layer are tolerated: the gate stays silent
  until both sides carry the section. Exit 1 on block, 2 on usage error.

### `masanalyzer.rulepack` / `iocs` / `osv` â€” deployment input layers

* `rulepack.load_rule_pack(path)` â€” JSON DSL â†’ `RulePack`s
  (`CUSTOM-<PACK>-<ID>`), activated via `--rules` / `scan(rule_packs=â€¦)`
  and included in `--list-rules`.
* `iocs.load_intel(path)` â€” `IntelBundle` (domains/IPv4/md5-sha1-sha256 by
  hex length) via `--intel` / `scan(intel=â€¦)`; hits become tagged findings.
* `osv` + `intelcli` (`masanalyzer-refresh-intel`) â€” **CVE currency**:
  OSV.dev `/v1/query` advisory data (keyless, TTL-stamped JSON cache;
  `Maven` coordinates for Android ids, `SwiftURL` repo URLs for iOS
  ids). `scan(osv_cache=â€¦)` / `--osv-cache` keeps itself current: before
  the SCA rules run, the stale coordinates of the SDKs detected in the
  bundle are re-queried (best-effort, 5 s timeout, failures counted in
  `meta["intel_refresh"]` â€” offline machines keep the cached view and the
  scan never aborts); `m02` turns matching SDK-version advisories into
  MAS-SCA-003 findings. `--no-intel-refresh` / `refresh_intel=False`
  skips the re-query for strictly reproducible runs; the explicit
  `masanalyzer-refresh-intel` CLI remains the fleet-wide/CI refresher.

### `masanalyzer.reporting`
Renderers depend only on duck-typed results (`result.target`,
`result.findings`, `Finding.to_dict`, `result.score`) â€” importing
`masanalyzer.reporting` must not pull in the analyzer set.

* **JSON** â€” versioned document (tool/scan/score/summary/findings).
* **Markdown** â€” severity sections, rule tables, remediation blocks.
* **HTML** â€” single-file report; **every text is `html.escape`d**, verified
  by `tests/test_reporting.py` with an injected `<script>` snippet; a
  dark card layout with a hero header and sticky section nav (Overview /
  Behaviour / Callsites / Assurance / Score / Severity / Surface /
  Findings), a findings summary table with `#fnd-N` anchor links that
  jumps straight to the detail cards, severity + assurance-tier chips
  colour-coded, and evidence notes (taint provenance, verification
  failures) render inline.
* **PDF** (`reporting/pdf_report.py`, returns `bytes`) â€” deterministic
  PDF 1.4 built from the base-14 fonts (Helvetica/Bold/Oblique), no
  compression, no external references, byte-reproducible. The layout is
  built for reading: a colored cover banner, a score card (grade letter
  + score/100 + findings count) beside a severity bar chart with
  proportional colored bars, an overview fact table, then findings
  grouped worst-severity-first â€” each opening with a colored severity
  chip, a bold rule-id + title line, a wrapped description and the
  evidence pointer in oblique gray, and a `page N of M` footer on
  every page. Non-Latin-1 strings transliterate to `?`; parens/backslashes
  are escaped per PDF string syntax. `tests/test_pdf_report.py` checks
  the bytes, determinism and the xref table offsets.
* **SARIF 2.1.0** â€” deterministic sorted `rules` array; severity mapping
  critical/high â†’ `error`, medium â†’ `warning`, low/info â†’ `note`; results
  carry full `region` objects (`startLine` + `endLine`, and
  `byteOffset`/`byteLength` for offset-based binary evidence), a
  `runs[].originalUriBaseIds { SRCROOT }` artifact-root definition and
  `columnKind: unicodeCodeUnits` â€” the pieces GitHub Code Scanning needs for
  inline annotations.
* **CycloneDX 1.5 SBOM** (`--format sbom`, aliases `cdx` / `cyclonedx`,
  file `report.cdx.json`) â€” auditable inventory: the application as
  `metadata.component`; native libraries (with hardening-property tape),
  embedded APKs and linked dylibs as `components`; Maven-style
  `group:artifact:version` strings harvested from resources (regex mirrored
  from `m02`, never importing the analysis package); every finding exported
  as a `vulnerabilities` entry (`id` = rule id, OWASP mapping in
  `properties`, severity rating). Fully deterministic: sorted keys,
  component refs sorted, and the serial is a `uuid5` of the target identity.
* **MASVS audit** (`--format audit`, aliases `masvs` / `matrix`,
  `report.audit.md`) â€” `masvs.py` maps every rule onto 17 MASVS v2
  requirement ids (explicit `RULE_TO_MASVS` table + OWASP-category
  fallback) and emits the requirement-level PASS/FAIL/N-A matrix with the
  worst severity per FAIL row. Failures point at mapped findings in the
  JSON/Markdown report; requirement glosses are abbreviated self-authored
  summaries, not the normative MASVS text.
* **CSV** (`--format csv`, `report.csv`) â€” one finding per row with a
  stable column order, stdlib `csv` quoting; for spreadsheet triage.
* **CI renderers** (`--format junit`/alias `xunit`, `--format gitlab`/
  alias `codequality`) â€” `render_junit` (JUnit XML for GitHub Actions/
  Azure, `xml.etree`, escaped attributes, grouped per rule) and
  `render_gitlab` (Code Quality JSON: `check_name`, `severity`,
  `location.path/lines`, `fingerprint` from the finding identity so the
  merge-request widget dedupes across runs).

### `masanalyzer.dashboard` â€” local web workbench

`dashboard.py` turns the toolchain into an upload â†’ scan â†’ report loop
without a CLI. Pure stdlib (`http.server.ThreadingHTTPServer`), binds
`127.0.0.1` by default, no authentication â€” a single-analyst tool by
design, never a network service.

* **Storage** â€” `_Jobs` mirrors an in-memory registry into
  `jobs/<32-hex-id>/job.json`, so job metadata survives a restart; a
  job that was queued/running when the process died is re-marked
  `error` ("dashboard restarted mid-scan"). Each job dir also holds the
  sanitised upload and the ten rendered `report.<fmt>` files (JSON/MD/HTML/PDF/SARIF/SBOM/audit/CSV/JUnit/GitLab).
* **Upload parsing** â€” `extract_upload()` is a hand-rolled
  multipart/form-data reader (`cgi` was removed in Python 3.13):
  boundary scan, accepts only the `file` field, `os.path.basename`s the
  client filename, and `sanitize_upload_name()` neutralises paths and
  unknown extensions (`.apk/.ipa/.aab/.apks/.zip` kept, else `.bin`).
  Uploads are capped (`--max-upload-mib`, default 2048 â†’ HTTP 413).
* **Workers** â€” `_Scanner` is a fixed thread pool (default 2) fed by a
  `queue.Queue`; it runs `scanner.scan(path, progress=...)`, streams the
  progress phases into the job record (polled by the progress page every 0.9 s),
  renders every `reporting.FORMATS` entry to disk, and stamps grade /
  score / finding count / severity histogram / **assurance histogram**
  (verified/structural/heuristic counts) / **attack-surface summary**
  (entry points, unguarded doors, browsable deep links â€” including the
  exposure-ranked `fix_first` queue) from the result.
  One failing renderer skips one file instead of killing the job; a job
  with zero written files ends `error`.
* **Routes** — `GET /` board, `GET /upload` new-scan page,
  `GET /settings` + `POST /settings` (display preferences — board refresh
  interval and the reports page's default preview format — validated,
  stored in `<workdir>/settings.json` and shared by every browser; the
  page also lists the read-only runtime flags so the two are never
  confused),
  `GET /scanning/<id>` live progress, `GET /reports/<id>` format list,
  `GET /jobs`, `GET /job/<id>`, `GET /overview/<id>` (at-a-glance facts
  from `inventory.overview`: hashes, identity, signer certificate,
  permissions, attack surface with the fix-first leader; escaped
  server-side; 404 when the scan predates the overview layer),
  `POST /upload`, `GET /view/<id>/<fmt>` styled viewers for
  `json`/`md`/`sarif`, `GET /report/<id>/<fmt>` (raw inline body) and
  `GET /download/<id>/<fmt>` (`Content-Disposition: attachment`).
  Unknown ids → 404, unknown formats → 400, oversized/non-multipart
  uploads → 413/400. Every route runs under a guard: an uncaught
  exception prints the traceback to the terminal and answers with a themed
  500 page (path, exception type and message, collapsed traceback, back to
  board) instead of dropping the connection — `/jobs` and `/job/<id>`
  answer with a JSON `{"error": ...}` for the same reason.
* **Pages** — one soft-canvas theme shared by every route: lilac-grey
  gradient canvas, white rounded cards, pill top nav with the active
  page in near-black, floating circular icon rail. The board is a live
  card grid (grade disc, severity bar and pills, assurance chips, surface
  line with the fix-first door, polling at the saved interval, name
  filter). Upload pairs a
  dashed drop zone with limits/worker panels and recent uploads, posts
  with `fetch` and lands on the progress page, which polls `/job/<id>`
  every 0.9 s, walks a four-phase stepper from the scanner's phase
  callbacks and streams the transcript. Reports lists the nine file
  formats (HTML lives on the overview instead) in three labelled groups,
  with real byte sizes, preview/download actions and an inline `<iframe>`
  preview of the selected format. From 1600px the format grid goes three
  across, the preview iframe takes `clamp(520px,66vh,900px)` of height and
  the viewers' side rail grows to 400px (460px from 2000px) so the extra
  width is used instead of stretched. The overview keeps the fact cards,
  permission table, assurance matrix and renders the report's own score
  table, callsite receipts and findings list as cards in the same visual
  language (no nested document), the detail cards grouped into
  collapsible severity blocks (closed by default, expand/collapse-all
  controls, each job's open state remembered in `localStorage` under
  `mas.sev.<job id>`), with severity chips in that bar that narrow the
  summary table and the groups together. Group headers are sticky
  (`top:64px`, below the topbar), so the severity stays on screen while
  you read through its cards; the three viewers share
  the chrome (markdown card + on-this-page rail, lazy JSON tree with
  search/path bar, SARIF triage table). Every board card is itself the
  link to its overview, with the inner Findings/Open links keeping their
  own targets. The HTML exporter in `reporting/html_report.py` uses the
  same soft-canvas theme, so the embedded, opened and downloaded report
  match the dashboard. No external assets: inline SVG
  icons, CSS-drawn format thumbnails, initials avatars (a bundle's own
  launcher icon is extracted at scan time - manifest `android:icon`
  resolved through `resources.arsc` to a zip entry, largest square image
  as fallback - written beside the reports and served from `/icon/<id>`,
  with the initials kept for older jobs and other platforms). Adaptive
  icons (`mipmap-anydpi-v26/*.xml`) are composited: `resource_colors` in
  `android/resources.py` recovers colour layers from the table, `raster.py`
  decodes/encodes PNG and stacks the layers cropped to the 72/108 launcher
  safe zone; when a layer is WebP the composite is emitted as one SVG that
  references the layers and draws the   same crop. Every dynamic value escaped.
* Covered by `tests/test_dashboard.py`: a real `ThreadingHTTPServer` on
  an ephemeral port runs a synthetic APK through upload â†’ poll â†’
  report/download assertions (a second fixture with an exported
  browsable door and a dangerous permission proves the fix-first queue
  reaches the job record, the page and the overview route), plus
  overview-page/404/link coverage, 404/400/413 paths, multipart
  sanitisation units and `_Jobs` restart persistence.

### Inventory enrichment (pre-analyzer step)

`packaging._finish()` runs after the container-specific enrichment of
every platform:

* `endpoints.build_inventory()` â€” URLs / bare domains / IPv4 literals
  harvested from the shared `string_pool` (DEX, `resources.arsc`, native
  strings, binary plists) plus text files; each host is classified
  (`tracker` against a curated analytics/ad list, `private` via the
  stdlib `ipaddress` module, `local`, `first_party` heuristic by package
  id token overlap, else `public`) and stored JSON-ready under
  `target.meta["endpoints"]`; `report.json` carries it in `inventory`.
* `packaging._so_graph()` â€” `elfdeps.inspect_blob()` parses the ELF
  program headers and dynamic table (`DT_NEEDED` + `DT_STRTAB` resolved
  through the PT_LOAD vaddrâ†’offset mapping) into per-library dependencies
  and a conservative dangerous-import byte scan (`dlopen`, `mprotect`,
  `ptrace`, `exec*`); `missing_dependencies()` flags `DT_NEEDED` entries
  with no same-bundle or NDK system provider. Stored in
  `target.meta["so_graph"]`.
* `packaging._load_idsig()` â€” parses a sibling `<apk>.idsig`
  (`android/apksigv4.py`): header contract (`APKV` magic, chunk/digest
  sizes, tree/digest/signer/cert offsets) plus the embedded X.509 leaf,
  cross-checked against the APK signer fingerprints
  (`idsig.signer_match`) and a hash-tree size sanity check
  (`idsig.tree_shape_ok`).
* `analysis/privacy.py::build_privacy_matrix()` â€” the **excess-access
  matrix**: declared dangerous/sensitive permissions joined with observed
  API corroboration (DEX descriptors, pool strings, manifest wiring)
  under `target.meta["privacy_matrix"]`; `m06` derives MAS-PRI-007/008
  and `m08` derives MAS-MIS-007 from the special-access column.
* `sdks.detect_sdks()` â€” curated SDK fingerprinting: Android ids over
  every DEX string table (character-trie regex, capped-cost version scan),
  iOS ids over embedded `<Name>.framework` bundles (version from each
  framework's `Info.plist`) â€” plus pool and native strings. SCA bands
  (`VULNERABLE_SDKS`/`EOL_SDKS`) produce MAS-SCA-001/002 and the optional
  OSV cache produces MAS-SCA-003.

### Performance

File hashing + classification and per-`.so` ELF parsing run on a bounded
`ThreadPoolExecutor` (`min(8, cpu_count)`) once the tree crosses
`_FILES_PARALLEL_THRESHOLD` (24 files); small scans stay serial.
Determinism is preserved: `executor.map` yields in input order, so file
inventory, `native_libs` and all report output are exactly as produced by
the serial path.

## Determinism & hygiene

* No randomness in parsing rules or emitter output; findings are sorted
  (severity desc â†’ risk â†’ rule â†’ location).
* Temporary unpack dirs are `<tmp>/masan_*`; removed on scan completion
  unless `--keep-workdir`.
* Windows-first: everything invoked with `python -X utf8` to avoid cp1252
  decode errors in console output and file writes with explicit encodings.

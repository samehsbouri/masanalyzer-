# masanalyzer rules catalog

Rule ids follow `MAS-<AREA>-<NNN>`:

| AREA | Meaning |
| --- | --- |
| `CRED` | hardcoded credentials (M1) |
| `SUP` | supply chain / signing (M2) |
| `AUTH` | authentication & authorization (M3) |
| `INPUT` | input/output validation (M4) |
| `NET` | communication security (M5) |
| `PRI` | privacy / logging (M6) |
| `BIN` | binary protections (M7) |
| `MIS` | security misconfiguration (M8) |
| `STO` | data storage (M9) |
| `CRY` | cryptography (M10) |

Findings are tagged with the OWASP Mobile Top 10 **2024** id (`M1…M10`),
CWE, an indicative CVSS v3.1 base score and a confidence level; the legacy
MSTG 2016 mapping is kept in `masanalyzer/owasp.py` (`CATEGORIES`).

## M1 — Improper Credential Usage (`analysis/m01.py`)

| Rule | Severity | Detects |
| --- | --- | --- |
| MAS-CRED-001 | high | `password = "…"` assignments |
| MAS-CRED-002 | high | `api_key` / `secret` / `token` literals in source |
| MAS-CRED-003 | high | Cloud credentials in compiled assets (AWS `AKIA…`, Google `AIza…`, GitHub `ghp_…`, Stripe `sk_live_…`) |
| MAS-CRED-004 | high | `Authorization: Bearer …` / JWT-shaped literals |
| MAS-CRED-005 | high | JDBC/Mongo/Postgres connection strings with embedded credentials |
| MAS-CRED-006 | high | `https://user:pass@host` basic-auth URLs |
| MAS-CRED-007 | medium | URLs with `password|token|secret` query keys |
| MAS-CRED-008 | medium | credential-shaped keys in property lists (Keychain bypass) |
| MAS-CRED-009 | medium | `firebaseio.com` endpoint embedded in the bundle (verify the project's security rules — Google documents that default rules expose records; rules cannot be checked offline) |

## M2 — Supply Chain (`m02.py`)

MAS-SUP-001 unsigned APK · MAS-SUP-002 debug/test-cert signing ·
MAS-SUP-003 v1-only scheme · MAS-SUP-004 outdated pinned dependencies ·
MAS-SUP-005 targetSdk < 29 · MAS-BIN-010 unsigned Mach-O ·
MAS-SUP-007 unsigned embedded APK ·
MAS-SUP-008 **v1 (JAR) signature verification failed** (critical, CWE-494) —
the PKCS#7→.SF→manifest→entry chain could not be validated: invalid attacker
signature over the .SF, .SF manifest-digest mismatch, modified entry content,
or archive entries not covered by the signed manifest.
MAS-SUP-009 **Janus exposure (CVE-2017-13156)** (high) — ZIP central-directory
entries pointing at non-local-file-header offsets, or a v1-only bundle with
DEX shipped on targetSdk ≥ 24.
MAS-SUP-010 **v2 signature verification failed** (critical) —
whole-file signing block present but content digest / signature / algorithm
equality / SPKI checks do not hold (`android/apksigv2.py`).
MAS-SUP-011 **v3 signature verification failed** (critical) — same checks for
the rotation-aware scheme on Android 9+.
MAS-SUP-012 missing `X-Android-APK-Signed` rollback banner (medium) —
a v1+v2/v3 bundle whose `.SF` does not declare the whole-file scheme ids.
MAS-SUP-013 signing certificate **expired or expiring ≤90 days**
(high) — validity window parsed from the X.509 leaf (v1 PKCS#7 / v2/v3
signing block); note shows the days and subject CN.
MAS-SUP-014 **weak signing-key material** (high, CWE-326) — RSA modulus
below 2048 bits detected via the parsed SPKI.
MAS-SUP-015 **v4 `.idsig` sidecar inconsistent with the APK signers**
(medium) — the sidecar's embedded signing certificate does not match any
APK v1/v2/v3 signer fingerprint, or its hash-tree size does not fit the
APK size; `android/apksigv4.py` parses the sidecar and cross-checks, the
result lands in `report.json` → `target`/`meta` as `idsig`.

### Software composition (SDK fingerprinting + SCA)

SDK detection (`sdks.py`) matches curated class-descriptor signatures
against every DEX string table directly (immune to the string-pool cap)
plus pool/native strings; results are shipped in
`json` → `inventory.sdks` with a best-effort `version` string.

| Rule | Severity | Detects |
| --- | --- | --- |
| MAS-SCA-001 | high | embedded SDK in a vendor-documented weak-version band (`VULNERABLE_SDKS`; facts only, no invented CVEs — extensible at runtime via `sdks.add_vulnerable_rule`) |
| MAS-SCA-002 | low | end-of-life SDK family (`EOL_SDKS`: Apache HttpClient port, HockeyApp, MoPub, Fabric/Answers) |
| MAS-SCA-003 | high | **advisory match from the OSV.dev cache** — see [CVE currency](#cve-currency--the-osv-cache-mas-sca-003) |

## M3 — Authentication/Authorization (`m03.py`)

MAS-AUTH-001 exported provider without permission guard (high) ·
MAS-AUTH-002 exported component without protection ·
MAS-AUTH-003 implicit export via intent-filter ·
MAS-AUTH-004 exported auth-flow component · MAS-AUTH-005 sharedUserId ·
MAS-AUTH-006 browsable deep link without validation.

## M4 — Input/Output Validation (`m04.py`)

MAS-INPUT-001 SQL built via `SELECT…' + var` (high) ·
MAS-INPUT-002 `Runtime.exec`/`ProcessBuilder` with concatenation (high) ·
MAS-INPUT-003 `new File(...)` fed from intents/external storage (high) ·
MAS-INPUT-004 `loadUrl(<unvalidated>)` · MAS-INPUT-005
`getQueryParameter` flowing into SQL (high) ·
MAS-INPUT-006 **user data reaches a sensitive sink (taint flow)** (high,
CWE-20) — value captured from an untrusted source (intent extra, deep link,
external storage, stream input) flows through local variables into a
database/command/file/WebView/component-launch call site without validation
on the path; the finding note records the captured variable and source line.
MAS-INPUT-007 **polymorphic deserialization of untrusted data** (high,
CWE-502) — `ObjectMapper.enableDefaultTyping()/activateDefaultTyping()`
embeds class names in payloads; untrusted input becomes a gadget-chain
execution primitive (MobSF `android_jackson_deserialize` parity).
MAS-INPUT-008 **LocalServerSocket without authentication** (medium,
CWE-306) — abstract-namespace local server socket reachable by any app on
the device; require an app-private handshake.

## M5 — Communication (`m05.py`)

MAS-NET-001 manifest `usesCleartextTraffic` · MAS-NET-002 NSC cleartext
domains · MAS-NET-003 `src="user"` trust anchors · MAS-NET-004 no pin-set ·
MAS-NET-005 `http://` endpoints · MAS-NET-006 trust-all
X509TrustManager/HostnameVerifier (**critical**) · MAS-NET-007 iOS ATS
`NSAllowsArbitraryLoads` ·
MAS-NET-008 third-party tracking/analytics endpoint referenced (low) —
suffix match against a curated list from the URL inventory
(`endpoints.py`, `meta["endpoints"]`) ·
MAS-NET-009 private/internal network address shipped in the bundle
(low, CWE-200) — RFC1918 / loopback / `.internal` names map an attacker's
pivot path.
MAS-NET-010 **WebView ignores TLS certificate errors** (high, CWE-295) —
`onReceivedSslError` handler calls `proceed()`, so the WebView accepts any
certificate a MITM presents (MobSF `android_webview_ignore_ssl` parity).
MAS-NET-011 **WebView mixed content unrestricted** (medium, CWE-319) —
`setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` re-opens an HTTP
content-injection channel inside HTTPS pages.

**Callsite receipts** (`android/dex.py::analyze_callsites`): the DEX
bytecode walker pairs URL-shaped `const-string` constants (tracking them
through `move-object` copies) with invokes into network-facing classes
(`java.net.*`, OkHttp, Retrofit, Volley, Apache-http, `WebView#loadUrl`,
DownloadManager, Chromium net). Receipts land in
`target.meta["callsites"]` (each: dex / method / url / callee / offset)
and the URL inventory attaches `called_from` (up to 4 calling methods)
to each URL endpoint row — evidence pointers, not dataflow guarantees;
registers were tracked linearly, so control-flow merges are a known
limitation. Decode stats ship as `meta["callsite_stats"]`.

## M6 — Privacy (`m06.py`)

MAS-PRI-001 credentials in logs · MAS-PRI-002 PII in logs ·
MAS-PRI-003 secrets printed to stdout (iOS) · MAS-PRI-005 PII keys in
plists · MAS-PRI-006 capturable credential screens ·
MAS-PRI-007 **excess access: sensitive permission never exercised**
(medium, CWE-250) — a sensitive runtime permission (location, camera,
microphone, contacts, SMS, phone-identity) is declared but no code path
exercises its APIs (`analysis/privacy.py` builds the
`meta["privacy_matrix"]` corroborated/unused split) ·
MAS-PRI-008 **excess access: dangerous permission without observed use**
(low) — declared dangerous permission with no corroborating API use
anywhere in the artifact.

## M7 — Binary Protections (`m07.py`)

MAS-BIN-001 debuggable build / get-task-allow · MAS-BIN-002 non-PIE `.so`
(high) · MAS-BIN-003 executable GNU_STACK (high) · MAS-BIN-004 Mach-O
without `MH_PIE` · MAS-BIN-005 Mach-O with `MH_ALLOW_STACK_EXECUTION` ·
MAS-BIN-006 unobfuscated dex (≥20 business-named classes) ·
MAS-BIN-007 stripped-symbol absence · MAS-BIN-008 dev provisioning profile ·
MAS-BIN-011 no full RELRO / writable text (medium) — `.so` without
`PT_GNU_RELRO`+`DT_BIND_NOW`, or `DT_TEXTREL` present (`packaging.py`
parses the ELF dynamic table); ·
MAS-BIN-012 **iOS code signature verification failed** (high, CWE-494) —
LC_CODE_SIGNATURE blob present but `ios/codesign.py` cannot verify the
CodeDirectory (malformed SuperBlob, page-shaped SHA-256 hashes differ from
the file, CMS messageDigest mismatch); ·
MAS-BIN-013 native library resolves code at runtime (medium) —
`dlopen`/`dlsym` imports (`elfdeps.py` byte scan, low-confidence) ·
MAS-BIN-014 native library creates executable memory (medium) —
`mprotect`/`memfd_create` imports ·
MAS-BIN-015 **native library depends on a missing shared object**
(high) — a `DT_NEEDED` entry that is neither an Android system library
nor another shipped `.so`; those libs crash at load time ·
MAS-BIN-016 native library launches processes or debug-hooks itself
(low) — `exec*`/`ptrace` imports.
MAS-BIN-017 **packer / anti-disassembly wrapper detected** (medium,
CWE-1357) — MobSF/APKiD-parity packer fingerprinting: loader-library file
names, stub classes and encrypted-dex asset names matched against a
self-authored signature table of the widely documented commercial packers
(Qihoo 360 Jiagu, Tencent Legu, Ijiami, Bangcle/SecNeo, Baidu,
AppSanguino, NetEase Yidun, Alibaba, Tencent Kiwi, DexProtector); the
evidence names the exact signature and matched string/file.
MAS-BIN-018 superuser / instrumentation tooling referenced (medium,
CWE-250) — bundle references root tooling (su managers, SuperSU, Xposed,
Cydia Substrate, su binary paths), usually root-detection logic; review
that it stays detection-only (MobSF `android_su_detect` parity).
MAS-BIN-019 **native library compiled without stack canaries** (medium,
CWE-693) — no `__stack_chk_fail`/`__stack_chk_guard` reference in the
dynamic symbol table (`elfdeps.py` byte match), i.e. built without
`-fstack-protector-strong`; only asserted when the symbol table was
actually parsed (gated on the PIE flag).
MAS-BIN-020 native library compiled without FORTIFY_SOURCE (low,
CWE-693) — no fortified `__*_chk` libc wrappers (`__memcpy_chk`,
`__strlen_chk`, …) in the symbol table; same gating as MAS-BIN-019.

## M8 — Misconfiguration (`m08.py`)

MAS-MIS-001 `allowBackup` without rules · MAS-MIS-002 `testOnly` ·
MAS-MIS-003 signature-only permission requests (`SET_DEBUG_APP`,
`INSTALL_PACKAGES`, …) · MAS-MIS-004 `addJavascriptInterface` with file
access (high) · MAS-MIS-005 `setJavaScriptEnabled(true)` ·
MAS-MIS-006 `extractNativeLibs=true` ·
MAS-MIS-007 **special-access privilege declared** (medium) — grants that
bypass the usual dialog flow (`INSTALL_PACKAGES`, overlay
`SYSTEM_ALERT_WINDOW`, all-files access, write-secure-settings,
package-usage-stats): store policy needs explicit justification and each
is a known abuse vector.
MAS-MIS-008 **WebView remote debugging enabled** (medium, CWE-489) —
`setWebContentsDebuggingEnabled(true)` (source) or the API referenced in
the compiled string pool (verify the flag is debug-build-only) — MobSF
`android_webview_debug` parity.

## M9 — Data Storage (`m09.py`)

MAS-STO-001 `MODE_WORLD_READABLE` (**critical**) · MAS-STO-002 external
storage dumps · MAS-STO-005 credentials in UserDefaults/plists ·
MAS-STO-007 plaintext DBs holding credential-shaped tables ·
MAS-STO-010 session material reconstructed from constants.

## M10 — Cryptography (`m10.py`)

MAS-CRY-001 MD5/SHA-1 · MAS-CRY-002 DES/3DES/RC4/Blowfish (high) ·
MAS-CRY-003 ECB (high) · MAS-CRY-004 `Cipher.getInstance("AES")` default
transformation (high) · MAS-CRY-005 `Random`/`Math.random` for security
values · MAS-CRY-006 `setSeed(System.currentTimeMillis())` ·
MAS-CRY-007 static IV literals · MAS-CRY-008 CBC without MAC.
MAS-CRY-009 **RSA without OAEP padding** (high, CWE-780) —
`Cipher.getInstance("RSA/…/NoPadding")` is deterministic, malleable raw
RSA; use OAEP or a hybrid AES-GCM envelope (MobSF `android_rsa_no_oaep`
parity).

## Rule packs (CUSTOM-* rules)

Deployment-defined signatures ride the same finding pipeline:

```
masanalyzer scan app.apk --rules mypack.json --rules other.json
masanalyzer --list-rules          # built-ins + activated packs
masanalyzer scan app.apk --rules mypack.json --list-rules
```

`load_rule_pack(path)` parses a JSON DSL → `RulePack` objects whose rules
run after the built-ins; generated ids are `CUSTOM-<PACK>-<ID>` so they
can never shadow MAS-* ids. See `rulepack.py` and the pack examples in
`docs/` samples for the schema.

## IOC intel files (--intel)

`iocs.load_intel("intel.txt")` expects one indicator per line — domains,
bare IPv4 addresses, or md5/sha1/sha256 hex digests (keyed by hex length);
`#` opens a comment. Pass bundles with `--intel FILE` (repeatable): any
hit in the string pool becomes a high/critical `intel` finding referencing
the matched indicator, and per-indicator counts stay in
`meta["intel_stats"]`.

## CVE currency — the OSV cache (MAS-SCA-003)

The curated `VULNERABLE_SDKS`/`EOL_SDKS` tables freeze at release time;
the OSV cache keeps component findings current without compromising the
offline scan:

1. **Refresh (network stops here):**
   `masanalyzer-refresh-intel app.apk [--cache PATH] [--ttl 86400] [--force]`
   detects SDKs in any bundle (APK/IPA/.aab/.apks), POSTs one keyless query
   per known coordinate to `https://api.osv.dev/v1/query` — Android ids
   through `osv.py::MAVEN_COORDS` (ecosystem `Maven`), iOS framework ids
   through `osv.py::IOS_POD_COORDS` (ecosystem `SwiftURL`, keyed by git
   repository URL) — and merges trimmed advisories
   (id/summary/versions/first-fixed) into a JSON cache — per-user default
   path, TTL-guarded so unchanged coordinates are not re-queried.
2. **Scan (auto-current):**
   `masanalyzer scan app.apk --osv-cache PATH` — before the SCA rules
   run, the scan re-queries the stale coordinates behind the SDKs it
   detected (best-effort, 5 s timeout; each network failure is counted
   in `meta["intel_refresh"]`, warned about, and never aborts the scan),
   then an SDK hit whose observed version matches an advisory (enumerated
   version or below the first fixed event) becomes a MAS-SCA-003 finding
   citing the advisory id + summary. A refreshed cache is written back to
   disk so the next scan starts warm. `--no-intel-refresh` (or
   `refresh_intel=False`) skips the re-query for strictly reproducible,
   no-network runs.
3. **Currency is visible, never silent:** the cache stores provenance
   (newest fetch timestamp, coordinate/advisory counts, written by every
   save). Scans embed the deterministic part as an `intel` section in
   `report.json` and a CVE-data line in the Markdown report; the
   wall-clock age deliberately stays out of report documents — it
   appears on operational surfaces: a stderr warning when the cache is
   7+ days old or has coordinates beyond the 24 h TTL, and a
   `CVE <N>d` chip per job in the dashboard (amber when stale).
4. **Extensibility:** both coordinate maps are plain dicts shipped in
   `osv.py`; platform teams add their internal libraries there (iOS hits
   without a mapping — e.g. the closed-source AppLovinSDK — are
   inventoried but deliberately never matched).
5. **iOS detection (`sdks.py`):** embedded SDKs on IPA targets surface as
   `<Name>.framework` bundles under `Payload/<App>.app/Frameworks/`
   (`sdks.detect_sdks` reads the file tree directly and takes the
   version from each framework's own `Info.plist`
   `CFBundleShortVersionString`).

## Containers beyond plain APK

`packaging.prepare_target` accepts, besides APK/IPA/trees:

- **`.apks` (APK Set)** — `base.apk` (or the largest inner APK) is scanned
  as the primary target; every further inner APK's entries are merged into
  the file tree under `splits/<splitname>/…` (their protobuf-only
  manifests and META-INF are skipped); `meta["container"]="apks"`,
  `meta["base_apk"]`, `meta["splits"]` document the merge.
- **`.aab` (App Bundle)** — the bundle tree is extracted and scanned
  flattened (`base/dex/*.dex`, `base/lib/**/*.so`, assets); the protobuf
  manifest/resources.pb blocks cannot be parsed without bundletool, are
  flagged as binary and produce a `meta["aab_proto_manifests"]` warning
  instead of parse noise.

## Finding lifecycle

1. An analyzer build `Finding`s via `Rule.finding(...)` — severity, CWE,
   CVSS and remediation come from immutable rule metadata.
2. `FindingCollector.add` dedupes by `Finding.identity` (rule + file +
   location + snippet) and sorts by risk.
3. The registry tags each finding with its OWASP 2024 category; scoring
   (`reporting/score.py`) aggregates per category.
4. Post-collect, the scanner stamps an **assurance tier** on every
   finding (`masanalyzer/assurance.py`): `verified` (cryptographic
   verification / binary header parsing — reproducible by anyone on the
   same artifact), `structural` (parsed configuration fact — manifest
   flags, NSC XML, plists, ZIP layout, inventory classification) or
   `heuristic` (pattern match over source/binary text; default). Rules
   not in the tier table default to `heuristic`.
5. The scanner also synthesizes the **attack surface**
   (`masanalyzer/surface.py`): every exported manifest component becomes
   an entry point carrying its permission guard, browsable deep links
   and the findings attached to it (exact component-name evidence, or
   manifest-global rules `MAS-MIS-003`/`MAS-MIS-007`), plus a summary
   (unprotected doors, deep-link hosts, WebView integration files).
   Each door also gets a transparent exposure score
   (worst severity 0–5 + 2 × verified findings + 1 if unguarded +
   min(deep links, 3)) and a `why` rationale; the ranked **Fix first**
   queue is part of the summary and rendered in every format.
   It is embedded as `inventory.attack_surface` in `report.json`, the
   `## Attack surface` section in Markdown/HTML — and
   `masanalyzer-delta --gate-surface` diffs the surface between two
   releases, blocking when an unguarded door or browsable deep link is
   added.

## Adding a rule

```python
R_NEW = make_rule(
    "MAS-AREA-NNN", "M5", "Title", "What it means", Severity.HIGH,
    "How to fix", cwe="CWE-295", confidence=Confidence.HIGH, cvss=7.0,
)

def analyze(target: Target) -> Iterable[Finding]:
    for sf, lineno, line in code_lines(target, kinds=("code", "smali")):
        if PATTERN.search(line):
            yield R_NEW.finding(file=sf.relpath, line=lineno,
                                snippet=sf.line_at(lineno) or line)
```

Keep rules per-file deduplicated (see `m05` trust-all scan) so repeated
pattern hits on one file stay a single finding.

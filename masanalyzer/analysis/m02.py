"""M2 - Inadequate Supply Chain Security.

Reports bundle/signing integrity problems (unsigned or debug-signed APKs,
missing v2-equivalent scheme, unsigned embedded bundles, unsigned Mach-O
images) and outdated third-party dependencies referenced in build scripts.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from ..model import Confidence, Finding, Severity, Target
from .common import code_lines, make_rule, matches_in_text, version_lt

MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
LOW = Severity.LOW
CRITICAL = Severity.CRITICAL

R_UNSIGNED = make_rule(
    "MAS-SUP-001",
    "M2",
    "Application bundle is not signed",
    "No v1 (JAR) or v2/v3 (APK Signing Block) signature was found. The bundle "
    "cannot be installed from an app store and provides no publisher proof.",
    HIGH,
    "Sign release builds with the platform signing scheme and keep the key in a "
    "managed keystore service.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=7.0,
)

R_DEBUG_SIGNED = make_rule(
    "MAS-SUP-002",
    "M2",
    "Bundle signed with a debug/test certificate",
    "The signer certificate carries a debug/test Common Name, meaning the build "
    "was not produced by the release pipeline.",
    MEDIUM,
    "Ship only certificates issued by the release pipeline; remove debug "
    "signing connectors from CI.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=5.5,
)

R_V1_ONLY = make_rule(
    "MAS-SUP-003",
    "M2",
    "Signed only with the legacy v1 (JAR) scheme",
    "v1-only bundles installed on targetSdk >= 24 are rejected, and v1 can be "
    "re-packed without detection because the ZIP contents are not protected as "
    "a whole.",
    MEDIUM,
    "Enable v2 (or v3+) signature schemes in the build (signingConfig), which "
    "cover the whole archive.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=5.7,
)

R_DEPRECATED_LIB = make_rule(
    "MAS-SUP-004",
    "M2",
    "Outdated third-party dependency declared",
    "A declared dependency is older than the first version containing publicly "
    "known security fixes for this component family.",
    MEDIUM,
    "Update the dependency to the patched line; pin dependency versions and "
    "audit them in CI.",
    cwe="CWE-1104",
    confidence=Confidence.MEDIUM,
)

R_DEPRECATED_TARGET_SDK = make_rule(
    "MAS-SUP-005",
    "M2",
    "Build targets an obsolete Android API level",
    "targetSdkVersion below 29 no longer receives current platform security "
    "guarantees (scoped storage, hardened network defaults, runtime"
    " restrictions).",
    MEDIUM,
    "Raise targetSdkVersion to a supported level and re-test permission flows.",
    cwe="CWE-1104",
    confidence=Confidence.HIGH,
    cvss=5.0,
)

R_NO_CODESIGN_MACHO = make_rule(
    "MAS-BIN-010",
    "M2",
    "Mach-O image without a code signature",
    "No LC_CODE_SIGNATURE load command was found in the image; the binary will "
    "not pass notarisation and lacks an integrity seal.",
    LOW,
    "Sign and notarise every shipped binary, including frameworks and tools.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=3.0,
    platform="ios",
)

R_UNSIGNED_EMBEDDED = make_rule(
    "MAS-SUP-007",
    "M2",
    "Embedded APK inside the bundle is unsigned",
    "An embedded .apk payload (common for dynamic feature delivery) carries no "
    "signature; tampered payloads can be swapped silently.",
    MEDIUM,
    "Sign embedded bundles and verify their signature before install.",
    cwe="CWE-494",
    confidence=Confidence.MEDIUM,
)

R_V1_BROKEN = make_rule(
    "MAS-SUP-008",
    "M2",
    "APK v1 (JAR) signature verification FAILED",
    "The v1 signature exists but does not verify as a chain: the PKCS#7 "
    "blob is not cryptographically valid over the .SF, the .SF does not "
    "digest the manifest, an entry digest mismatches its signed value "
    "(content was modified after signing), or the manifest does not cover "
    "every archive entry. Android's PackageManager would refuse this bundle.",
    CRITICAL,
    "Re-pack and re-sign with the release pipeline; treat the analyzed file "
    "as an untrusted, potentially trojanised artifact.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=9.0,
)

R_JANUS = make_rule(
    "MAS-SUP-009",
    "M2",
    "Janus exposure (CVE-2017-13156) / ZIP layout tampering",
    "The archive is protected only with the v1 (JAR) scheme while "
    "whole-file signatures exist, or its ZIP central directory points "
    "into the middle of the entries payload. Both are the conditions of "
    "Janus: a crafted prefix of DEX bytes can be glued to a v1-only APK "
    "without invalidating any installed signature, so tampered classes "
    "load instead of the published ones.",
    HIGH,
    "Sign with v2/v3 schemes (which cover the whole file), keep "
    "X-Android-APK-Signed in the .SF, and treat a bundle that fails the "
    "ZIP layout check as malicious.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=8.2,
)

R_V2_BROKEN = make_rule(
    "MAS-SUP-010",
    "M2",
    "APK v2 signature verification FAILED",
    "A whole-file (v2) signing block exists but does not verify: the "
    "signature over the signed data is invalid, the recomputed content "
    "digest of entry / central-directory / EOCD sections differs from "
    "the signed digest, algorithm lists differ between digests and "
    "signatures (strip/add risk), the public key does not match the "
    "certificate, or the block layout is inconsistent. The bundle would "
    "be rejected by modern Android and is likely repacked.",
    CRITICAL,
    "Re-pack and re-sign with the release pipeline; treat the analyzed "
    "file as an untrusted, potentially trojanised artifact.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=9.0,
)

R_V3_BROKEN = make_rule(
    "MAS-SUP-011",
    "M2",
    "APK v3 signature verification FAILED",
    "The v3 (rotation-aware) block is present but fails verification "
    "(signature, content digest, algorithm-list equality, or "
    "certificate/SPKI mismatch). On Android 9+ that means the whole-file "
    "chain is broken and the artifact may have been tampered with after "
    "signing.",
    CRITICAL,
    "Re-pack and re-sign with the release pipeline; treat the analyzed "
    "file as an untrusted, potentially trojanised artifact.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=9.0,
)

R_ROLLBACK = make_rule(
    "MAS-SUP-012",
    "M2",
    "Missing X-Android-APK-Signed rollback banner",
    "The APK carries both a v1 (JAR) signature and a whole-file (v2/v3) "
    "signature, but the .SF metadata section does not declare "
    "\"X-Android-APK-Signed: 2 ...\". Platform code that trusts the v1 "
    "path could accept a v2/v3-stripped variant of this bundle.",
    MEDIUM,
    "Build with apksig-signer defaults (the banner is written "
    "automatically) and do not post-process signed artifacts.",
    cwe="CWE-494",
    confidence=Confidence.HIGH,
    cvss=5.5,
)

R_CERT_EXPIRED = make_rule(
    "MAS-SUP-013",
    "M2",
    "Signing certificate expired or expiring",
    "The certificate that signed the bundle is either already outside its "
    "validity window or runs out within 90 days. Expired signing keys "
    "cannot produce trustworthy release updates - platforms warn, and "
    "enterprise MDM allow-lists start rejecting the app - and last-minute "
    "key rotation is exactly when silently shipping under the wrong "
    "certificate happens.",
    HIGH,
    "Rotate to a fresh release certificate with plenty of runway and "
    "enroll it in the platform's rotation scheme (APK v3 key rotation "
    "needs the old and new cert in the block).",
    cwe="CWE-1357",
    confidence=Confidence.HIGH,
    cvss=6.5,
)

R_CERT_WEAK_KEY = make_rule(
    "MAS-SUP-014",
    "M2",
    "Weak signing-key material",
    "The signing certificate's key is below today's minimum (RSA < 2048 "
    "bits). A 1024-bit modulus is within reach of determined adversaries "
    "and forms the trust anchor for the app's whole supply-chain story - "
    "if it falls, updates can be signed in the publisher's name.",
    HIGH,
    "Generate an RSA-3072 (or EC P-256) release key, move artifacts to it "
    "via the v3 rotation scheme, and retire the weak key.",
    cwe="CWE-326",
    confidence=Confidence.HIGH,
    cvss=7.5,
)

R_IDSIG_MISMATCH = make_rule(
    "MAS-SUP-015",
    "M2",
    "APK v4 sidecar (.idsig) inconsistent with the APK signers",
    "The shipped ``.idsig`` (incremental-install signature sidecar) "
    "embeds a signing certificate that does not match the APK's own "
    "v1/v2/v3 signing certificates, or its hash-tree shape does not "
    "match the APK size increment: the sidecar belongs to a different "
    "build. Incremental installs would fail, and a stale sidecar can "
    "hide a repack, since only the base APK was rebuilt/re-signed.",
    MEDIUM,
    "Regenerate the .idsig with apksig's v4 signer in the same build "
    "step as the APK, and ship both atomically from CI.",
    cwe="CWE-1357",
    confidence=Confidence.HIGH,
    platform="android",
)

R_SCA_VULNERABLE = make_rule(
    "MAS-SCA-001",
    "M2",
    "Embedded SDK version falls in a known-weak band",
    "A third-party SDK detected inside the bundle resolves to a version "
    "that its own vendor documentation marks as weak (see the curated "
    "table; masanalyzer only reports vendor-documented facts, never "
    "invented CVEs). Attackers enumerate component versions exactly this "
    "way before picking their exploit path.",
    HIGH,
    "Upgrade the SDK to the vendor's fixed/current version, or remove the "
    "integration. Teams can extend the vulnerable-version table via "
    "``sdks.add_vulnerable_rule`` to encode their own policy bands.",
    cwe="CWE-1395",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_SCA_EOL = make_rule(
    "MAS-SCA-002",
    "M2",
    "End-of-life embedded SDK",
    "An SDK family detected in the bundle is end-of-life: it no longer "
    "receives security patches (retired or sunset by its maintainer), so "
    "any future vulnerability in it stays open in shipped builds.",
    LOW,
    "Migrate to the successor SDK (or maintain a fork you actually "
    "control); track retirement dates for every third-party integration.",
    cwe="CWE-1104",
    confidence=Confidence.MEDIUM,
    platform="android",
)

R_SCA_CVE = make_rule(
    "MAS-SCA-003",
    "M2",
    "Advisory match from the OSV intelligence cache",
    "A third-party SDK detected inside the bundle matches an advisory in "
    "the OSV.dev cache. The scan refreshes stale coordinates of the SDKs "
    "it detects automatically (best-effort; offline machines keep their "
    "cached view), and the explicit ``masanalyzer-refresh-intel`` command "
    "does the same for whole fleets on CI. masanalyzer reports what the "
    "cache says - advisory id and summary from the public OSV database "
    "paired with the version string observed in the bundle - so component "
    "findings age with real vulnerability data instead of freezing at the "
    "table shipped with the tool.",
    HIGH,
    "Follow the cited advisory: upgrade the SDK past the fixed version or "
    "remove the integration. The cache refreshes automatically at scan "
    "time; ``masanalyzer-refresh-intel`` on CI keeps fleet-wide data warm "
    "even for bundles that are never scanned locally.",
    cwe="CWE-1395",
    confidence=Confidence.MEDIUM,
    platform="any",
)

R_PINNED_OLD_OK: Tuple[str, ...] = tuple()

#: component -> first patched line per public vulnerability history
_KNOWN_PATCHED = (
    ("com.fasterxml.jackson.core:jackson-databind", "2.10.0"),
    ("com.squareup.okhttp3:okhttp", "3.12.0"),
    ("log4j:log4j", "2.15.0"),
    ("org.apache.logging.log4j", "2.15.0"),
    ("com.android.support:appcompat-v7", "29.0.0"),
    ("com.google.android.material:material", "1.2.0"),
    ("org.apache.httpcomponents:httpclient", "4.5.13"),
    ("xerces:xercesImpl", "2.12.1"),
    ("commons-collections:commons-collections", "3.2.2"),
    ("com.squareup.retrofit2:retrofit", "2.6.2"),
)
_RX_DEP = re.compile(r"['\"]([\w.\-]+:[\w.\-]+):([\w.\-]+)['\"]")
_RX_TARGET_SDK = re.compile(r"targetSdk(?:Version)?\s*[\(=:\s]+(\d+)")


def analyze(target: Target) -> Iterable[Finding]:
    out: List[Finding] = []

    apk = target.meta.get("apk")
    if apk is not None:
        if not apk.signed:
            out.append(R_UNSIGNED.finding(file=target.name, note="no signature scheme detected"))
        else:
            if apk.debug_signed:
                out.append(R_DEBUG_SIGNED.finding(file=target.name))
            if apk.v1 is not None and apk.v2 is None and not apk.v3:
                out.append(R_V1_ONLY.finding(file=target.name, note=apk.signing_scheme))
            if apk.v1_verified is False:
                # name the exact entry that broke the chain as the matched
                # component, keep the verification reasons as "how detected"
                broken = next(
                    (re.split(r"\s*\(|\s+-\s",
                              r.split("mismatch: ", 1)[-1], maxsplit=1)[0].strip()
                     for r in apk.v1_reasons or [] if "mismatch: " in r),
                    "",
                )
                out.append(
                    R_V1_BROKEN.finding(
                        file=target.name,
                        symbol=broken or "META-INF PKCS#7 (.RSA/.SF) chain",
                        note="; ".join(apk.v1_reasons[:2]) or "chain invalid",
                    )
                )
            if apk.v2_verified is False:
                out.append(
                    R_V2_BROKEN.finding(
                        file=target.name,
                        note="; ".join(apk.v2_reasons[:2]) or "v2 verification failed",
                    )
                )
            if apk.v3_verified is False:
                out.append(
                    R_V3_BROKEN.finding(
                        file=target.name,
                        note="; ".join(apk.v3_reasons[:2]) or "v3 verification failed",
                    )
                )
            # Janus: ZIP layout anomalies are direct tampering evidence; a
            # plain v1-only bundle on targetSdk >= 24 is the exposed class
            _mf = target.manifest
            _tsdk = _mf.target_sdk if _mf is not None and _mf.target_sdk else 0
            if apk.zip_layout_anomalies:
                out.append(
                    R_JANUS.finding(
                        file=target.name,
                        note="; ".join(apk.zip_layout_anomalies[:2]),
                    )
                )
            elif (
                apk.v1 is not None and apk.v2 is None and not apk.v3
                and apk.dex_files and _tsdk >= 24
            ):
                out.append(
                    R_JANUS.finding(
                        file=target.name,
                        note=f"CVE-2017-13156: v1-only bundle with DEX, targetSdk={_tsdk}",
                    )
                )
            if apk.rollback_protected is False:
                out.append(
                    R_ROLLBACK.finding(
                        file=target.name,
                        note=f"{apk.signing_scheme} bundle without the banner in .SF",
                    )
                )
            # signing-certificate quality (fingerprint + validity + key size)
            import datetime as _dt

            now = _dt.datetime.now()
            for scheme, signer in apk.signers():
                ci = signer.cert_info
                if not ci:
                    continue
                try:
                    not_after = _dt.datetime.fromisoformat(ci["not_after"])
                except (ValueError, TypeError):
                    not_after = None
                if not_after is not None:
                    days_left = (not_after - now).days
                    if days_left <= 0:
                        out.append(
                            R_CERT_EXPIRED.finding(
                                file=target.name,
                                note=(
                                    f"{scheme} signing certificate expired "
                                    f"{abs(days_left)} day(s) ago "
                                    f"({not_after.date()}); subject="
                                    f"{ci.get('subject', '?')!r}"
                                ),
                            )
                        )
                    elif days_left <= 90:
                        out.append(
                            R_CERT_EXPIRED.finding(
                                file=target.name,
                                note=(
                                    f"{scheme} signing certificate expires in "
                                    f"{days_left} day(s) ({not_after.date()}); "
                                    f"subject={ci.get('subject', '?')!r}"
                                ),
                            )
                        )
                if (
                    ci.get("key_algorithm") == "rsa"
                    and isinstance(ci.get("key_bits"), int)
                    and ci["key_bits"] < 2048
                ):
                    out.append(
                        R_CERT_WEAK_KEY.finding(
                            file=target.name,
                            note=f"{scheme} RSA {ci['key_bits']}-bit signing key",
                        )
                    )
        for embedded in target.meta.get("embedded_apks", []):
            if not embedded.signed:
                out.append(
                    R_UNSIGNED_EMBEDDED.finding(file=str(embedded.name), note="unsigned nested apk")
                )

    # APK v4 (.idsig) sidecar consistency
    idsig = target.meta.get("idsig")
    if isinstance(idsig, dict):
        cert_fp = (idsig.get("cert_sha256") or "").lower()
        apk_fps = {
            (f or "").lower()
            for f in (getattr(target.meta.get("apk"), "signer_fingerprints", []) or [])
        }
        if idsig.get("tree_shape_ok") is False:
            out.append(
                R_IDSIG_MISMATCH.finding(
                    file=str(idsig.get("path", ".idsig")),
                    note="hash-tree size inconsistent with the APK size",
                )
            )
        if cert_fp and apk_fps and cert_fp not in apk_fps:
            out.append(
                R_IDSIG_MISMATCH.finding(
                    file=str(idsig.get("path", ".idsig")),
                    note=(
                        "sidecar cert "
                        f"{cert_fp[:16]}... does not match any APK signer "
                        + "/".join(sorted(f[:16] for f in apk_fps))
                    ),
                )
            )

    # embedded-SDK composition analysis (sdks.py, run from packaging._finish)
    from ..sdks import EOL_SDKS, vulnerable_version_check

    for hit in target.meta.get("sdks") or []:
        sdk_id = hit.get("id", "?")
        version = hit.get("version") or "?"
        reason = vulnerable_version_check(hit)
        if reason:
            shown = reason.replace("%s", version or "?") if "%s" in reason else reason
            out.append(
                R_SCA_VULNERABLE.finding(
                    file=target.name,
                    note=f"sdk {sdk_id} {version or '?'}: {shown}",
                )
            )
        eol = EOL_SDKS.get(sdk_id)
        if eol:
            out.append(
                R_SCA_EOL.finding(
                    file=target.name,
                    note=f"sdk {sdk_id}: {eol}",
                )
            )

    # OSV intelligence cache (prepared by masanalyzer-refresh-intel): report
    # advisory matches for detected SDK versions, best effort per cache.
    try:
        from ..osv import cache_from

        cache = cache_from(target.meta.get("osv_intel"))
        if cache is not None:
            for hit in target.meta.get("sdks") or []:
                for _coordinate, advisory in cache.matching(hit):
                    shown = str(advisory.get("summary") or "no summary")
                    out.append(
                        R_SCA_CVE.finding(
                            file=target.name,
                            note=(
                                f"sdk {hit.get('id', '?')} "
                                f"{hit.get('version') or '?'}: "
                                f"{advisory.get('id', '?')} - {shown[:180]}"
                            ),
                        )
                    )
    except Exception as exc:  # noqa: BLE001 - intel cache must not kill scans
        target.meta.setdefault("warnings", []).append(f"osv_intel: {exc}")

    # mach-O without code signature
    for img in target.meta.get("macho", []) or []:
        if not img.has_code_signature:
            out.append(
                R_NO_CODESIGN_MACHO.finding(
                    file=_macho_relpath(target, img), note="no LC_CODE_SIGNATURE"
                )
            )

    # dependency versions in build scripts
    for sf, lineno, text in code_lines(target, kinds=("resource",)):
        for dep, version in _deps(text):
            for name, patched in _KNOWN_PATCHED:
                if dep == name and version_lt(version, patched):
                    out.append(
                        R_DEPRECATED_LIB.finding(
                            file=sf.relpath,
                            line=lineno,
                            snippet=sf.line_at(lineno) or text,
                            note=f"{dep} {version} < {patched}",
                        )
                    )

    # targetSdk in gradle or in the source manifest
    for sf, lineno, text in code_lines(target, kinds=("resource",)):
        m = _RX_TARGET_SDK.search(text)
        if m and 0 < int(m.group(1)) < 29:
            out.append(
                R_DEPRECATED_TARGET_SDK.finding(
                    file=sf.relpath,
                    line=lineno,
                    snippet=sf.line_at(lineno) or text,
                    note=f"targetSdk={m.group(1)}",
                )
            )
    manifest = target.manifest
    if manifest is not None and manifest.target_sdk and manifest.target_sdk < 29:
        out.append(
            R_DEPRECATED_TARGET_SDK.finding(
                file=target.meta.get("manifest_path", "AndroidManifest.xml"),
                note=f"manifest targetSdk={manifest.target_sdk}",
            )
        )
    return out


def _deps(text: str) -> Iterable[Tuple[str, str]]:
    for m in _RX_DEP.finditer(text):
        yield m.group(1), m.group(2)


def _macho_relpath(target: Target, img) -> str:
    ipa = target.meta.get("ipa")
    if ipa is not None and getattr(ipa, "macho_paths", None):
        return ipa.macho_paths[0]
    return target.name

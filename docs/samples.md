# Sample fixtures (training only)

`samples/make_samples.py` deterministically rebuilds two deliberately
vulnerable fixtures used as end-to-end scanner benchmarks. **Nothing in the
trees executes** — the only compiled artifacts are synthetic DEX/ELF/Mach-O
bytes built by `masanalyzer.testing`; every "secret" is a placeholder and
every endpoint is a `.example` host. Regenerate anytime:

```bat
python -X utf8 samples\make_samples.py
```

## InsecureBank (Android)

```
samples/InsecureBank/
├── app/src/main/
│   ├── AndroidManifest.xml            debuggable · cleartext · targetSdk 28
│   │                                  5 exported components incl. an
│   │                                  unprotected CredentialsProvider
│   │                                  READ_SMS/CAMERA/… + SET_DEBUG_APP
│   └── java/com/example/insecurebank/
│       ├── LoginActivity.java         hardcoded admin password, AWS-style
│       │                              key, jdbc:// URL with creds, ECB
│       │                              AES, seeded java.util.Random, PIN
│       ├── TransferActivity.java      SQL concatenation (execSQL/rawQuery)
│       ├── TrustAllCerts.java         accept-all X509TrustManager and
│       │                              return-true HostnameVerifier
│       ├── SessionStore.java          MODE_WORLD_READABLE token prefs,
│       │                              password copied to external storage,
│       │                              deep-link controlled new File()
│       ├── CryptoHelper.java          MD5 digest, default "DES" cipher
│       └── PinActivity.java           email/token logged
├── res/xml/network_security_config.xml  cleartextTrafficPermitted + user CAs
├── res/values/strings.xml             http:// mirror endpoint
├── assets/config.properties           JDBC url with embedded creds
├── app/build/intermediates/classes.dex synthetic DEX (bank_dex)
├── app/src/main/jniLibs/
│   ├── arm64-v8a/libcrypto-hardened.so  ET_DYN (PIE) — hardened control
│   └── armeabi-v7a/liblegacy.so         ET_EXEC (non-PIE) → MAS-BIN-002
└── build/outputs/InsecureBank.apk     unsigned by design → MAS-SUP-001
```

Quirks kept deliberately: the unsigned APK lets M2 report MAS-SUP-001;
`liblegacy.so` carries `e_type=2` (fixed load address) so the no-PIE rule
fires while `libcrypto-hardened.so` stays clean (`e_type=3`).

## InsecureNotes (iOS)

```
samples/InsecureNotes/
├── Payload/InsecureNotes.app/
│   ├── Info.plist                     binary plist, ATS opt-out
│   │                                  (NSAllowsArbitraryLoads=true)
│   ├── Prefs.plist                    binary plist: username/password/
│   │                                  authToken → MAS-STO-005/MAS-CRED-008
│   ├── InsecureNotes                  arm64e Mach-O: PIE yes, no code
│   │                                  signature, symtab with
│   │                                  _debug_helper_doLogin /
│   │                                  _helper_keychainRemoveShared
│   └── embedded.mobileprovision       dev profile, get-task-allow=true
│                                      → MAS-BIN-008
├── Sources/
│   ├── Keychain.swift                 password/token into UserDefaults
│   ├── Crypto.swift                   kCCAlgorithmDES + kCCOptionECBMode
│   ├── Sync.swift                     URLSession over http:// cleartext URL
│   └── Export.swift                   document-dir dump from saved path
└── build/outputs/InsecureNotes.ipa    packaged container copy of the .app
```

Scanning the *tree* and the *IPA container* both work (the later exercises
zip unpacking + dedup, e.g. ATS appears once although the plist is present
inside `Payload/...` and the loose copy at the bundle root).

## Expected scan results (as of the 1.0.0 ruleset)

| Target | findings | grade | notable criticals |
| --- | --- | --- | --- |
| `samples/InsecureBank` | ~30 | C (≈77/100) | MAS-NET-006 (trust-all TLS), MAS-STO-001 (world-readable prefs) |
| `samples/InsecureNotes` | ~11 | A (≈93/100) | — (high only: DES/ECB, ATS) |

Reproduce:

```bat
python -X utf8 -m masanalyzer samples\InsecureBank  -o samples\out --format all
python -X utf8 -m masanalyzer samples\InsecureNotes -o samples\out --format all
```

Both scans run all ten OWASP analyzers with `analyzers_failed: []`.

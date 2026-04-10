# Drake-X APK Static Analysis

Drake-X includes a dedicated APK static-analysis agent for malware
analysis, reverse engineering support, threat research, and defensive
investigation. It orchestrates native Kali Linux tools, normalizes
findings into structured evidence, and produces a complete technical
report.

## Design Principles

The APK agent follows the same principles as the rest of Drake-X:

- **Evidence over assumptions.** Every conclusion is labeled as observed
  evidence, analytic assessment, or pending confirmation.
- **Local-first.** All analysis runs on the operator's host. No samples
  or results leave the machine.
- **Human-in-the-loop.** The agent produces findings. The analyst
  validates them.
- **Graceful degradation.** If a tool is missing, the agent skips it,
  logs a warning, and continues with reduced coverage.

## Prerequisites

Install on Kali Linux:

```bash
sudo apt install -y apktool jadx aapt unzip file yara radare2
```

None of these are hard requirements. Drake-X checks availability at
runtime and skips missing tools.

## Usage

```bash
# Basic analysis (uses apktool + jadx + strings by default)
drake apk analyze sample.apk -o ./output

# With a workspace
drake apk analyze sample.apk -w my-engagement

# Enable radare2 analysis
drake apk analyze sample.apk --radare2

# Skip jadx (faster, less Java-level coverage)
drake apk analyze sample.apk --no-jadx

# Deep mode (more time, more coverage)
drake apk analyze sample.apk --deep
```

## Analysis Phases

### Phase 1 — File intake and inventory
- Compute MD5 and SHA-256
- Identify file type
- Record file size, create work directory

### Phase 2 — Manifest and surface analysis
- Extract AndroidManifest.xml via aapt or apktool
- Enumerate permissions, activities, services, receivers, providers
- Flag suspicious permission combinations (REQUEST_INSTALL_PACKAGES,
  BIND_ACCESSIBILITY_SERVICE, READ_SMS, etc.)
- Identify exported components and intent filters

### Phase 3 — Code and asset extraction
- Decompile with apktool (smali + resources)
- Decompile with jadx (Java source)
- Extract raw APK contents with unzip
- Inventory native libraries, secondary DEX files, encrypted blobs
- Run strings on the APK and native libraries

### Phase 4 — Static behavior analysis
- Scan source/smali/strings for behavior patterns:
  - Dynamic code loading (DexClassLoader, reflection)
  - Dropper/installer patterns (PackageInstaller, session install)
  - Persistence (BOOT_COMPLETED, foreground services, alarms)
  - Exfiltration indicators (contacts, SMS, clipboard, accessibility)
  - External communication (URLs, Firebase/FCM, WebView, HTTP clients)
  - Social engineering (fake updates, credential phishing strings)
  - Trigger logic (preference flags, SIM/locale checks, time triggers)

### Phase 5 — Obfuscation and packing assessment
- Identifier renaming (short class/method names)
- String encryption or base64 encoding patterns
- High-entropy or encrypted assets
- Known packer signatures (Jiagu, Bangcle, Legu, etc.)
- Reflection abuse
- Native indirection (heavy JNI usage)

### Phase 6 — Protection detection
- Root detection
- Emulator detection
- Anti-debugging (Debug.isDebuggerConnected, ptrace, TracerPid)
- Frida detection
- Certificate pinning (CertificatePinner, network-security-config)
- Native protections (suspicious .so libraries, heavy native calls)

Each protection is classified as `observed`, `suspected`, or
`not_observed` with supporting evidence and analyst next steps.

### Phase 7 — Campaign similarity assessment
- Maps observed traits to generic mobile malware categories:
  dropper, banker-like, spyware-like, loader, fake update lure,
  FCM-abusing malware
- Uses conservative language: "consistent with", "shares traits with",
  "tentatively resembles", "insufficient evidence"
- Does not claim attribution to specific threat actors or families

### Phase 8 — Reporting
Produces:
- `apk_report.md` — full 11-section technical report
- `apk_executive.md` — executive summary
- `apk_analysis.json` — structured JSON findings

## Output structure

```
<output-dir>/
  raw/              # raw APK contents (unzip)
  apktool/          # apktool decompilation (smali + resources)
  jadx/             # jadx decompilation (Java source)
  apk_report.md     # technical report
  apk_executive.md  # executive summary
  apk_analysis.json # structured findings
```

## Report structure

1. Executive Summary
2. Methodology
3. Surface Analysis (hashes, permissions, components)
4. Static Analysis (behavior indicators, native libs, embedded files)
5. Campaign Objective Assessment
6. Obfuscation Analysis
7. Hidden Business Logic (communication, exfiltration, triggers)
8. Protection Detection and Dynamic-Analysis Considerations
9. Indicators and Extracted Artifacts (network IOCs, file inventory)
10. Conclusions
11. Analyst Next Steps

## Evidence classification

Every major conclusion in the report includes:

- **Observed Evidence** — what the tool or parser directly extracted
- **Analytic Assessment** — what the analysis engine concluded from
  evidence, always labeled with confidence
- **Pending Confirmation** — hypotheses that require further
  investigation (dynamic analysis, manual review, threat intel
  correlation)

The report never presents analytic assessment as observed evidence.
Campaign similarity uses conservative language and never claims
definitive attribution.

## Limitations

- This is static analysis only. Runtime behavior is not observed.
- Obfuscation can hide code paths from static analysis.
- Packed or encrypted payloads may not be fully extracted.
- Campaign similarity is based on trait matching, not signature
  matching or threat intelligence correlation.
- The agent does not perform dynamic exploitation or runtime bypass.

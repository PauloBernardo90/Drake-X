# Drake-X APK Static Analysis

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`usage.md`](usage.md), [`evidence-model.md`](evidence-model.md)

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

# With VirusTotal enrichment (requires API key in workspace config)
drake apk analyze sample.apk -w my-engagement --vt

# With Ghidra deeper analysis on native libraries
drake apk analyze sample.apk --ghidra

# Full pipeline: VT + Ghidra + radare2
drake apk analyze sample.apk -w my-engagement --vt --ghidra --radare2
```

### Ghidra integration (opt-in)

Ghidra provides deeper static analysis of native `.so` libraries that
jadx and apktool cannot decompile. Enable it with `--ghidra`.

**Prerequisites:**

```bash
# Install Ghidra on Kali
sudo apt install -y ghidra
# OR set the environment variable
export GHIDRA_INSTALL_DIR=/opt/ghidra
```

**What it does:**

- Runs `analyzeHeadless` on each `.so` in the APK's `lib/` directory
- Extracts function names, symbols, and string references
- Identifies suspicious symbols (decrypt, anti-debug, root check, etc.)
- Feeds results into the behavior and obfuscation analyzers
- Results are labeled as `ghidra_headless` source in the report

**When to use it:**

- When the APK contains native libraries with anti-analysis logic
- When jadx fails to decompile obfuscated code
- When embedded payloads need deeper inspection
- When you need better targets for Frida dynamic validation

**Graceful degradation:** If Ghidra is not installed, the `--ghidra`
flag produces a warning and the pipeline continues without it.

### VirusTotal enrichment (opt-in)

To enable VT hash lookup, add your API key to the workspace config:

```toml
# In <workspace>/workspace.toml
[virustotal]
api_key = "your-vt-api-key-here"
```

Then pass `--vt` when running analysis. VT enrichment:

- Performs a **read-only hash lookup** (GET by SHA-256). Never uploads.
- Is fully optional — the pipeline runs without it.
- Degrades gracefully on network errors, rate limits, or missing key.
- Is labeled as **external intel enrichment** in the report.

### Frida Dynamic Validation Targets

The analysis automatically generates Frida hook candidates when
protections or suspicious behaviors are detected. These are **not**
auto-bypass scripts — they are investigative starting points for an
analyst working in a controlled lab.

Each target includes:
- `target_class` / `target_method` — the Java/JNI symbol to hook
- `protection_type` — what protection or behavior it relates to
- `evidence_basis` — static evidence that led to this suggestion
- `expected_observation` — what the analyst should see
- `suggested_validation_objective` — what the hook confirms
- `analyst_notes` — practical guidance
- `priority` / `confidence`

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
3. VirusTotal Enrichment (opt-in, labeled as external intel)
4. Surface Analysis (hashes, permissions, components)
5. Static Analysis (behavior indicators, native libs, embedded files)
6. Campaign Objective Assessment
7. Obfuscation Analysis
8. Hidden Business Logic (communication, exfiltration, triggers)
9. Protection Detection and Dynamic-Analysis Considerations
10. Frida Dynamic Validation Targets (labeled as dynamic hypothesis)
11. Indicators and Extracted Artifacts (network IOCs, file inventory)
12. Conclusions and Recommendations
13. Analyst Next Steps

### PDF export

Drake-X does not include a built-in PDF renderer. The canonical report
formats are Markdown and JSON. To produce a PDF:

```bash
# Using pandoc (commonly available on Kali)
pandoc apk_report.md -o apk_report.pdf --pdf-engine=xelatex

# Using wkhtmltopdf via markdown conversion
grip apk_report.md --export apk_report.html && wkhtmltopdf apk_report.html apk_report.pdf
```

The Markdown structure is designed to render cleanly in PDF converters.

## Evidence classification

The report uses four explicit evidence categories:

| Category | Label in report | Source | Example |
|---|---|---|---|
| **Static fact** | (default in Sections 3–5) | Tool output or parser | "Permission READ_SMS declared" |
| **Analytic assessment** | Section 6 (campaign) | Inference from observed traits | "consistent with dropper" |
| **External intel enrichment** | VT section | VirusTotal API response | "42/72 detection ratio" |
| **Dynamic hypothesis** | Frida targets section | Static evidence → validation plan | "Hook File.exists() for su check" |

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

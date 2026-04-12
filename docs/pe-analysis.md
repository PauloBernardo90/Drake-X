# Drake-X PE Static Analysis

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`architecture.md`](architecture.md), [`kali-setup.md`](kali-setup.md)

Drake-X v0.8 includes a Windows PE static-analysis domain for malware
analysis and defensive investigation. It parses PE structure, assesses
protections, classifies import risk, detects structural anomalies, and
produces structured evidence and reports.

## Design Principles

The PE domain follows the same principles as the rest of Drake-X:

- **Evidence over assumptions.** Every conclusion is labeled as observed
  evidence or analytic assessment.
- **Local-first.** All analysis runs on the operator's host.
- **Graceful degradation.** If `pefile` or `capstone` is missing, the
  pipeline skips those stages with warnings and continues.
- **Bounded exploit-awareness.** PE analysis detects protection status
  and suspicious import patterns. It does not generate exploits, ROP
  chains, or bypass instructions.

## Prerequisites

```bash
pip install pefile capstone
```

Both are optional. Drake-X checks availability at runtime and skips
missing tools.

## Usage

```bash
# Basic PE analysis
drake pe analyze sample.exe

# With a workspace
drake pe analyze sample.exe -w my-engagement

# With VirusTotal enrichment
drake pe analyze sample.exe -w my-engagement --vt

# Deep mode
drake pe analyze sample.exe --deep
```

## Analysis Phases

### Phase 1 — File intake and identification
- Compute MD5 and SHA-256
- Identify file type via `file(1)`
- Detect binary format (PE, ELF, APK) via magic bytes
- Optional VirusTotal hash lookup

### Phase 2 — PE parsing
- Parse PE headers (machine, entry point, image base, timestamp,
  subsystem, DLL characteristics)
- Enumerate sections with entropy calculation
- Resolve imports (DLL + function + ordinal)
- Resolve exports
- Extract resource directory
- Detect structural anomalies:
  - Zero or future timestamps
  - Non-standard section names
  - High-entropy sections (>7.0, indicating packing/encryption)
  - Writable + executable sections
  - Entry point outside `.text`
  - Minimal import count
- Parse protection status:
  - ASLR (DYNAMIC_BASE)
  - DEP/NX (NX_COMPAT)
  - CFG (GUARD_CF)
  - SafeSEH
  - Stack cookies (GS)
  - High Entropy VA
  - Force Integrity

### Phase 3 — Normalization and risk assessment
- Classify imported functions by risk category:
  - Injection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
  - Execution (CreateProcess, ShellExecute, LoadLibrary)
  - Persistence (RegSetValueEx, CreateService, SetWindowsHookEx)
  - Evasion (IsDebuggerPresent, GetTickCount, NtQueryInformationProcess)
  - Credential access (CryptUnprotectData, SAMConnect)
  - Discovery (CreateToolhelp32Snapshot, EnumProcesses)
  - Communication (InternetOpen, URLDownloadToFile, WSAStartup)
- Assess section anomalies (packer signatures, entropy patterns)
- Generate structured findings with ATT&CK technique mappings

### Phase 4 — Bounded disassembly
- Disassemble the entry-point region (up to 200 instructions / 4 KB)
  using Capstone
- Output stored as structured JSON artifact (`entry_disasm.json`)
- Architecture-aware: x86 (32-bit) and x86-64 (64-bit)

**Important:** The v0.8 bounded disassembly operates on the entry-point
region, not on individual function boundaries. It captures the initial
execution path to support analyst triage. Function-scoped disassembly
is planned for v0.9.

### Phase 5 — Reporting
- Technical Markdown report (10 sections)
- Executive summary
- Structured JSON output

## Output structure

```
<output-dir>/
  pe_analysis.json      # structured analysis result
  pe_report.md          # technical report
  pe_executive.md       # executive summary
  entry_disasm.json     # bounded disassembly (if Capstone available)
```

## Report structure

1. Executive Summary
2. Methodology
3. Surface Analysis (hashes, file type)
4. PE Metadata (headers, entry point, timestamp)
5. Section Analysis (entropy, characteristics)
6. Import Risk Assessment (API classification with ATT&CK)
7. Protection Analysis (ASLR, DEP, CFG, SafeSEH, GS)
8. Structural Anomalies
9. Behavioral Signals (injection chain, communication, evasion)
10. Validation Recommendations

## Evidence classification

| Category | Label | Source |
|----------|-------|--------|
| **Static fact** | Sections 3-7 | Parser output |
| **Observed anomaly** | Section 8 | Structural indicators |
| **Analytic assessment** | Section 9 | Behavioral inference from imports |
| **Analyst recommendation** | Section 10 | Validation suggestions |

## Evidence model integration

In v0.8, PE analysis integrates into the Drake-X evidence model via:

- **Findings:** Structured `Finding` objects produced by
  `pe_normalize.py` — injection risk, protection absence, packing
  indicators, structural anomalies. Each finding carries severity,
  confidence, evidence references, and ATT&CK mappings.
- **JSON output:** Full `PeAnalysisResult` serialized to
  `pe_analysis.json` for downstream tooling.
- **Report output:** Markdown and executive reports with evidence labels.

**Note:** Direct evidence graph extensions (PE-specific node types such
as `pe_file`, `pe_section`, `pe_import`) are planned for v0.9. In v0.8,
PE evidence enters the platform model through the shared Finding
interface and structured JSON outputs.

## Current limitations (v0.8)

- Bounded disassembly covers the entry-point region only, not individual
  functions.
- No evidence graph node types specific to PE (planned for v0.9).
- No exploit-primitive detection (planned for v0.9).
- No shellcode carving or classification (planned for v0.9).
- No cross-sample PE correlation (planned for v1.0).
- No debugger integration.
- `jadx` and `apktool` are not applicable to PE files.

## Bounded exploit-awareness

Per the Drake-X v1.0 doctrine (ADR-0005), PE analysis supports bounded
exploit-awareness:

- **Allowed:** Detecting import patterns associated with injection,
  parsing protection status, identifying structural anomalies, assessing
  section characteristics.
- **Not allowed:** Generating exploit chains, reconstructing ROP chains,
  producing shellcode, providing bypass instructions.

All findings use conservative language: "consistent with", "suggests",
"may indicate". Nothing is claimed as confirmed exploitation without
dynamic validation.

# Drake-X PE Static Analysis

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`architecture.md`](architecture.md), [`kali-setup.md`](kali-setup.md)

Drake-X v0.9 includes a Windows PE static-analysis domain for malware
analysis and defensive investigation. It parses PE structure, assesses
protections, classifies import risk, detects structural anomalies,
identifies exploit-related indicators, performs suspected shellcode
carving, assesses protection-interaction, and produces structured
evidence and reports.

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

# AI-assisted exploit assessment (requires local Ollama runtime)
drake pe analyze sample.exe --ai-exploit-assessment \
  --ollama-url http://127.0.0.1:11434 --ollama-model llama3.1:8b

# Emit candidate YARA + STIX bundle for analyst review
drake pe analyze sample.exe --detection-output

# Full v0.9 end-to-end run
drake pe analyze sample.exe \
  --ai-exploit-assessment \
  --detection-output \
  -w my-engagement
```

## v0.9 Outputs

A v0.9 PE run produces, in the work directory:

| File | Purpose |
|------|---------|
| `pe_analysis.json` | Full Pydantic-serialized `PeAnalysisResult` (includes `graph_snapshot` and `ai_exploit_assessment` when set) |
| `pe_graph.json` | Evidence Graph nodes and edges for this sample |
| `pe_report.md` | Technical Markdown report (adds the AI-assisted section when present) |
| `pe_executive.md` | One-page executive summary |
| `entry_disasm.json` | Bounded entry-point disassembly |
| `ai_audit/exploit_assessment.jsonl` | Append-only AI audit log (only with `--ai-exploit-assessment`) |
| `pe_candidates.yar` | Candidate YARA rules (only with `--detection-output`, only if signals justify) |
| `pe_stix.json` | STIX 2.1 bundle with `candidate` labels (only with `--detection-output`) |

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

**Important:** Bounded disassembly operates on the entry-point region,
not on individual function boundaries. It captures the initial
execution path to support analyst triage. Function-scoped disassembly
is planned for v1.0 and will be driven by the Ghidra-structured export
pipeline rather than an expanded Capstone path.

### Phase 5 — Reporting
- Technical Markdown report; sections expand dynamically with
  evidence (executive summary, methodology, surface, PE metadata,
  sections, imports, protections, structural anomalies, behavioral
  signals, exploit-capability assessment, suspected shellcode,
  protection-interaction, AI-assisted assessment when present,
  and validation recommendations).
- Executive summary.
- Structured JSON output (`pe_analysis.json`, includes embedded
  evidence-graph snapshot).
- Evidence Graph (`pe_graph.json`).
- Optional AI audit log (`ai_audit/exploit_assessment.jsonl`) and
  candidate detection outputs (`pe_candidates.yar`, `pe_stix.json`)
  when the relevant CLI flags are set.

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

v0.9 makes the Evidence Graph the canonical output of PE analysis:

- **Evidence Graph:** `drake_x/graph/pe_writer.py` ingests every PE
  analysis into a graph whose node IDs are deterministic (derived from
  the sample SHA-256). Artifact, section, import, protection,
  indicator, shellcode, and protection-interaction nodes are linked
  via `derived_from` and `supports` edges. Persisted as
  `pe_graph.json`.
- **Findings:** Structured `Finding` objects produced by
  `pe_normalize.py` — injection risk, protection absence, packing
  indicators, structural anomalies. Each finding carries severity,
  confidence, evidence references, and ATT&CK mappings.
- **JSON output:** Full `PeAnalysisResult` serialized to
  `pe_analysis.json` for downstream tooling. Includes an embedded
  graph snapshot for self-contained consumption.
- **Report output:** Markdown and executive reports with evidence
  labels and, when `--ai-exploit-assessment` is used, an AI-assisted
  capability assessment section that references the audit log.

## v0.9 Exploit-Awareness

v0.9 adds bounded exploit-awareness on top of v0.8 native foundations:

- **Exploit-related indicator detection:** injection chains, stack
  corruption, control-flow hijack, shellcode setup, heap manipulation
- **Suspected shellcode carving:** heuristic and pattern-based detection
  of shellcode-like blobs in sections, resources, and overlay
- **Bounded decoding:** XOR and base64 decode for classification triage
- **Protection-interaction assessment:** analytical assessment of how
  observed capability interacts with DEP, ASLR, CFG, SafeSEH
- **ATT&CK mapping:** conservative technique association for findings
- **AI exploit-aware assessment:** evidence-cited, uncertainty-bounded

See [`exploit-awareness.md`](exploit-awareness.md) for full details.

## Current limitations (v0.9)

- Bounded disassembly covers the entry-point region only, not individual
  functions.
- No evidence graph node types specific to PE (planned for v1.0).
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

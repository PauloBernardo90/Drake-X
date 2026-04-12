# Drake Unleashed

Structured onboarding and operating guide for Drake-X.

See also: [`cheat-sheet.md`](cheat-sheet.md), [`usage.md`](usage.md),
[`apk-analysis.md`](apk-analysis.md), [`pe-analysis.md`](pe-analysis.md)

## 1. What Drake-X Is

Drake-X is an evidence-driven malware analysis and threat investigation
platform. It turns raw artifacts such as APK, PE, and ELF into
structured, reproducible evidence for analyst review.

Drake-X supports bounded exploit-awareness. It may detect and
contextualize exploit-related capability in malware samples. It does not
generate exploit chains, optimize payloads, provide bypass guidance, or
replace external debugging tools.

## 2. Getting Started

Basic setup on Kali:

```bash
git clone https://github.com/PauloBernardo90/Drake-X.git
cd Drake-X
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify the environment:

```bash
drake --help
drake tools
drake ai status -w my-engagement
```

For deeper native and malware workflows, optional tooling includes:

- `ghidra`
- `adb`
- `frida`
- `pefile`
- `capstone`

## 3. Core Concepts

### Workspace

A workspace lives under:

```text
~/.drake-x/workspaces/<name>/
```

It contains:

- `workspace.toml`
- `scope.yaml`
- `drake.db`
- `runs/`
- `audit.log`

### Session

A session is one analysis or collection run stored inside the workspace.
Reports, graph views, findings, and AI tasks operate on sessions.

### Evidence

Drake-X separates:

- observed fact
- analytic assessment
- external enrichment
- analyst-assisted hypothesis

### Reports

The platform produces technical Markdown, executive Markdown, JSON, and
other export-oriented report artifacts from stored session evidence.

## 4. Working Modes

Drake-X supports two operating styles:

### One-shot CLI

Use direct commands when you know the exact action:

```bash
drake apk analyze ./sample.apk -w my-engagement --vt --ghidra
drake pe analyze ./sample.exe -w my-engagement --vt
```

### Persistent Console

Use the console when investigating multiple samples and sessions in the
same workspace:

```bash
drake console
```

The console keeps active workspace and session context and avoids
repeating `-w` and `session_id` on every command.

## 5. Persistent Console

Start:

```bash
drake console
```

Typical prompt:

```text
drake(my-engagement)>
drake(my-engagement:376431952b79)>
```

Core commands:

```text
workspace list
workspace use <workspace>
workspace new <workspace>
workspace show
session list
session use <session-id>
session show
status
tools
exit
```

The console renders the banner once and then dispatches to the existing
CLI surface with context injection.

## 6. Workspace Operations

Create and inspect a workspace:

```bash
drake init my-engagement
drake status -w my-engagement
drake scope validate -w my-engagement
drake scope show -w my-engagement
```

The workspace config can hold local AI and VirusTotal settings:

```toml
[ai]
ollama_url = "http://127.0.0.1:11434"
ollama_model = "llama3.2:1b"

[virustotal]
api_key = "YOUR_VT_API_KEY"
```

## 7. Session-Centric Workflow

Typical cycle:

1. analyze a sample
2. list sessions
3. select the session
4. inspect findings and graph
5. generate technical or executive reports
6. run AI tasks against stored evidence

Core commands:

```bash
drake report list -w my-engagement
drake findings list -w my-engagement
drake graph show <session-id> -w my-engagement --format summary
drake report generate <session-id> -f md -w my-engagement
drake ai summarize <session-id> -w my-engagement
```

## 8. APK Analysis Workflow

Primary Android malware workflow:

```bash
drake apk analyze ./sample.apk -w my-engagement --vt --ghidra
```

What it covers:

- manifest parsing
- permission review
- behavior detection
- protection detection
- campaign similarity assessment
- VT enrichment
- Frida validation targets
- optional Ghidra deeper analysis

Follow-up workflow:

```bash
drake report list -w my-engagement
drake ai summarize <session-id> -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
```

## 9. PE Analysis Workflow

Primary Windows PE malware workflow:

```bash
drake pe analyze ./sample.exe -w my-engagement --vt
```

Optional v0.9 workflows:

```bash
# AI-assisted exploit-aware assessment (local Ollama only)
drake pe analyze ./sample.exe -w my-engagement --ai-exploit-assessment

# Candidate detection artifacts for analyst review
drake pe analyze ./sample.exe -w my-engagement --detection-output

# Full v0.9 path
drake pe analyze ./sample.exe -w my-engagement --vt \
  --ai-exploit-assessment --detection-output
```

What v0.9 covers:

- PE header parsing
- sections, imports, exports, resources
- section anomalies
- protection status
- import-risk classification
- ATT&CK-linked findings
- exploit-related indicator detection
- suspected shellcode carving and bounded decoding for triage
- protection-interaction assessment
- technical and executive report output
- Evidence Graph output as `pe_graph.json`
- optional AI-assisted exploit-aware assessment with append-only audit log
- optional candidate YARA and STIX outputs for analyst review

Optional prerequisites:

```bash
pip install pefile capstone
```

Current bounded disassembly behavior:

- limited to the entry-point region
- stored as `entry_disasm.json`
- off-graph by default

Key PE output artifacts:

- `pe_analysis.json` — structured analysis result
- `pe_graph.json` — canonical Evidence Graph output for the sample
- `pe_report.md` — technical report
- `pe_executive.md` — executive summary
- `entry_disasm.json` — bounded entry-point disassembly
- `ai_audit/exploit_assessment.jsonl` — present only with `--ai-exploit-assessment`
- `pe_candidates.yar` — present only with `--detection-output` when signals justify it
- `pe_stix.json` — present only with `--detection-output`

## 10. Evidence and Graph

Use the graph to inspect relationships between findings, artifacts,
indicators, and assessments:

```bash
drake graph show <session-id> -w my-engagement --format summary
drake graph show <session-id> -w my-engagement --findings
drake graph show <session-id> -w my-engagement --format json
```

Use the graph for reasoning-relevant evidence. Deep low-level data such
as bounded disassembly remains in structured artifacts rather than the
canonical graph by default.

## 11. Reports

Drake-X supports:

- technical Markdown
- executive Markdown
- JSON
- manifest/evidence-oriented output
- session diff

Examples:

```bash
drake report generate <session-id> -f md -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
drake report generate <session-id> -f json -w my-engagement
drake report diff <session-a> <session-b> -w my-engagement
```

## 12. AI Assistance

The AI layer is local-first and uses Ollama on the same host. AI reasons
over stored evidence; it does not replace deterministic detection or run
tools itself.

Core tasks:

```bash
drake ai status -w my-engagement
drake ai summarize <session-id> -w my-engagement
drake ai classify <session-id> -w my-engagement
drake ai next-steps <session-id> -w my-engagement
drake ai draft-report <session-id> -w my-engagement
```

## 13. Investigation Playbooks

### Android triage

```bash
drake apk analyze ./sample.apk -w my-engagement --vt --ghidra
drake report list -w my-engagement
drake ai summarize <session-id> -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
```

### Windows PE triage

```bash
drake pe analyze ./sample.exe -w my-engagement --vt
drake report list -w my-engagement
drake findings list -w my-engagement
drake report generate <session-id> -f md -w my-engagement
```

### Graph-first review

```bash
drake graph show <session-id> -w my-engagement --format summary
drake graph show <session-id> -w my-engagement --findings
drake ai observations <session-id> -w my-engagement
```

## 14. Tooling Matrix

- `apktool` — APK unpacking and resource extraction
- `jadx` — APK decompilation
- `ghidra` — deeper native and binary analysis
- `adb` — analyst-controlled Android device interaction
- `frida` — analyst-assisted dynamic validation
- `pefile` — PE parsing
- `capstone` — bounded disassembly
- `yara` — rule-based pattern matching

All optional tooling must degrade gracefully when unavailable.

## 15. Current Status and Next Phase

Current status:

- v0.8 native foundations are in place
- PE analysis is a first-class v0.9 workflow
- bounded exploit-awareness is implemented for PE analysis
- PE analysis writes the Evidence Graph as a canonical output
- optional AI-assisted exploit-aware assessment is available with audit logging
- optional candidate YARA and STIX outputs are available for analyst review
- persistent console is available

Next phase:

- v1.0 cross-sample correlation
- richer graph query surfaces
- dynamic evidence-ingestion adapters
- broader multi-domain reporting and validation planning

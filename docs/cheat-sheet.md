# Drake-X Cheat Sheet

See also: [`drake-unleashed.md`](drake-unleashed.md),
[`usage.md`](usage.md), [`apk-analysis.md`](apk-analysis.md),
[`pe-analysis.md`](pe-analysis.md), [`kali-setup.md`](kali-setup.md)

Fast reference for the current Drake-X CLI. Use
[`drake-unleashed.md`](drake-unleashed.md) for the structured workflow
guide.

## 1. Fast Start

```bash
drake --help
drake tools
drake init <workspace>
drake ai status -w <workspace>
```

## 2. Persistent Console

```bash
drake console
```

Inside the console:

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

## 3. Workspace and Scope

```bash
drake init <workspace>
drake init <workspace> --operator <operator>
drake init <workspace> --here
drake status -w <workspace>
drake scope validate -w <workspace>
drake scope show -w <workspace>
drake scope check <target> -w <workspace>
```

Common paths:

```text
~/.drake-x/workspaces/<workspace>/
  workspace.toml
  scope.yaml
  drake.db
  runs/
  audit.log
```

## 4. APK Fast Path

```bash
drake apk analyze ./sample.apk -w <workspace>
drake apk analyze ./sample.apk -w <workspace> --vt
drake apk analyze ./sample.apk -w <workspace> --ghidra
drake apk analyze ./sample.apk -w <workspace> --vt --ghidra
drake apk analyze ./sample.apk -w <workspace> --deep
```

VirusTotal configuration:

```toml
[virustotal]
api_key = "YOUR_VT_API_KEY"
```

Environment fallback:

```bash
export VT_API_KEY="your_vt_api_key"
```

Resolution order:
1. `[virustotal].api_key` in `workspace.toml`
2. `VT_API_KEY` environment variable

## 5. PE Fast Path

```bash
drake pe analyze ./sample.exe -w <workspace>
drake pe analyze ./sample.dll -w <workspace> --vt
drake pe analyze ./sample.exe -w <workspace> --deep
```

Optional prerequisites:

```bash
pip install pefile capstone
```

Primary outputs:

```text
pe_analysis.json       # Full analysis result (JSON)
pe_report.md           # Technical report with exploit-awareness sections (v0.9)
pe_executive.md        # Executive summary
entry_disasm.json      # Bounded disassembly artifact
```

v0.9 report includes (when detected):

- Exploit-related capability assessment
- Suspected shellcode artifacts
- Protection-interaction assessment

## 6. Sessions and Reports

```bash
drake report list -w <workspace>
drake findings list -w <workspace>
drake findings show <finding-id> -w <workspace>
drake graph show <session-id> -w <workspace> --format summary
drake report generate <session-id> -f md -w <workspace>
drake report generate <session-id> -f executive -w <workspace>
drake report generate <session-id> -f json -w <workspace>
drake report diff <session-a> <session-b> -w <workspace>
```

## 7. AI Tasks

```bash
drake ai status -w <workspace>
drake ai summarize <session-id> -w <workspace>
drake ai classify <session-id> -w <workspace>
drake ai next-steps <session-id> -w <workspace>
drake ai observations <session-id> -w <workspace>
drake ai draft-report <session-id> -w <workspace>
drake ai dedupe <session-id> -w <workspace>
drake ai dedupe <session-id> -w <workspace> --apply
```

## 8. Supporting Collection

Supporting evidence-gathering remains available, but is not the primary
product workflow.

```bash
drake recon list-modules
drake recon plan <target> -m recon_passive -w <workspace>
drake recon run <target> -m recon_passive -w <workspace>
drake web inspect <url-or-domain> -w <workspace>
drake api ingest ./openapi.json -w <workspace>
```

## 9. Common Investigation Sequences

APK triage:

```bash
drake apk analyze ./sample.apk -w <workspace> --vt --ghidra
drake report list -w <workspace>
drake ai summarize <session-id> -w <workspace>
drake report generate <session-id> -f executive -w <workspace>
```

PE triage:

```bash
drake pe analyze ./sample.exe -w <workspace> --vt
drake report list -w <workspace>
drake graph show <session-id> -w <workspace> --format summary
drake report generate <session-id> -f md -w <workspace>
```

# Drake-X Cheat Sheet

See also: [`README.md`](README.md), [`usage.md`](usage.md),
[`kali-setup.md`](kali-setup.md), [`llm-setup.md`](llm-setup.md)

Fast reference for the current Drake-X CLI.

## Basic Help

```bash
drake --help
drake status -w <workspace>
drake tools
drake tools -w <workspace>
drake flow
```

## Workspace

Create a workspace under `~/.drake-x/workspaces/`:

```bash
drake init <name>
drake init <name> --operator <operator>
drake init <name> --force
```

Create a workspace under the current directory:

```bash
drake init <name> --here
```

Quick status view:

```bash
drake status -w <workspace>
```

## Scope

```bash
drake scope validate -w <workspace>
drake scope show -w <workspace>
drake scope show -w <workspace> --json
drake scope check <target> -w <workspace>
```

## Recon

List modules:

```bash
drake recon list-modules
```

Plan a run:

```bash
drake recon plan <target> -m recon_passive -w <workspace>
drake recon plan <target> -m recon_active -w <workspace>
```

Run a module:

```bash
drake recon run <target> -m recon_passive -w <workspace>
drake recon run <target> -m recon_active -w <workspace>
drake recon run <target> -m recon_active -w <workspace> --yes
drake recon run <target> -m recon_active -w <workspace> --dry-run
drake recon run <target> -m recon_passive -w <workspace> --ai
drake recon run <target> -m recon_passive -w <workspace> --timeout 120
```

Common modules:

```text
recon_passive
recon_active
web_inspect
tls_inspect
headers_audit
content_discovery
api_inventory
```

## Web

Shortcut for `web_inspect`:

```bash
drake web inspect <url-or-domain> -w <workspace>
drake web inspect <url-or-domain> -w <workspace> --yes
drake web inspect <url-or-domain> -w <workspace> --dry-run
drake web inspect <url-or-domain> -w <workspace> --ai
```

## API

Ingest an OpenAPI or Swagger file:

```bash
drake api ingest ./openapi.json -w <workspace>
drake api ingest ./openapi.yaml -w <workspace> --target https://api.example.com
```

## APK

Static analysis:

```bash
drake apk analyze ./sample.apk
drake apk analyze ./sample.apk -w <workspace>
drake apk analyze ./sample.apk -o ./apk-output
drake apk analyze ./sample.apk -w <workspace> --vt
drake apk analyze ./sample.apk -w <workspace> --ghidra
drake apk analyze ./sample.apk -w <workspace> --vt --ghidra
drake apk analyze ./sample.apk --radare2
drake apk analyze ./sample.apk --no-jadx
drake apk analyze ./sample.apk --deep
drake apk analyze ./sample.apk -w <workspace> --vt --ghidra --radare2 --deep
```

VirusTotal enrichment:

```toml
[virustotal]
api_key = "YOUR_VT_API_KEY"
```

Store the VirusTotal API key in the workspace config at
`~/.drake-x/workspaces/<workspace>/workspace.toml`.
Do not hardcode secrets in the repository or source files.

Environment fallback:

```bash
export VT_API_KEY="your_vt_api_key"
drake apk analyze ./sample.apk -w <workspace> --vt
```

Resolution order:
1. `[virustotal].api_key` in `workspace.toml`
2. `VT_API_KEY` environment variable

## Findings

```bash
drake findings list -w <workspace>
drake findings list -w <workspace> --severity medium
drake findings list -w <workspace> --source parser
drake findings show <finding-id> -w <workspace>
```

## Evidence Graph

Show graph:

```bash
drake graph show <session-id> -w <workspace>
```

Useful filters:

```bash
drake graph show <session-id> -w <workspace> --format ascii
drake graph show <session-id> -w <workspace> --format json
drake graph show <session-id> -w <workspace> --format summary
drake graph show <session-id> -w <workspace> --node <node-id>
drake graph show <session-id> -w <workspace> --kind finding
drake graph show <session-id> -w <workspace> --edge supports
drake graph show <session-id> -w <workspace> --findings
drake graph show <session-id> -w <workspace> --indicators
drake graph show <session-id> -w <workspace> --artifacts
drake graph show <session-id> -w <workspace> -o ./graph.txt
```

## AI

Check Ollama connectivity:

```bash
drake ai status -w <workspace>
```

Run tasks against a stored session:

```bash
drake ai summarize <session-id> -w <workspace>
drake ai classify <session-id> -w <workspace>
drake ai next-steps <session-id> -w <workspace>
drake ai observations <session-id> -w <workspace>
drake ai draft-report <session-id> -w <workspace>
drake ai dedupe <session-id> -w <workspace>
drake ai dedupe <session-id> -w <workspace> --apply
```

## Reports

List sessions available for reporting:

```bash
drake report list -w <workspace>
```

Generate reports:

```bash
drake report generate <session-id> -f md -w <workspace>
drake report generate <session-id> -f executive -w <workspace>
drake report generate <session-id> -f json -w <workspace>
drake report generate <session-id> -f manifest -w <workspace>
drake report generate <session-id> -f evidence -w <workspace>
drake report generate <session-id> -f md -w <workspace> -o ./report.md
```

Compare sessions:

```bash
drake report diff <session-a> <session-b> -w <workspace>
```

## Missions

Built-in multi-step workflows:

```bash
drake mission list -w <workspace>
drake mission show <mission> -w <workspace>
drake mission run recon <target> -w <workspace>
drake mission run web <target> -w <workspace>
drake mission run full <target> -w <workspace>
drake mission run apk ./sample.apk -w <workspace>
```

Useful options:

```bash
drake mission run web <target> -w <workspace> --yes
drake mission run web <target> -w <workspace> --dry-run
drake mission run web <target> -w <workspace> --no-active
drake mission run web <target> -w <workspace> --ai
drake mission run web <target> -w <workspace> --no-report
drake mission run apk ./sample.apk -w <workspace> -o ./mission-output
```

## Assist

AI-guided operator mode:

```bash
drake assist start web <target> -w <workspace>
drake assist start recon <target> -w <workspace>
drake assist start apk <target> -w <workspace>
drake assist start web <target> -w <workspace> --max-steps 10
```

Audit trail:

```bash
drake assist history <assist-session-id> -w <workspace>
drake assist export <assist-session-id> -w <workspace>
```

## Common Setup Flow

```bash
drake init my-engagement
mousepad ~/.drake-x/workspaces/my-engagement/scope.yaml &
drake scope validate -w my-engagement
drake scope check example.com -w my-engagement
drake recon run example.com -m recon_passive -w my-engagement
drake ai status -w my-engagement
drake report generate <session-id> -f md -w my-engagement
```

## Ollama Workspace Config

Example `workspace.toml` section:

```toml
[ai]
ollama_url = "http://127.0.0.1:11434"
ollama_model = "llama3.2:1b"
```

## Notes

- Prefer `-w <workspace>` consistently.
- Active modules require valid scope and may require confirmation.
- `drake ai ...` works on stored session IDs, not arbitrary targets.
- `drake report generate` writes under the workspace run directory unless `-o` is used.

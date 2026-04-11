# Drake-X Operator Control (v0.7)

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`architecture.md`](architecture.md), [`ux-layer.md`](ux-layer.md)

Drake-X v0.7 uses operator control to keep evidence collection,
malware-analysis triage, and reporting transparent and reviewable. The
goal is not just awareness, but disciplined analyst control over what is
observed, enriched, hypothesized, and reported.

## `drake status` — Workspace Observability

A single read-only command that summarizes the current workspace state.

```bash
drake status -w my-engagement
```

### Output sections

1. **Workspace** — name, path, creation date, operator
2. **Scope** — engagement name, in/out-of-scope rule counts, active
   policy, rate limits
3. **Sessions** — total count, last session ID and timestamp, profile
   breakdown
4. **Findings** — total count, severity breakdown (critical/high/medium
   /low/info), deduplicated count
5. **Evidence Graph** — node/edge counts, top 3 most-connected nodes
6. **Tools** — availability check for key Kali tools across collection,
   malware analysis, dynamic observation, enrichment, and reporting

The command never mutates state. It degrades gracefully when data is
missing (no sessions, no graph, no scope file).

### Sample output

```
Workspace
  name:       my-engagement
  path:       /home/operator/.drake-x/workspaces/my-engagement
  created:    2026-04-10T00:00:00+00:00

Scope
  engagement: acme-bug-bounty
  in-scope:   3 rule(s)
  out-scope:  1 rule(s)
  active:     denied
  rate limit: 5.0 rps / 4 concurrent

Sessions
  total:      7
  last ID:    abc123def456
  last run:   2026-04-10T14:30:00+00:00
  by profile: recon_passive=3, apk_analyze=2, safe=2, web-basic=2

Findings
  total:      23
  high           4
  medium         8
  low            6
  info           5
  deduplicated: 2

Evidence Graph
  session:    abc123def456
  nodes:      42
  edges:      67
  top nodes:
    web:target:example.com (example.com) — 15 edge(s)
    web:finding:f-abc123 (Missing HSTS) — 8 edge(s)

Tools
  available:  nmap, dig, whois, curl, strings, unzip, apktool, ghidra
  missing:    httpx, jadx, yara, frida, pandoc
```

## Audit-Logged Assist Sessions

Every Assist Mode interaction is now fully persisted.

### Storage schema

```sql
assist_sessions (id, workspace, domain, target, started_at, ended_at)
assist_events (assist_session_id, timestamp, step_number,
               suggestion_json, operator_action, executed_command,
               result_status)
```

### Event lifecycle

Each assist step logs:
1. AI suggestion (or error if AI unavailable)
2. Operator decision: `approve`, `reject`, `exit`, `ai_failed`
3. Executed command (if approved)
4. Result status: `success`, `failed`, `skipped`, `manual`

### Review commands

```bash
# Show chronological steps
drake assist history <assist-session-id> -w my-engagement

# Export full trace as JSON
drake assist export <assist-session-id> -w my-engagement
```

### Design properties

- Sessions are created atomically at the start of `drake assist start`.
- Events are logged per-step, so interrupted sessions retain their
  partial trace.
- Suggestion JSON is stored verbatim for reproducibility.
- No secrets or scope file data is logged in events.

## Custom Mission Templates

Operators can define their own mission workflows as TOML files.

### File location

```
<workspace>/missions/<name>.toml
```

### Template format

```toml
name = "deep-web-audit"

[[steps]]
label = "Passive Recon"
module = "recon_passive"

[[steps]]
label = "Active Recon"
module = "recon_active"
skippable = true

[[steps]]
label = "Headers"
module = "headers_audit"

[[steps]]
label = "Content Discovery"
module = "content_discovery"
skippable = true
```

### Usage

```bash
# List available missions (built-in + workspace templates)
drake mission list -w my-engagement

# Show steps of a mission
drake mission show deep-web-audit -w my-engagement

# Execute a custom mission
drake mission run deep-web-audit example.com -w my-engagement --yes

# Dry-run a custom mission
drake mission run deep-web-audit example.com -w my-engagement --dry-run
```

### Behavior

- Templates are validated before execution (invalid modules rejected).
- Scope enforcement applies to every step.
- `--no-active` skips steps marked `skippable = true`.
- `--dry-run` plans without executing.
- `--yes` pre-approves confirmation gates.
- Built-in missions (`web`, `recon`, `full`, `apk`) take precedence
  over templates with the same name.

## Design Principles

- **Observability, not automation.** `drake status` shows state; it
  does not change it.
- **Auditability.** Every assist interaction is logged with timestamps,
  suggestions, decisions, and outcomes.
- **Operator control.** Custom missions are defined by the operator,
  validated before execution, and subject to all existing safety
  controls.
- **Evidence classification awareness.** Operator-facing features should
  help the analyst distinguish fact, inference, external enrichment, and
  dynamic hypothesis rather than collapsing them into one narrative.
- **Non-destructive.** All three features are additive. No existing
  commands, schemas, or behaviors are modified.

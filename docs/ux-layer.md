# Drake-X UX Layer

Drake-X v0.5.1 introduces a usability layer that simplifies operator
interaction without removing control, hiding steps, or weakening the
safety model. Every UX command delegates to existing modules, engines,
and scope enforcement — it adds guidance, not automation.

## Design Principles

- **Simplify, not obscure.** UX commands print what they are doing,
  why, and what comes next. Nothing is hidden.
- **Human-in-the-loop.** Every active or intrusive step requires
  confirmation. The operator can exit at any time.
- **Evidence-driven.** Assist Mode ties every suggestion to workspace
  evidence. It does not invent actions.
- **No new logic.** Mission, Assist, and Flow call the same engine,
  modules, and scope enforcer that individual commands use.

## Mission CLI

High-level guided workflows that chain existing modules.

```bash
drake mission run web example.com -w my-engagement
drake mission run recon example.com -w my-engagement --yes
drake mission run apk sample.apk -w my-engagement
drake mission run full example.com -w my-engagement --no-active --dry-run
```

### Mission types

| Type | Steps |
|------|-------|
| `recon` | passive recon → active recon |
| `web` | passive → active → web inspect → headers audit |
| `full` | passive → active → web → headers → content discovery |
| `apk` | delegates to `drake apk analyze` |

### Behavior

- Each step prints its number, label, and result.
- Active/intrusive steps are skippable via `--no-active`.
- `--dry-run` plans every step without executing.
- `--yes` pre-approves confirmation gates.
- Scope enforcement applies to every step.
- Failed non-skippable steps halt the mission.
- Reports are generated at the end.

### UX output

```
  Drake-X Mission: WEB
  Target: example.com
  Steps:  4

[1/4] Passive Recon (recon_passive)
✓     completed — tools: dig, whois, curl
[2/4] Active Recon (recon_active) — skipped (--no-active)
[3/4] Web Inspection (web_inspect) — skipped (--no-active)
[4/4] Header Analysis (headers_audit)
✓     completed — tools: curl

✓ Mission complete. 2 session(s) recorded.
```

## Assist Mode

AI-guided operator assistant that suggests next steps based on
workspace evidence.

```bash
drake assist start web example.com -w my-engagement
drake assist start apk com.evil.dropper -w my-engagement
```

### Interaction loop

1. Read workspace state (sessions, findings, graph)
2. Ask local LLM for a suggested next step
3. Present the suggestion with reasoning and evidence basis
4. Wait for operator confirmation
5. Execute via existing engine (if approved)
6. Repeat

### UX output

```
--- assist step 1/10 ---
› analyzing workspace state...

Suggested next step:
  run headers_audit
  Reason: No security header analysis has been performed yet.
  Based on: curl:http_meta artifact present
  Confidence: high

Proceed? [y/n/q] >
```

### Requirements

- Requires a running local Ollama instance.
- Suggestions are evidence-backed — the AI sees current findings and
  the evidence graph if present.
- Type `q` at any prompt to exit.
- Non-executable suggestions (like "review findings") show the
  relevant command instead of running blindly.

## Flow Navigation

Interactive menu for operators who don't want to memorize subcommands.

```bash
drake flow
```

### UX output

```
  Drake-X Flow Navigation
  Select a category to see the command to run.

   1  Workspace Setup
   2  Scope Management
   3  Reconnaissance
   4  Web Analysis
   5  APK Analysis
   6  Mission Workflow
   7  AI Assist
   8  Findings
   9  Evidence Graph
  10  AI Tasks
  11  Reports
  12  Tools
   q  Exit

  > 3

  Reconnaissance
  drake recon run <target> -m <module>
```

### Behavior

- No curses, no heavy UI. Just numbered choices and stdin.
- Shows the exact command to run — the operator copies and executes it.
- Type `q` or press Ctrl-C to exit.

## Compatibility

All original commands (`init`, `scope`, `recon`, `web`, `api`, `apk`,
`graph`, `findings`, `ai`, `report`, `tools`) remain unchanged. The UX
layer adds `mission`, `assist`, and `flow` alongside them.

The UX commands are pure orchestration — they never bypass scope
enforcement, skip audit logging, or execute without confirmation where
the underlying module requires it.

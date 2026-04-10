# Drake-X usage walkthrough

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`kali-setup.md`](kali-setup.md), [`llm-setup.md`](llm-setup.md)

This is the long-form companion to the README "Quick tour" section. It
walks you through a realistic engagement from `drake init` through
report generation.

For the full docs index, see [`README.md`](README.md).
If you want a compact command reference while following this guide, see
[`cheat-sheet.md`](cheat-sheet.md).

## 1. Scaffold a workspace

```bash
drake init acme-bug-bounty --operator alice
```

This creates `~/.drake-x/workspaces/acme-bug-bounty/` with:

- `workspace.toml` — workspace config (operator, AI model, defaults)
- `scope.yaml` — engagement scope template (REPLACE BEFORE USE)
- `runs/` — per-session evidence and reports
- `audit.log` — append-only JSONL of every plan, run, denial, and
  completion event
- `drake.db` — SQLite database (created on first run)

> Use `--here` if you want the workspace to live inside your current
> directory instead of the default `~/.drake-x/workspaces/`.

## 2. Define the engagement scope

Open `~/.drake-x/workspaces/acme-bug-bounty/scope.yaml` and replace the
placeholder values. A realistic file might look like:

```yaml
engagement: acme-bug-bounty
authorization_reference: "HackerOne report 87654 / signed letter 2026-04-08"

rate_limit_per_host_rps: 5.0
max_concurrency: 4
allow_active: false        # flip to true ONLY after re-confirming permission

in_scope:
  - kind: domain
    value: acme.example
  - kind: wildcard_domain
    value: acme.example
  - kind: cidr
    value: 198.51.100.0/24
  - kind: url_prefix
    value: https://api.acme.example/v2/

out_of_scope:
  - kind: wildcard_domain
    value: corp.acme.example
  - kind: domain
    value: legacy.acme.example
```

Validate it:

```bash
drake scope validate -w acme-bug-bounty
drake scope show     -w acme-bug-bounty
```

Spot-check that a target falls inside the scope before scanning:

```bash
drake scope check api.acme.example -w acme-bug-bounty
# ✓ ALLOW — api.acme.example
```

## 3. List and pick a recon module

```bash
drake recon list-modules
```

Output:

```
recon_passive  (passive/light)
  Passive recon: DNS, WHOIS, one safe HTTP HEAD. No active scanning.
recon_active   (active)
  Conservative active recon: dig, whois, curl, whatweb, sslscan, nmap.
  Requires scope.allow_active=true and operator confirmation.
web_inspect    (active)
  Web stack inspection: HTTP headers, redirects, technologies, TLS
  posture, nikto information-only checks.
tls_inspect    (passive/light)
  TLS protocol/cipher/certificate posture (sslscan, future testssl).
headers_audit  (passive/light)
  Check HTTP security headers (HSTS, CSP, framing, MIME).
content_discovery  (active)
  Directory and content discovery (intrusive — stub).
api_inventory      (passive/light)
  Build an inventory of API endpoints from OpenAPI/Swagger specs. Stub.
```

Plan a passive recon run before executing:

```bash
drake recon plan api.acme.example -m recon_passive -w acme-bug-bounty
```

Output:

```
✓ plan for api.acme.example using module recon_passive
› profile: passive
› runnable: dig, whois, curl
```

## 4. Run it

```bash
drake recon run api.acme.example -m recon_passive -w acme-bug-bounty
```

Drake-X prints a summary at the end:

```
✓ session 7a4b9e21c133 finished with status completed
› tools ran: dig, whois, curl
› next: `drake report generate 7a4b9e21c133 --workspace acme-bug-bounty`
```

## 5. Run an active module (after confirming permission)

Edit `scope.yaml` and set `allow_active: true`. Then:

```bash
drake recon run api.acme.example -m recon_active -w acme-bug-bounty
```

Drake-X prompts at the gate for each active integration:

```
[!] Active action requested:
    integration: nmap
    policy:      active
    target:      api.acme.example
  Proceed? (yes/no) >
```

Use `--yes` to pre-approve everything in one shot, or `--dry-run` to
plan without executing:

```bash
drake recon run api.acme.example -m recon_active -w acme-bug-bounty --dry-run
drake recon run api.acme.example -m recon_active -w acme-bug-bounty --yes
```

## 6. List and inspect findings

```bash
drake findings list -w acme-bug-bounty
drake findings list -w acme-bug-bounty --severity medium
drake findings list -w acme-bug-bounty --source parser
drake findings show f-abc123 -w acme-bug-bounty
```

## 7. Run AI tasks

(Requires Ollama — see [`llm-setup.md`](llm-setup.md).)

```bash
drake ai status                                  -w acme-bug-bounty
drake ai summarize    7a4b9e21c133               -w acme-bug-bounty
drake ai classify     7a4b9e21c133               -w acme-bug-bounty
drake ai next-steps   7a4b9e21c133               -w acme-bug-bounty
drake ai draft-report 7a4b9e21c133               -w acme-bug-bounty
```

## 8. Generate reports

```bash
drake report list                                       -w acme-bug-bounty

drake report generate 7a4b9e21c133 -f md                -w acme-bug-bounty
drake report generate 7a4b9e21c133 -f executive         -w acme-bug-bounty
drake report generate 7a4b9e21c133 -f json              -w acme-bug-bounty
drake report generate 7a4b9e21c133 -f manifest          -w acme-bug-bounty
drake report generate 7a4b9e21c133 -f evidence          -w acme-bug-bounty
```

The five formats:

- `md` — full technical Markdown (default)
- `executive` — short, non-technical executive summary
- `json` — canonical machine-readable JSON (this is what you ship to
  CI / dashboards / triage tools)
- `manifest` — small JSON document with command lines, exit codes,
  durations, and host info; reproducibility-oriented
- `evidence` — Markdown table of every artifact, tool, and confidence

By default reports are written under
`~/.drake-x/workspaces/<name>/runs/<session-id>/`. Pass `-o <path>` to
override.

## 9. Audit log

Every plan / run / deny / confirmation / finish event is appended as
one JSON line to `<workspace>/audit.log`:

```bash
tail -f ~/.drake-x/workspaces/acme-bug-bounty/audit.log
```

Sample entry:

```json
{"ts": "2026-04-10T09:12:33+00:00", "actor": "operator", "action": "run.finish",
 "subject": "api.acme.example", "decision": "allow", "dry_run": false,
 "workspace": "acme-bug-bounty", "session_id": "7a4b9e21c133",
 "payload": {"status": "completed", "tools_ran": ["dig", "whois", "curl"]}}
```

Treat this file as evidence in its own right — never edit it by hand.

## 10. Listing supported tools

```bash
drake tools             # uses the default workspace if none is given
drake tools -w acme-bug-bounty
```

You'll see:
- built-in recon adapters
- optional real/stub integrations
- third-party plugins discovered through the `drake_x.integrations`
  entry-point group
- supporting toolchains used by APK, dynamic validation, intelligence
  enrichment, and reporting workflows

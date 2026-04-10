# Drake-X

Drake-X is a local-first offensive security framework for Kali Linux,
featuring local AI assistance, strict scope enforcement, reproducible
workspaces, human-in-the-loop operation, and evidence-driven reporting.

Drake-X orchestrates locally installed reconnaissance tools, normalizes
their output into structured artifacts, enforces operator-declared
engagement scope, and optionally asks a local LLM for triage and
classification. It produces auditable, evidence-linked reports that
clearly separate observed facts from AI-generated inference.

Drake-X is written in Python 3. It shells out to native Kali tools as
subprocesses but contains no Kali-only Python dependencies.

## Authorized use only

> Drake-X is intended for **authorized** security testing only. Only run
> it against assets you own, or for which you have explicit, written
> permission to assess. Unauthorized scanning may be illegal in your
> jurisdiction.

Drake-X is not an exploit framework. It does not perform exploitation,
brute forcing, credential attacks, payload generation, post-exploitation,
persistence, lateral movement, phishing, or weaponization of any kind.
The code and the AI prompts both enforce this boundary.

## Design Principles

- **Human-in-the-loop by design.** The operator declares scope, selects
  modules, confirms active actions, and validates every finding. Drake-X
  assists with triage and reporting — it never acts autonomously.
- **Strict scope enforcement.** An engagement scope file must exist
  before any tool runs. Out-of-scope targets are refused. Active
  integrations require both `scope.allow_active=true` and explicit
  operator confirmation.
- **Evidence over assumptions.** Every finding carries a `source` (rule,
  AI, parser, operator) and a `fact_or_inference` flag. Reports never
  present AI-generated interpretation as observed fact.
- **Local-first AI.** The optional LLM layer communicates only with a
  local Ollama instance on the same host. There is no remote AI client
  in the codebase. No telemetry. No cloud dependency.
- **Reproducibility and auditability.** Each workspace is a
  self-contained directory with config, scope, database, evidence, and
  an append-only audit log. Copy the directory to reproduce every
  report on another host.

## Capabilities

**Workspace model.** `~/.drake-x/workspaces/<name>/` holds
`workspace.toml`, `scope.yaml`, `drake.db` (SQLite), `runs/`, and
`audit.log`.

**Scope enforcement.** Operator-declared in-scope and out-of-scope
assets (domain, wildcard, IP, CIDR, URL prefix). Out-of-scope rules
always win. Targets matching no in-scope rule are denied by default.

**Modules.** `recon_passive`, `recon_active`, `web_inspect`,
`tls_inspect`, `headers_audit`, `content_discovery`, `api_inventory`.

**Integrations.** Built-in: nmap, dig, whois, whatweb, nikto, curl,
sslscan. Real optional: httpx, ffuf. Stubs for future work: subfinder,
amass, naabu, dnsx, nuclei, feroxbuster, eyewitness, testssl.

**Mission workflows.** `drake mission run web/recon/apk/full <target>`
orchestrates multi-step analysis with progress output, scope enforcement,
and confirmation gating. See [`docs/ux-layer.md`](docs/ux-layer.md).

**AI Assist.** `drake assist start <domain> <target>` provides a guided
AI loop that suggests evidence-backed next steps, explains reasoning,
and executes only with operator confirmation.

**Flow navigation.** `drake flow` provides interactive menu-based
navigation for operators who prefer not to memorize subcommand names.

**Workspace observability.** `drake status` shows workspace info, scope
summary, session history, findings severity breakdown, evidence graph
stats, and tool availability in a single read-only command.

**Audit-logged assist sessions.** Every Assist Mode suggest/confirm/
execute/skip step is persisted. Review with `drake assist history` or
export with `drake assist export`.

**Custom mission templates.** Define operator workflows as TOML files
in `<workspace>/missions/`. List, show, and execute with full scope
enforcement. See [`docs/operator-control.md`](docs/operator-control.md).

**Security headers audit.** Rule-based findings for missing HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, cookie flags,
and server version leaks. Each tagged with CWE and OWASP references.

**Rate limiter.** HTTP-style integrations respect per-host pacing and a
global concurrency budget, both configurable in the scope file.

**Findings model.** CWE / OWASP / MITRE ATT&CK references, evidence
backrefs, fact vs inference flag, remediation placeholders, operator tags.

**Local AI assistance.** File-based prompts and task classes:
`summarize`, `classify`, `next_steps`, `observations`, `report_draft`,
`dedupe`. All tasks run against stored artifacts — they never invoke
tools.

**Reporting.** Five output formats: technical Markdown, executive
Markdown, JSON, scan manifest, evidence index. Session-to-session diff
for tracking attack-surface changes over time.

**API inventory.** Parses operator-supplied OpenAPI/Swagger specs into
structured endpoint inventories without making network calls.

**APK static analysis.** Dedicated agent for Android malware analysis:
manifest parsing, permission auditing, behavior detection, obfuscation
assessment, protection detection, campaign similarity, and a structured
11-section technical report. See [`docs/apk-analysis.md`](docs/apk-analysis.md).

**Evidence Graph.** Structured relationships between findings, artifacts,
indicators, and assessments. Nodes carry domain (web, apk), kind, and
provenance. Edges encode derived_from, supports, related_to, and
duplicate_of relationships. Persisted per-session, queryable via
`drake graph show`, and consumed by AI tasks for graph-aware reasoning.
See [`docs/evidence-model.md`](docs/evidence-model.md).

**Auditability.** Every plan, run, denial, confirmation, and completion
event is appended as a JSON line to `<workspace>/audit.log`. The
engagement scope is snapshotted into the database at the start of each
session.

## Installation (Kali Linux)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
                    nmap dnsutils whois whatweb nikto curl sslscan

git clone https://github.com/PauloBernardo90/Drake-X.git
cd Drake-X
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify:

```bash
drake --help
drake tools
```

See [`docs/kali-setup.md`](docs/kali-setup.md) for the full walkthrough.

## Local LLM (optional)

Drake-X never sends data to a remote provider. For local AI assistance,
run [Ollama](https://ollama.com/) on the same host:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b
ollama serve &
drake ai status -w my-engagement
```

See [`docs/llm-setup.md`](docs/llm-setup.md) for model selection and
prompt customization.

## Quick tour

```bash
# Initialize a workspace
drake init my-engagement

# Define the engagement scope
$EDITOR ~/.drake-x/workspaces/my-engagement/scope.yaml
drake scope validate -w my-engagement
drake scope check example.com -w my-engagement

# Plan and execute passive recon
drake recon plan example.com -m recon_passive -w my-engagement
drake recon run  example.com -m recon_passive -w my-engagement

# Execute active recon (requires scope.allow_active=true)
drake recon run example.com -m recon_active -w my-engagement --yes

# Ingest an OpenAPI spec
drake api ingest /path/to/openapi.json -w my-engagement

# Static analysis of an Android APK
drake apk analyze sample.apk -o ./apk-output

# Generate reports
drake report generate <session-id> -f md        -w my-engagement
drake report generate <session-id> -f json      -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
drake report generate <session-id> -f manifest  -w my-engagement

# Compare two sessions
drake report diff <session-a> <session-b> -w my-engagement

# Explore the evidence graph
drake graph show <session-id> -w my-engagement
drake graph show <session-id> -w my-engagement --format summary
drake graph show <session-id> -w my-engagement --node <node-id> --depth 2
drake graph show <session-id> -w my-engagement --findings --format json

# Run AI tasks (requires Ollama) — graph-aware when graph is present
drake ai summarize    <session-id> -w my-engagement
drake ai classify     <session-id> -w my-engagement
drake ai dedupe       <session-id> -w my-engagement --apply

# Inspect findings
drake findings list -w my-engagement
drake findings show <finding-id> -w my-engagement
```

See [`docs/usage.md`](docs/usage.md) for the full walkthrough.
For a compact command reference, see [`docs/cheat-sheet.md`](docs/cheat-sheet.md).

## Documentation

- [`docs/README.md`](docs/README.md) — documentation index
- [`docs/cheat-sheet.md`](docs/cheat-sheet.md) — compact CLI command reference
- [`docs/usage.md`](docs/usage.md) — end-to-end usage walkthrough
- [`docs/kali-setup.md`](docs/kali-setup.md) — Kali installation and setup
- [`docs/llm-setup.md`](docs/llm-setup.md) — Ollama and local AI configuration
- [`docs/architecture.md`](docs/architecture.md) — architecture and package layout
- [`docs/safety.md`](docs/safety.md) — safety and scope enforcement

## Safety

Drake-X enforces every action through four layers:

1. **Target validation** — refuses loopback, link-local, multicast,
   reserved ranges, and excessively broad CIDRs regardless of scope.
2. **Engagement scope** — out-of-scope rules win; unmatched targets are
   denied by default.
3. **Action policy** — every integration is classified as passive, light,
   active, or intrusive. Active and intrusive integrations require
   `scope.allow_active=true`.
4. **Confirmation gate** — active and intrusive integrations prompt the
   operator for confirmation. `--dry-run` plans without executing.

Every event is recorded in the append-only audit log. See
[`docs/safety.md`](docs/safety.md) for the complete safety model.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check drake_x tests
ruff format drake_x tests
```

See [`docs/architecture.md`](docs/architecture.md) for the package
layout, engine lifecycle, storage schema, and extension guide.
For a quick CLI reference, see [`docs/cheat-sheet.md`](docs/cheat-sheet.md).

## Non-goals

Drake-X does not and will not implement:

- Exploit execution or Metasploit integration
- Brute forcing or credential attacks
- SQL injection, XSS, SSRF, CSRF, or RCE testing
- Lateral movement, persistence, or privilege escalation
- Phishing or malware simulation
- Autonomous agent loops that execute arbitrary commands
- Telemetry or network calls to remote AI providers

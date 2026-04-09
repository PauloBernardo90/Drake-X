# Drake-X

**Drake-X** is a CLI-based reconnaissance assistant for **authorized** security
assessments. It accepts a single target (IPv4, IPv6, CIDR, domain, or URL),
discovers which native Kali tools are installed on the host, runs a safe set of
recon workflows against the target, normalizes the output into structured
artifacts, persists everything to SQLite, and (optionally) hands the artifacts
to a **local** Ollama model for careful triage. It then renders a Markdown
report.

## Authorized use only

> Drake-X is intended for **authorized** security testing only. Only run it
> against assets you own, or for which you have explicit, written permission to
> assess. Unauthorized scanning may be illegal in your jurisdiction. By using
> Drake-X you accept full responsibility for the targets you choose.

Drake-X is **not an exploit framework**. It does not perform exploitation,
brute forcing, credential attacks, payload generation, post-exploitation,
persistence, lateral movement, phishing, or any kind of weaponization. The AI
layer is constrained by prompt and by code to refuse exploit suggestions.

## Features

- Scope-aware target validation (rejects loopback, link-local, multicast,
  reserved ranges, and absurdly broad CIDRs).
- Profile-based recon orchestration: `passive`, `safe`, `web-basic`,
  `network-basic`.
- Adapters for the most common Kali recon tools: `nmap`, `dig`, `whois`,
  `whatweb`, `nikto` (information-only mode), `curl`, `sslscan`.
- Per-tool subprocess execution with timeouts; **no shell injection** anywhere
  (every adapter builds an `argv` list and uses
  `asyncio.create_subprocess_exec`).
- Structured normalizers that turn raw tool output into stable JSON artifacts.
- SQLite persistence for sessions, tool results, artifacts, and findings.
- Optional local Ollama integration with a careful, defensive system prompt.
  Drake-X never calls remote AI providers.
- Markdown reports with explicit "analyst validation required" framing.
- Graceful degradation when binaries are missing — missing tools are reported,
  not silently skipped.

## Architecture overview

```
                    ┌────────────────┐
        target ──▶  │  drake_x.scope │   validate / canonicalize
                    └────────┬───────┘
                             ▼
                    ┌────────────────┐
                    │   registry     │   discover installed binaries
                    └────────┬───────┘
                             ▼
                    ┌────────────────┐
                    │  orchestrator  │   pick tools, run safely, persist
                    └────────┬───────┘
                             ▼
        ┌───────────────┬───────────────┬──────────────────┐
        ▼               ▼               ▼                  ▼
   tools (subprocess)  normalizers     session_store    AI analyzer (optional)
                                       (SQLite)         (local Ollama)
                             ▼
                    ┌────────────────┐
                    │ reports.markdown │
                    └────────────────┘
```

The CLI (`drake_x.cli`) wires these together. Every layer is exercised by tests
in `tests/`.

## Installation (Kali Linux)

```bash
# 1. Install Python 3.12+ and a few build deps if missing.
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

# 2. Recommended: native recon tools.
sudo apt install -y nmap dnsutils whois whatweb nikto curl sslscan

# 3. Clone and install Drake-X.
git clone https://github.com/PauloBernardo90/Drake-X.git
cd Drake-X
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

After install, you should have a `drake-x` entrypoint on your `PATH`:

```bash
drake-x --help
drake-x tools list
```

### Expected native tools

Drake-X works fine if some of these are missing — it will just report them as
skipped — but the more you have, the more useful the output:

| Package (Debian/Kali) | Binary    | Used by profiles                       |
|-----------------------|-----------|----------------------------------------|
| `nmap`                | `nmap`    | `safe`, `network-basic`                |
| `dnsutils`            | `dig`     | all profiles                           |
| `whois`               | `whois`   | `passive`, `safe`, `web-basic`         |
| `whatweb`             | `whatweb` | `safe`, `web-basic`                    |
| `nikto`               | `nikto`   | `web-basic` only (information-only)    |
| `curl`                | `curl`    | `passive`, `safe`, `web-basic`         |
| `sslscan`             | `sslscan` | `safe`, `web-basic`                    |

## Optional: Ollama setup

Drake-X never sends data to a remote provider. If you want AI triage you must
run [Ollama](https://ollama.com/) locally.

```bash
# Install Ollama (see https://ollama.com for the latest instructions).
curl -fsSL https://ollama.com/install.sh | sh

# Pull a small instruction-tuned model. Drake-X defaults to llama3.2:3b.
ollama pull llama3.2:3b

# Make sure the daemon is running on http://localhost:11434.
ollama serve &
```

Drake-X will automatically detect whether Ollama is reachable. If it's not, the
scan still runs and the AI section is simply omitted.

## Profiles

| Profile         | Intent                                                              | Typical tools                                |
|-----------------|---------------------------------------------------------------------|----------------------------------------------|
| `passive`       | DNS / WHOIS / single HTTP HEAD only — no active scanning            | `dig`, `whois`, `curl`                       |
| `safe`          | Conservative active recon, suitable for most engagements (default)  | `dig`, `whois`, `curl`, `whatweb`, `sslscan`, `nmap` |
| `web-basic`     | Web fingerprinting oriented                                         | `dig`, `whois`, `curl`, `whatweb`, `sslscan`, `nikto` (info-only) |
| `network-basic` | Service discovery oriented                                          | `dig`, `nmap`                                |

You can pick a profile with `--profile`:

```bash
drake-x scan example.com --profile passive
drake-x scan https://example.com/login --profile web-basic
drake-x scan 192.0.2.0/24 --profile network-basic
```

## Basic usage

```bash
# Recon a domain with the default safe profile.
drake-x scan example.com

# Recon a URL, write a JSON summary to stdout, generate the report file.
drake-x scan https://example.com/login --json

# Use a different local model via Ollama.
drake-x scan example.com --model llama3.2:1b

# Skip AI analysis even if Ollama is reachable.
drake-x scan example.com --no-ai

# Use a custom database / output directory.
drake-x scan example.com --db-path /tmp/drake.db --output-dir /tmp/drake_runs

# List supported tools and which ones are installed.
drake-x tools list

# Re-render a Markdown report from a previously stored session.
drake-x report <session_id> -o report.md
```

## Output

Each scan produces:

1. A row in the SQLite database (`drake_x.db` by default) covering the session,
   each tool result, every parsed artifact, and any AI findings.
2. A directory under `drake_x_runs/<session_id>/` with:
   - `report.md` — the Markdown report
   - `artifacts.json` — every parsed artifact, for downstream processing

The Markdown report includes:

- session metadata
- target summary
- tools executed and missing tools (and warnings)
- discovered services (nmap)
- DNS records (dig)
- WHOIS summary
- web stack observations (whatweb, curl)
- TLS observations (sslscan)
- nikto information-only headlines
- AI executive summary + findings (if Ollama was used)
- a closing reminder that all output requires analyst validation

## Development

```bash
# In your venv:
pip install -e ".[dev]"

# Run tests (no real tools required — subprocess and shutil.which are mocked).
pytest -q

# Lint / format.
ruff check drake_x tests
ruff format drake_x tests
```

The codebase is small and intentionally avoids clever metaprogramming. Adding a
new tool means writing one adapter under `drake_x/tools/` (subclass `BaseTool`,
provide `meta` and `build_command`), and one normalizer under
`drake_x/normalize/`.

## Known limitations

- Drake-X does not maintain its own scope file — scope checks are baked in
  (loopback / link-local / huge CIDRs are refused) but per-engagement allow
  lists are out of scope for v1.
- Tool output is parsed best-effort. Where a parser cannot make sense of the
  output, the artifact is still produced but with `confidence = 0.0` and an
  explanatory note.
- The AI layer is informational. It cannot replace a human analyst.
- IPv6 support is present but lightly tested in the v1 tool adapters.
- We do not (yet) attempt subdomain enumeration, certificate transparency
  lookups, or passive DNS aggregation.

## Roadmap (v2 ideas)

- Engagement-scoped allow lists (refuse anything outside an explicit scope file).
- Optional, opt-in subdomain enumeration via passive sources only.
- Concurrency tuning per profile.
- Pluggable normalizers via Python entry points.
- HTML report rendering alongside Markdown.
- Richer findings model with cross-tool correlation.
- A "watch" mode that diffs successive scans of the same target.

## Out of scope (intentionally)

Drake-X **does not** and **will not** implement any of the following:

- Exploit execution, Metasploit integration
- Brute forcing or credential attacks
- Default-on directory fuzzing
- SQL injection / XSS / SSRF / CSRF / RCE testing
- Lateral movement, persistence, privilege escalation
- Phishing, malware simulation
- Autonomous "agent loops" that can run arbitrary commands
- Telemetry or any network call to a remote AI provider

If you need any of those for an engagement, use a purpose-built tool with the
appropriate authorization in place.

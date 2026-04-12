# Kali Linux setup

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`usage.md`](usage.md), [`llm-setup.md`](llm-setup.md)

Drake-X is designed to run natively on Kali Linux. The framework itself
is pure Python 3, but it shells out to native Kali tools as subprocesses,
so you'll get the most value from it on a Kali host where malware-
analysis, reverse-engineering, and supporting collection tools already
live.

## Prerequisites

- Kali Linux 2024.x or newer (any rolling release works)
- Python 3.12 or newer
- About 200 MB of disk for the framework + dependencies
- Additional disk for local models, extracted samples, APK reports, and
  reverse-engineering artifacts

## 1. Install Python and the system tools

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-pip \
    nmap dnsutils whois whatweb nikto curl sslscan \
    apktool jadx unzip yara radare2 ghidra adb
```

| Package (Debian/Kali) | Binary    | Used by                                    |
|-----------------------|-----------|--------------------------------------------|
| `nmap`                | `nmap`    | `recon_active`, `recon_active`             |
| `dnsutils`            | `dig`     | every recon module                         |
| `whois`               | `whois`   | every passive/light module                 |
| `whatweb`             | `whatweb` | `web_inspect`, `recon_active`              |
| `nikto`               | `nikto`   | `web_inspect` (information-only)           |
| `curl`                | `curl`    | every web/passive module                   |
| `sslscan`             | `sslscan` | `tls_inspect`, `web_inspect`               |

Drake-X gracefully degrades when tools are missing — they show up under
"missing" in the plan and the run continues without them.

For v0.8, the most important optional toolchains after the base install
are:

- `apktool`, `jadx`, `unzip`, `yara`, `radare2` for APK/static analysis
- `ghidra` for deeper native analysis
- `adb` and `frida` for analyst-assisted dynamic validation
- `pefile` and `capstone` (Python) for PE/Windows malware analysis

### PE analysis prerequisites (v0.8)

```bash
pip install pefile capstone
```

These are Python libraries, not system packages. Install them in the
Drake-X virtualenv. Both are optional — PE analysis degrades gracefully
without them.

Install Frida if you want to use runtime observation workflows:

```bash
python3 -m pip install frida-tools
```

## 2. Optional: install supporting collection integrations

Drake-X ships stubs for these integrations under
`drake_x/integrations/optional/`. The stubs declare their argv layout
and policy classification so plans and audits already know about them,
but they refuse to actually execute until the wrapper is implemented.
Install the binaries now if you want to be ready when the wrappers
land:

```bash
# ProjectDiscovery suite (preferred install via Go is also fine)
sudo apt install -y httpx-toolkit subfinder amass

# nuclei / naabu / dnsx — install per upstream docs
# https://github.com/projectdiscovery

# Web fuzzers (intrusive — Drake-X never runs them by default)
sudo apt install -y ffuf feroxbuster

# Screenshots
sudo apt install -y eyewitness

# testssl.sh
sudo apt install -y testssl.sh
```

## 3. Clone and install Drake-X

```bash
git clone https://github.com/PauloBernardo90/Drake-X.git
cd Drake-X
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

After installation you'll have the `drake` console entry point:

```bash
drake --help
```

Confirm the install:

```bash
drake tools             # lists integrations plus APK/dynamic/reporting toolchains
pytest -q               # all tests should pass
```

## 4. Optional: install PyYAML

Drake-X reads scope files via PyYAML when present, otherwise via a
small built-in subset reader good enough for the default template. If
you plan to write more elaborate scope files, install PyYAML:

```bash
pip install pyyaml
```

## 5. Optional: set up a local LLM

See [`llm-setup.md`](llm-setup.md).

## Running Drake-X under a non-root user

Drake-X never asks for root privileges. Some supporting collection
integrations may need them (`nmap` for SYN scans, etc.), while some
dynamic-analysis setups may require device/emulator-specific privileges.
Run Drake-X as a normal user; only escalate the specific tools that need
it, ideally via `sudo` on a per-command allowlist.

## Persisted state on disk

After `drake init my-engagement`:

```
~/.drake-x/
  workspaces/
    my-engagement/
      workspace.toml          # workspace config
      scope.yaml              # engagement scope (edit before running)
      scope.json              # (optional) JSON snapshot for programmatic use
      drake.db                # SQLite database
      runs/
        <session-id>/
          report.md           # technical report
          executive.md        # executive report (when generated)
          report.json         # JSON report
          manifest.json       # scan manifest
          evidence_index.md   # evidence table
      audit.log               # append-only JSONL audit log
```

You can copy a workspace directory to another Kali box and re-render
every report against the same evidence:

```bash
rsync -av ~/.drake-x/workspaces/my-engagement/ otherbox:~/.drake-x/workspaces/my-engagement/
ssh otherbox 'drake report generate <session-id> -f md -w my-engagement'
```

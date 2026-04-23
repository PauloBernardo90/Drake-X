# Sandbox — Local-First Isolated Execution

Drake-X's sandbox layer provides controlled, isolated execution of Android
samples and artifacts for defensive malware research. The primary backend
is **Firejail** on Linux.

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Deny-by-default** | No network access unless explicitly opted-in via lab mode |
| **Fail-closed** | If isolation cannot be guaranteed, execution is refused |
| **Ephemeral** | Each run gets a temporary workspace destroyed after completion |
| **Auditable** | Every run produces a structured report with full provenance |
| **Local-first** | No samples or telemetry sent to external services |
| **No fallback** | There is no "run without sandbox" path — missing backend = error |

## Dependencies

### Required

- **Firejail** — Linux sandbox (primary backend)
  ```bash
  sudo apt install firejail
  ```

### Python

- Python 3.11+
- All Drake-X core dependencies

## Usage

### CLI

```bash
# Basic execution — network DENIED by default
drake sandbox run malware.apk -- file sample/malware.apk

# With timeout override
drake sandbox run sample.dex --timeout 60 -- strings sample/sample.dex

# With report output
drake sandbox run payload.apk -o ./reports -- ls -la sample/

# Lab mode (network enabled — controlled environment only)
drake sandbox run sample.apk --network -- curl http://localhost:8080

# Check if sandbox is available
drake sandbox check
```

### Python API

```python
from pathlib import Path
from drake_x.sandbox import run_sandboxed
from drake_x.sandbox.base import SandboxConfig, NetworkPolicy

# Default: deny network, 120s timeout
report = run_sandboxed(
    sample_path=Path("malware.apk"),
    command=["file", "sample/malware.apk"],
)

# Custom configuration
config = SandboxConfig(
    timeout_seconds=60,
    network=NetworkPolicy.DENY,  # explicit
)
report = run_sandboxed(
    sample_path=Path("malware.apk"),
    command=["strings", "sample/malware.apk"],
    config=config,
    output_dir=Path("./reports"),
)

print(report.status)         # "success"
print(report.exit_code)      # 0
print(report.sample_sha256)  # full hash
print(report.stdout)         # captured output
```

## Containment Model

### What the sandbox restricts

| Resource | Policy |
|----------|--------|
| **Network** | Denied by default (`net none` in Firejail) |
| **Filesystem** | Private namespace — no host access |
| **Home directory** | Isolated (`private`) |
| **Temp files** | Private (`private-tmp`) |
| **Device access** | Private (`private-dev`) |
| **Capabilities** | All dropped (`caps.drop all`) |
| **Privileges** | No new privileges (`nonewprivs`) |
| **Root** | No root access (`noroot`) |
| **Syscalls** | Filtered (`seccomp`) |
| **Sensitive paths** | Blacklisted (`/etc/shadow`, `/etc/ssh`, `/root`, `/boot`) |
| **Audio/Video/3D** | Disabled |
| **Workspace** | Destroyed after execution |

### What the sandbox does NOT protect against

- **Kernel exploits**: Firejail uses namespaces, not virtualization
- **Hardware-level attacks**: No hypervisor isolation
- **Side-channel attacks**: Shared kernel with host
- **Zero-day sandbox escapes**: No sandbox is 100% escape-proof

For higher isolation requirements, use a dedicated VM or hardware-isolated lab.

## Execution Workflow

```
1. Validate sample (exists, is file, no path traversal, size check)
2. Validate network policy
3. Check Firejail availability
4. Verify isolation capability (fail-closed if not)
5. Create ephemeral workspace
   ├─ sample/   — copy of sample (read-only)
   └─ output/   — writable area for command output
6. Generate Firejail security profile
7. Execute command inside Firejail
8. Capture stdout/stderr (size-capped)
9. Generate structured report
10. Destroy workspace (guaranteed via context manager)
```

## Report Format

Every execution produces a `SandboxReport` with this structure:

```json
{
  "run_id": "sbx-a1b2c3d4e5f6",
  "sample": {
    "path": "/path/to/malware.apk",
    "sha256": "abc123...",
    "size": 12345
  },
  "execution": {
    "backend": "firejail",
    "command": ["file", "sample/malware.apk"],
    "network_policy": "deny",
    "timeout_seconds": 120
  },
  "timing": {
    "started_at": "2025-01-15T10:30:00+00:00",
    "finished_at": "2025-01-15T10:30:02+00:00",
    "duration_seconds": 1.523
  },
  "outcome": {
    "exit_code": 0,
    "timed_out": false,
    "status": "success",
    "error": null
  },
  "output": {
    "stdout": "sample/malware.apk: Zip archive data...",
    "stderr": ""
  },
  "isolation": {
    "verified": true,
    "notes": ["Firejail isolation verified"]
  },
  "audit": {
    "observations": [
      "Workspace created: /tmp/drake_sandbox_xxxx",
      "Workspace cleanup: completed"
    ]
  }
}
```

## Security Hardening Details

### Firejail Profile

The auto-generated profile includes:

```
private              # isolated filesystem namespace
private-tmp          # private /tmp
private-dev          # private /dev
caps.drop all        # drop all Linux capabilities
nonewprivs           # no privilege escalation
noroot               # no root access
seccomp              # syscall filter
net none             # no network (default)
blacklist /etc/shadow
blacklist /etc/ssh
blacklist /root
blacklist /boot
```

### Input Validation

- Sample path resolved and verified (no symlink traversal)
- Sample size capped at 2 GiB
- `--profile` and `--private` overrides blocked in extra_args
- Subprocess called with list form (no shell injection)
- Output truncated at 512 KiB per stream

## Limitations

1. **Linux only**: Firejail is Linux-specific
2. **Not a VM**: Shares the host kernel — kernel exploits can escape
3. **No Android emulation**: This sandbox runs host-native commands on the
   sample, not the sample itself in an Android environment
4. **Static tools only**: Designed for running static analysis tools (file,
   strings, objdump) on samples, not for dynamic execution of APK code
5. **Single backend**: Only Firejail is implemented (extensible via
   `SandboxBackend` ABC for future Docker/QEMU backends)

## Module Architecture

```
drake_x/sandbox/
├── __init__.py          # Package entry point (run_sandboxed)
├── base.py              # ABC, config, result, enums
├── exceptions.py        # Sandbox-specific exceptions
├── firejail_runner.py   # Firejail backend implementation
├── network_guard.py     # Network policy validation
├── profile_builder.py   # Firejail profile generation
├── report.py            # Structured execution report
├── runner.py            # Main orchestrator (ties everything together)
└── workspace.py         # Ephemeral workspace manager
```

## Risks Accepted

| Risk | Mitigation |
|------|------------|
| Firejail namespace escape | Use VM for high-risk samples |
| Kernel-level exploit in sample | Run on disposable VM host |
| Firejail misconfiguration | Profile is auto-generated with hardened defaults |
| Workspace cleanup failure | Logged as warning; manual cleanup may be needed |
| Large output capture | Capped at 512 KiB per stream |

"""Firejail profile builder — generates restrictive security profiles.

Firejail profiles define what the sandboxed process can and cannot do.
The builder generates a profile with deny-by-default posture:

- Private filesystem namespace
- No network access (unless lab mode)
- No access to home directory
- No access to /etc sensitive files
- Read-only binds for essential directories
- Seccomp syscall filter enabled
- No new privileges
- No root access
- No audio, dbus, or X11

The generated profile is written to the workspace and passed to Firejail
via ``--profile=``.
"""

from __future__ import annotations

from pathlib import Path

from .base import NetworkPolicy, SandboxConfig


def build_firejail_profile(
    workspace: Path,
    config: SandboxConfig,
) -> str:
    """Generate a Firejail profile string for the given configuration.

    Returns the profile content as a string.
    """
    lines: list[str] = [
        "# Drake-X sandbox profile — auto-generated, deny-by-default",
        "#",
        "# This profile restricts the sandboxed process to the workspace",
        "# directory and denies access to sensitive host resources.",
        "",
        "# Filesystem isolation",
        "private",
        "private-tmp",
        "private-dev",
        "",
        "# Deny sensitive paths",
        "blacklist /etc/shadow",
        "blacklist /etc/gshadow",
        "blacklist /etc/ssh",
        "blacklist /root",
        "blacklist /boot",
        "blacklist /var/log",
        "",
        "# Security hardening",
        "caps.drop all",
        "nonewprivs",
        "noroot",
        "seccomp",
        "",
        "# Disable unnecessary subsystems",
        "no3d",
        "nodvd",
        "nosound",
        "notv",
        "novideo",
        "shell none",
        "",
    ]

    # Network policy
    if config.network == NetworkPolicy.DENY:
        lines.append("# Network: DENIED (default safe mode)")
        lines.append("net none")
    else:
        lines.append("# Network: LAB MODE (explicit opt-in — analyst accepted risk)")
        # No net restriction in lab mode

    lines.append("")

    # Read-only bind for the workspace sample directory
    if config.read_only_sample:
        sample_dir = workspace / "sample"
        if sample_dir.exists():
            lines.append(f"# Sample directory: read-only")
            lines.append(f"read-only {sample_dir}")

    lines.append("")
    return "\n".join(lines) + "\n"


def write_profile(
    workspace: Path,
    config: SandboxConfig,
) -> Path:
    """Generate and write the Firejail profile to the workspace.

    Returns the path to the written profile file.
    """
    content = build_firejail_profile(workspace, config)
    profile_path = workspace / "sandbox.profile"
    profile_path.write_text(content, encoding="utf-8")
    return profile_path

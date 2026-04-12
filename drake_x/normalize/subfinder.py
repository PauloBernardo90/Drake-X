"""Parse ProjectDiscovery subfinder ``-silent`` output into an artifact.

subfinder with ``-silent`` emits one fully qualified subdomain per line
on stdout and nothing else. The normalizer:

- splits stdout into unique FQDNs (case-folded to lowercase)
- keeps only names that look like valid DNS labels ending in the
  requested root (or, if the root cannot be recovered, any plausibly
  valid FQDN)
- returns an :class:`Artifact` of kind ``dns.subdomains`` whose payload
  contains ``{"subdomains": [...], "count": N}``

The normalizer is intentionally conservative: no inference about whether
subdomains resolve, are live, or belong to the target. Those claims
belong to downstream stages (dig / httpx / dnsx) that actually observe
them.
"""

from __future__ import annotations

import re
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult

# Narrow FQDN validator: labels of 1–63 LDH chars separated by dots, at
# least two labels. We do not attempt IDN decoding here — subfinder
# already emits A-labels.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _root_from_command(command: list[str] | None) -> str | None:
    if not command:
        return None
    for i, tok in enumerate(command):
        if tok == "-d" and i + 1 < len(command):
            return command[i + 1].strip().lower() or None
    return None


def normalize_subfinder(result: ToolResult) -> Artifact:
    text = (result.stdout or "").strip()
    notes: list[str] = []

    if not text:
        return Artifact(
            tool_name="subfinder",
            kind="dns.subdomains",
            payload={"subdomains": [], "count": 0, "root": _root_from_command(result.command)},
            confidence=0.0,
            notes=["empty subfinder output"],
            raw_command=result.command,
        )

    root = _root_from_command(result.command)
    seen: set[str] = set()
    ordered: list[str] = []
    malformed = 0

    for line in text.splitlines():
        candidate = line.strip().lower()
        if not candidate:
            continue
        if not _FQDN_RE.match(candidate):
            malformed += 1
            continue
        if root is not None and not (
            candidate == root or candidate.endswith("." + root)
        ):
            # Drop rows that don't belong to the requested root. This
            # protects against any upstream oddity leaking unrelated names.
            malformed += 1
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)

    payload: dict[str, Any] = {
        "subdomains": ordered,
        "count": len(ordered),
        "root": root,
    }

    if malformed:
        notes.append(
            f"{malformed} subfinder output line(s) discarded "
            "(not a valid FQDN under the requested root)"
        )

    if ordered:
        confidence = 0.9
    else:
        confidence = 0.2
        notes.append("no subdomains parsed from subfinder output")

    return Artifact(
        tool_name="subfinder",
        kind="dns.subdomains",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:1500],
    )

"""Parse ``dig +noall +answer`` output into DNS record sets."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult

# A `dig +noall +answer` line looks like:
#   example.com.            300     IN      A       93.184.216.34
# We tolerate variable whitespace.


def normalize_dig(result: ToolResult) -> Artifact:
    records: dict[str, list[str]] = defaultdict(list)
    notes: list[str] = []

    if not result.stdout.strip():
        return Artifact(
            tool_name="dig",
            kind="dns.records",
            payload={"records": {}},
            confidence=0.0,
            notes=["empty dig output"],
            raw_command=result.command,
        )

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        rtype = parts[3]
        rdata = " ".join(parts[4:])
        if rdata and rdata not in records[rtype]:
            records[rtype].append(rdata)

    payload: dict[str, Any] = {"records": dict(records)}
    confidence = 0.9 if records else 0.3
    if not records:
        notes.append("no DNS records parsed")

    return Artifact(
        tool_name="dig",
        kind="dns.records",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=result.stdout[:1500],
    )

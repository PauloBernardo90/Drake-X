"""Best-effort WHOIS parser.

WHOIS output varies wildly between registries. We try a small set of common
keys and otherwise hand the analyst a low-confidence "raw" payload.
"""

from __future__ import annotations

import re
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult

_KEY_PATTERNS: dict[str, re.Pattern[str]] = {
    "registrar": re.compile(r"^\s*Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "creation_date": re.compile(
        r"^\s*(?:Creation Date|created|Registered On)\s*[:.]?\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "expiration_date": re.compile(
        r"^\s*(?:Registry Expiry Date|Expiration Date|paid-till)\s*[:.]?\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "updated_date": re.compile(
        r"^\s*(?:Updated Date|last-updated)\s*[:.]?\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "org": re.compile(
        r"^\s*(?:Registrant Organization|Organization|OrgName)\s*[:.]?\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    "country": re.compile(
        r"^\s*(?:Registrant Country|Country)\s*[:.]?\s*(.+)$",
        re.IGNORECASE | re.MULTILINE,
    ),
}

_NS_PATTERN = re.compile(r"^\s*(?:Name Server|nserver)\s*[:.]?\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def normalize_whois(result: ToolResult) -> Artifact:
    text = result.stdout or ""
    payload: dict[str, Any] = {}
    notes: list[str] = []

    for key, pattern in _KEY_PATTERNS.items():
        m = pattern.search(text)
        if m:
            payload[key] = m.group(1).strip()

    nameservers = sorted({n.strip().lower() for n in _NS_PATTERN.findall(text) if n.strip()})
    if nameservers:
        payload["nameservers"] = nameservers

    confidence = 0.7 if payload else 0.2
    if not payload:
        notes.append("no recognized WHOIS fields")

    return Artifact(
        tool_name="whois",
        kind="whois.summary",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:1500],
    )

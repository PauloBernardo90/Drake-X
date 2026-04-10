"""Parse ffuf ``-json`` output into a structured artifact.

ffuf with ``-json`` and ``-s`` emits one JSON object per discovered
result on stdout (one line per hit). Each line contains:

- ``input.FUZZ`` — the word that triggered the match
- ``url`` — the full URL probed
- ``status`` — HTTP response status code
- ``length`` — response body length in bytes
- ``words`` — word count in the body
- ``lines`` — line count in the body
- ``content-type`` — response Content-Type
- ``redirectlocation`` — Location header if the response was a redirect
- ``host`` — the target host

The normalizer collects all hits into a single artifact whose payload
lists discovered paths and their response metadata.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult


def normalize_ffuf(result: ToolResult) -> Artifact:
    text = (result.stdout or "").strip()
    notes: list[str] = []

    if not text:
        return Artifact(
            tool_name="ffuf",
            kind="web.content_discovery",
            payload={"hits": [], "hit_count": 0},
            confidence=0.0,
            notes=["empty ffuf output"],
            raw_command=result.command,
        )

    hits: list[dict[str, Any]] = []
    parse_errors = 0

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if not isinstance(obj, dict):
            parse_errors += 1
            continue

        fuzz_input = ""
        input_obj = obj.get("input") or {}
        if isinstance(input_obj, dict):
            fuzz_input = input_obj.get("FUZZ", "")

        hits.append({
            "path": fuzz_input,
            "url": obj.get("url"),
            "status": obj.get("status"),
            "length": obj.get("length"),
            "words": obj.get("words"),
            "lines": obj.get("lines"),
            "content_type": obj.get("content-type"),
            "redirect": obj.get("redirectlocation"),
            "host": obj.get("host"),
        })

    if parse_errors:
        notes.append(f"{parse_errors} ffuf output line(s) could not be parsed as JSON")

    payload: dict[str, Any] = {
        "hits": hits,
        "hit_count": len(hits),
    }

    confidence = 0.85 if hits else 0.3
    if not hits:
        notes.append("no content-discovery hits in ffuf output")

    return Artifact(
        tool_name="ffuf",
        kind="web.content_discovery",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:2000],
    )

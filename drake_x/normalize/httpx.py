"""Parse ProjectDiscovery httpx ``-json`` output into a structured artifact.

httpx with ``-json`` emits one JSON object per target on stdout. We
expect a single object because the Drake-X wrapper always passes one
``-u <url>``.

The normalizer is intentionally defensive:

- empty stdout → low-confidence artifact with a note
- garbage stdout → low-confidence artifact pointing at the raw excerpt
- partial fields → fields are forwarded as-is, missing ones become ``None``

The companion :mod:`drake_x.normalize.headers` audit consumes this
artifact (or curl's ``web.http_meta``) to produce structured findings.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult


def normalize_httpx(result: ToolResult) -> Artifact:
    text = (result.stdout or "").strip()
    notes: list[str] = []

    if not text:
        return Artifact(
            tool_name="httpx",
            kind="web.http_probe",
            payload={},
            confidence=0.0,
            notes=["empty httpx output"],
            raw_command=result.command,
        )

    record = _first_json_object(text)
    if record is None:
        return Artifact(
            tool_name="httpx",
            kind="web.http_probe",
            payload={},
            confidence=0.0,
            notes=["no JSON object parsed from httpx output"],
            raw_command=result.command,
            raw_stdout_excerpt=text[:1500],
        )

    headers = _normalize_headers(record)

    payload: dict[str, Any] = {
        "url": record.get("url"),
        "input": record.get("input"),
        "host": record.get("host"),
        "scheme": record.get("scheme"),
        "port": _coerce_int(record.get("port")),
        "method": record.get("method"),
        "status_code": _coerce_int(record.get("status_code")),
        "title": record.get("title"),
        "webserver": record.get("webserver"),
        "content_type": record.get("content_type"),
        "content_length": _coerce_int(record.get("content_length")),
        "technologies": _ensure_str_list(record.get("tech")),
        "addresses": _ensure_str_list(record.get("a")),
        "cnames": _ensure_str_list(record.get("cname") or record.get("cnames")),
        "chain_status_codes": _ensure_int_list(record.get("chain_status_codes")),
        "location": record.get("location"),
        "response_time": record.get("response_time"),
        "headers": headers,
    }

    if payload["status_code"] is None:
        notes.append("httpx response had no status_code field")
        confidence = 0.4
    elif not headers:
        notes.append("httpx response carried no parsed headers")
        confidence = 0.7
    else:
        confidence = 0.9

    return Artifact(
        tool_name="httpx",
        kind="web.http_probe",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:1500],
    )


# ----- helpers ---------------------------------------------------------------


def _first_json_object(text: str) -> dict[str, Any] | None:
    """Return the first JSON object found in ``text``.

    httpx normally emits one JSON object per line. We try line-by-line
    first, then fall back to extracting the first balanced ``{...}``
    block in case the output is glued together.
    """
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
        if isinstance(obj, dict):
            return obj
    return None


def _normalize_headers(record: dict[str, Any]) -> dict[str, str]:
    """Return a flat ``{lowercase-name: value}`` dict.

    httpx represents headers in two slightly different shapes depending
    on the version:

    - newer builds: ``"header": {"server": "nginx", ...}``
    - older builds: ``"headers": {"Server": "nginx", ...}``

    Both branches collapse to a lowercase-keyed dict so the headers
    audit doesn't have to know which version produced the data.
    """
    raw = record.get("header") or record.get("headers") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if k is None:
            continue
        key = str(k).lower()
        if isinstance(v, list):
            # Some httpx versions emit list-valued headers (e.g. set-cookie).
            # Join with `, ` so downstream audits see every value.
            out[key] = ", ".join(str(x) for x in v)
        else:
            out[key] = str(v)
    return out


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ensure_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if v is not None]


def _ensure_int_list(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for v in value:
        coerced = _coerce_int(v)
        if coerced is not None:
            out.append(coerced)
    return out

"""OpenAPI / Swagger spec parser → ``api.inventory`` artifact.

This is a pure-Python parser that reads a local JSON or YAML file and
extracts:

- every ``path`` + ``method`` combination
- parameters (query, path, header, cookie)
- request body content types
- security scheme references
- server URLs

The parser intentionally avoids resolving ``$ref`` pointers across files.
It covers the common case — a single self-contained spec — and degrades
gracefully on partial or non-standard specs by producing what it can and
dropping the rest with a note.

Supports both OpenAPI 3.x and Swagger 2.x layouts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..exceptions import DrakeXError
from ..models.artifact import Artifact

try:
    import yaml as _yaml  # type: ignore[import-not-found]
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


class SpecParseError(DrakeXError):
    """Raised when the spec file cannot be read or is malformed."""


def parse_openapi_file(path: Path) -> Artifact:
    """Read a local OpenAPI/Swagger spec and return an ``api.inventory`` artifact."""
    if not path.exists():
        raise SpecParseError(f"spec file not found: {path}")

    text = path.read_text(encoding="utf-8")
    data = _load_json_or_yaml(text, path)

    if not isinstance(data, dict):
        raise SpecParseError(f"spec root must be a mapping, got {type(data).__name__}")

    info = data.get("info") or {}
    title = info.get("title", "(untitled)")
    version = info.get("version", "?")
    spec_version = data.get("openapi") or data.get("swagger") or "unknown"
    servers = _extract_servers(data)
    security_schemes = _extract_security_schemes(data)
    endpoints = _extract_endpoints(data)

    notes: list[str] = []
    if not endpoints:
        notes.append("no endpoints found in spec")

    payload: dict[str, Any] = {
        "spec_file": str(path),
        "spec_version": spec_version,
        "title": title,
        "api_version": version,
        "servers": servers,
        "security_schemes": list(security_schemes.keys()),
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }

    confidence = 0.9 if endpoints else 0.3

    return Artifact(
        tool_name="openapi_parser",
        kind="api.inventory",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=["openapi_parser", str(path)],
        raw_stdout_excerpt=text[:2000],
    )


# ----- internals -------------------------------------------------------------


def _load_json_or_yaml(text: str, path: Path) -> Any:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecParseError(f"invalid JSON in {path}: {exc}") from exc

    if _HAS_YAML:
        try:
            return _yaml.safe_load(text)
        except Exception as exc:
            raise SpecParseError(f"invalid YAML in {path}: {exc}") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SpecParseError(
            f"spec is not JSON and PyYAML is not installed to try YAML: {exc}"
        ) from exc


def _extract_servers(data: dict[str, Any]) -> list[str]:
    # OpenAPI 3.x
    servers = data.get("servers")
    if isinstance(servers, list) and servers:
        return [s.get("url", "") for s in servers if isinstance(s, dict)]
    # Swagger 2.x style
    host = data.get("host", "")
    base = data.get("basePath", "")
    schemes = data.get("schemes") or ["https"]
    if host:
        return [f"{s}://{host}{base}" for s in schemes]
    return []


def _extract_security_schemes(data: dict[str, Any]) -> dict[str, Any]:
    # OpenAPI 3.x: components.securitySchemes
    components = data.get("components")
    if isinstance(components, dict):
        schemes = components.get("securitySchemes") or {}
        if isinstance(schemes, dict) and schemes:
            return schemes
    # Swagger 2.x: top-level securityDefinitions
    defs = data.get("securityDefinitions")
    if isinstance(defs, dict) and defs:
        return defs
    return {}


def _extract_endpoints(data: dict[str, Any]) -> list[dict[str, Any]]:
    paths = data.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    endpoints: list[dict[str, Any]] = []
    http_methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, detail in methods.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(detail, dict):
                continue
            ep: dict[str, Any] = {
                "path": path,
                "method": method.upper(),
                "summary": detail.get("summary") or detail.get("description", ""),
                "operation_id": detail.get("operationId"),
                "tags": detail.get("tags") or [],
                "parameters": _extract_parameters(detail, methods),
                "request_body_types": _extract_request_body_types(detail),
                "security": detail.get("security") or [],
                "deprecated": bool(detail.get("deprecated", False)),
            }
            endpoints.append(ep)

    return endpoints


def _extract_parameters(detail: dict[str, Any], path_item: dict[str, Any]) -> list[dict[str, str]]:
    """Merge path-level and operation-level parameters."""
    params: list[dict[str, str]] = []
    seen: set[str] = set()
    for param in (detail.get("parameters") or []) + (path_item.get("parameters") or []):
        if not isinstance(param, dict):
            continue
        name = param.get("name", "")
        in_ = param.get("in", "")
        key = f"{in_}:{name}"
        if key in seen:
            continue
        seen.add(key)
        params.append({
            "name": name,
            "in": in_,
            "required": str(param.get("required", False)).lower(),
        })
    return params


def _extract_request_body_types(detail: dict[str, Any]) -> list[str]:
    """Return the content types accepted by the request body."""
    body = detail.get("requestBody") or {}
    if not isinstance(body, dict):
        return []
    content = body.get("content") or {}
    if isinstance(content, dict):
        return list(content.keys())
    # Swagger 2.x: consumes at operation or root level
    consumes = detail.get("consumes") or []
    return list(consumes) if isinstance(consumes, list) else []

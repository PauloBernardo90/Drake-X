"""Engagement scope file loader.

Drake-X's scope file is plain YAML by convention but we read it via the
standard library's ``json`` parser as a fallback when PyYAML is not
installed. The schema is small and self-contained, so a tiny hand-rolled
YAML reader covers the common subset we need.

We deliberately avoid hard-failing if PyYAML is missing — operators on
locked-down Kali installations should be able to use Drake-X without an
extra dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..exceptions import ScopeFileError
from ..models.scope import ScopeAsset, ScopeFile

try:  # pragma: no cover - optional import
    import yaml as _yaml  # type: ignore[import-not-found]

    _HAS_YAML = True
except ImportError:  # pragma: no cover - tested on hosts without PyYAML
    _HAS_YAML = False


DEFAULT_SCOPE_TEMPLATE = """\
# Drake-X engagement scope file.
#
# This file is the operator's authoritative declaration of what is in
# bounds for this engagement. Drake-X refuses to act on any target not
# matched by an in_scope rule, regardless of CLI flags.
#
# Tighten this file BEFORE you run any active recon.

engagement: example-engagement
authorization_reference: "REPLACE-ME (PO #, ticket, signed letter ID)"

# Per-host request rate limit applied to integrations that honor it.
rate_limit_per_host_rps: 5.0

# Maximum integrations the engine will run in parallel.
max_concurrency: 4

# Active modules are refused unless this is set to true. Even then,
# Drake-X still requires interactive confirmation per active run.
allow_active: false

in_scope:
  - kind: domain
    value: example.com
    notes: "Primary marketing site"
  - kind: wildcard_domain
    value: example.com
    notes: "All *.example.com hosts"
  # - kind: cidr
  #   value: 198.51.100.0/24
  # - kind: url_prefix
  #   value: https://api.example.com/v2/

out_of_scope:
  - kind: wildcard_domain
    value: corp.example.com
    notes: "Internal corporate; not in this engagement"
  # - kind: ipv4
  #   value: 198.51.100.42
"""


def write_scope_template(path: Path) -> None:
    """Write the default scope template to ``path``.

    Refuses to overwrite an existing file so we never trash an operator's
    in-progress scope.
    """
    if path.exists():
        raise ScopeFileError(f"refusing to overwrite existing scope file at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DEFAULT_SCOPE_TEMPLATE, encoding="utf-8")


def load_scope_file(path: Path) -> ScopeFile:
    """Read and validate a scope file from disk."""
    if not path.exists():
        raise ScopeFileError(f"scope file not found: {path}")
    text = path.read_text(encoding="utf-8")
    data = _parse_yaml_or_json(text, path=path)
    if not isinstance(data, dict):
        raise ScopeFileError(f"scope file root must be a mapping, got {type(data).__name__}")

    try:
        return ScopeFile.model_validate(_normalize_scope_payload(data))
    except Exception as exc:  # noqa: BLE001 — re-wrap pydantic errors uniformly
        raise ScopeFileError(f"invalid scope file at {path}: {exc}") from exc


def save_scope_file(scope: ScopeFile, path: Path) -> None:
    """Write a scope back to disk as JSON (always parseable, no PyYAML required).

    YAML round-tripping is intentionally not supported — operators may have
    formatting/comments we should not silently lose. ``save_scope_file`` is
    only for programmatic snapshots (e.g. the per-session audit copy).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = scope.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


# ----- internals -------------------------------------------------------------


def _parse_yaml_or_json(text: str, *, path: Path) -> Any:
    # Fast path: JSON is a strict subset of YAML 1.2 and ``save_scope_file``
    # always writes JSON. Trying it first means PyYAML is not required for
    # programmatic round-trips.
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    if _HAS_YAML:
        try:
            return _yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise ScopeFileError(f"invalid YAML in {path}: {exc}") from exc

    # Fallback: a permissive line-based reader for the small subset we ship
    # in the template. If a user writes anything fancier, ask them to install
    # PyYAML rather than guess.
    try:
        return _tiny_yaml_load(text)
    except Exception as exc:  # noqa: BLE001
        raise ScopeFileError(
            f"PyYAML is not installed and the fallback parser could not read {path}: {exc}. "
            "Install pyyaml or simplify the file."
        ) from exc


def _tiny_yaml_load(text: str) -> dict[str, Any]:
    """A *very* small YAML subset reader.

    Supports the shape of :data:`DEFAULT_SCOPE_TEMPLATE`:
    ``key: value`` lines, integer/float/bool/null/string scalars, and lists
    of dicts introduced by ``- key: value``.
    """
    root: dict[str, Any] = {}
    current_list: list[dict[str, Any]] | None = None
    current_list_key: str | None = None
    current_item: dict[str, Any] | None = None

    def _coerce(raw: str) -> Any:
        s = raw.strip()
        if s == "":
            return ""
        if s.startswith(("'", '"')) and s.endswith(s[0]) and len(s) >= 2:
            return s[1:-1]
        lower = s.lower()
        if lower in {"true", "yes"}:
            return True
        if lower in {"false", "no"}:
            return False
        if lower in {"null", "~"}:
            return None
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return float(s)
        except ValueError:
            pass
        return s

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("- "):
            inner = stripped[2:].strip()
            if current_list is None or current_list_key is None:
                raise ValueError("list item with no parent key")
            current_item = {}
            current_list.append(current_item)
            if inner:
                k, _, v = inner.partition(":")
                current_item[k.strip()] = _coerce(v)
            continue

        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if value == "":
                # opens a new collection
                if indent == 0:
                    current_list = []
                    current_list_key = key
                    root[key] = current_list
                    current_item = None
                elif current_item is not None:
                    nested: dict[str, Any] = {}
                    current_item[key] = nested
                else:
                    # nested mapping at root level — out of our subset
                    root[key] = {}
            else:
                if indent == 0 or current_item is None:
                    root[key] = _coerce(value)
                else:
                    current_item[key] = _coerce(value)
            continue

    return root


def _strip_comment(line: str) -> str:
    """Strip ``# ...`` comments outside of quoted strings.

    This is intentionally minimal: it only tracks single and double quote
    contexts and ignores backslash escapes (the template uses neither).
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def _normalize_scope_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize a parsed scope dict into the shape Pydantic expects."""
    payload = dict(data)
    for field in ("in_scope", "out_of_scope"):
        items = payload.get(field) or []
        if not isinstance(items, list):
            raise ScopeFileError(f"{field} must be a list")
        normalized: list[ScopeAsset | dict[str, Any]] = []
        for item in items:
            if isinstance(item, dict):
                normalized.append(item)
            else:
                raise ScopeFileError(
                    f"{field} entries must be mappings with 'kind' and 'value'"
                )
        payload[field] = normalized
    return payload

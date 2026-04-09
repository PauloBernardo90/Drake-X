"""Normalizers for web-oriented tools (curl, whatweb, nikto, sslscan).

Each function returns an :class:`Artifact`. We avoid raising on parser errors;
when in doubt, drop confidence and explain in ``notes``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..models.artifact import Artifact
from ..models.tool_result import ToolResult

# ----- curl ------------------------------------------------------------------

_HTTP_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})\s*(.*)$")
_HEADER_RE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.+?)\s*$")


def normalize_curl(result: ToolResult) -> Artifact:
    notes: list[str] = []
    hops: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    headers_block: dict[str, str] = {}

    for line in result.stdout.splitlines():
        line = line.rstrip("\r")
        if not line:
            if current is not None:
                current["headers"] = headers_block
                hops.append(current)
                current = None
                headers_block = {}
            continue
        m = _HTTP_STATUS_RE.match(line)
        if m:
            if current is not None:
                current["headers"] = headers_block
                hops.append(current)
            current = {"status": int(m.group(1)), "reason": m.group(2)}
            headers_block = {}
            continue
        h = _HEADER_RE.match(line)
        if h and current is not None:
            headers_block[h.group(1).lower()] = h.group(2)

    # flush
    if current is not None:
        current["headers"] = headers_block
        hops.append(current)

    payload: dict[str, Any] = {
        "hops": hops,
        "final_status": hops[-1]["status"] if hops else None,
        "final_headers": hops[-1]["headers"] if hops else {},
        "redirect_chain": [h.get("headers", {}).get("location") for h in hops if h.get("headers", {}).get("location")],
    }
    confidence = 0.9 if hops else 0.2
    if not hops:
        notes.append("no HTTP responses parsed from curl")

    return Artifact(
        tool_name="curl",
        kind="web.http_meta",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=result.stdout[:1500],
    )


# ----- whatweb ---------------------------------------------------------------


def normalize_whatweb(result: ToolResult) -> Artifact:
    notes: list[str] = []
    plugins: dict[str, Any] = {}
    technologies: list[str] = []
    target_url: str | None = None
    payload: dict[str, Any] = {}

    text = (result.stdout or "").strip()

    if text:
        # whatweb --log-json prints one JSON object per target.
        # If multiple, take the first that parses cleanly.
        for chunk in text.splitlines():
            chunk = chunk.strip().rstrip(",")
            if not chunk:
                continue
            try:
                obj = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            target_url = obj.get("target")
            plugins = obj.get("plugins", {}) or {}
            break

        if not plugins:
            # Try to parse the whole blob as a JSON array (some versions do this).
            try:
                arr = json.loads(text)
                if isinstance(arr, list) and arr:
                    target_url = arr[0].get("target")
                    plugins = arr[0].get("plugins", {}) or {}
            except json.JSONDecodeError:
                pass

    for name, info in plugins.items():
        if not name:
            continue
        version = None
        if isinstance(info, dict) and isinstance(info.get("version"), list) and info["version"]:
            version = info["version"][0]
        technologies.append(f"{name} {version}".strip() if version else name)

    payload = {
        "target": target_url,
        "technologies": sorted(set(technologies)),
        "plugin_count": len(plugins),
    }
    confidence = 0.85 if plugins else 0.3
    if not plugins:
        notes.append("no whatweb plugin data parsed")

    return Artifact(
        tool_name="whatweb",
        kind="web.fingerprint",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:1500] if text else None,
    )


# ----- nikto -----------------------------------------------------------------

# Nikto's text output uses lines starting with "+ " for findings. We extract
# only headline observations and DROP anything that looks like an exploit
# suggestion (e.g. SQL injection PoCs). Drake-X is not an exploit framework.
_EXPLOIT_BLOCK = re.compile(r"\b(sqli|xss|csrf|rce|exploit|payload|injection)\b", re.IGNORECASE)


def normalize_nikto(result: ToolResult) -> Artifact:
    findings: list[str] = []
    suppressed = 0
    notes: list[str] = []

    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        text = line[2:].strip()
        if _EXPLOIT_BLOCK.search(text):
            suppressed += 1
            continue
        findings.append(text)

    payload = {
        "headline_findings": findings,
        "finding_count": len(findings),
        "suppressed_exploit_suggestions": suppressed,
    }
    confidence = 0.7 if findings else 0.3
    if not findings:
        notes.append("no nikto headline findings parsed")
    if suppressed:
        notes.append(
            f"suppressed {suppressed} nikto lines that resembled exploit suggestions; "
            "Drake-X intentionally only surfaces information-only observations"
        )

    return Artifact(
        tool_name="nikto",
        kind="web.posture",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=(result.stdout or "")[:1500],
    )


# ----- sslscan ---------------------------------------------------------------


def normalize_sslscan(result: ToolResult) -> Artifact:
    text = result.stdout or ""
    notes: list[str] = []
    protocols: dict[str, str] = {}
    weak_ciphers: list[str] = []
    cert: dict[str, Any] = {}

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Protocol lines look like: "SSLv3     disabled" / "TLSv1.2   enabled"
        m = re.match(r"^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)\b", s)
        if m:
            protocols[m.group(1)] = m.group(2)
            continue
        # Cipher lines often start with "Accepted" or "Preferred".
        if s.startswith(("Accepted", "Preferred")) and ("RC4" in s or "DES" in s or "EXPORT" in s or "NULL" in s or "MD5" in s):
            weak_ciphers.append(s)
            continue
        # Cert subject/issuer lines.
        if s.startswith("Subject:"):
            cert["subject"] = s.split(":", 1)[1].strip()
        elif s.startswith("Issuer:"):
            cert["issuer"] = s.split(":", 1)[1].strip()
        elif s.startswith("Not valid before:"):
            cert["not_before"] = s.split(":", 1)[1].strip()
        elif s.startswith("Not valid after:"):
            cert["not_after"] = s.split(":", 1)[1].strip()

    enabled_protocols = sorted(p for p, state in protocols.items() if state == "enabled")
    deprecated_enabled = [p for p in enabled_protocols if p in {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}]

    payload: dict[str, Any] = {
        "protocols": protocols,
        "enabled_protocols": enabled_protocols,
        "deprecated_enabled": deprecated_enabled,
        "weak_cipher_lines": weak_ciphers,
        "certificate": cert,
    }
    confidence = 0.85 if protocols else 0.3
    if not protocols:
        notes.append("no protocol lines parsed from sslscan")

    return Artifact(
        tool_name="sslscan",
        kind="tls.summary",
        payload=payload,
        confidence=confidence,
        notes=notes,
        raw_command=result.command,
        raw_stdout_excerpt=text[:1500],
    )

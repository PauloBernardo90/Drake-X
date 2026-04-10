"""VirusTotal v3 API enrichment client (opt-in, read-only).

This client performs a **hash lookup only** — it never uploads samples.
It queries the VT v3 ``/files/{sha256}`` endpoint and parses the
response into a :class:`VtEnrichment` model.

Design principles:

- **Opt-in.** Requires a non-empty ``vt_api_key`` in workspace config.
- **Read-only.** GET request by SHA-256 — no POST, no upload, no submit.
- **Degradation-safe.** Returns a ``VtEnrichment(available=False)`` on
  any error (missing key, network failure, rate limit, bad response).
- **No secrets in output.** The API key is never logged or persisted
  in findings.
- **Local-first compatible.** The pipeline runs fully without VT; this
  is an optional enrichment layer.
"""

from __future__ import annotations

import json
from typing import Any

from ...logging import get_logger
from ...models.apk import VtEnrichment

log = get_logger("virustotal")

VT_API_BASE = "https://www.virustotal.com/api/v3"


def lookup_sha256(sha256: str, *, api_key: str) -> VtEnrichment:
    """Query VT v3 for a file hash. Returns enrichment or a safe fallback."""
    if not api_key:
        return VtEnrichment(available=False, sha256=sha256, error="no API key configured")
    if not sha256 or len(sha256) != 64:
        return VtEnrichment(available=False, sha256=sha256, error="invalid SHA-256")

    try:
        import httpx
    except ImportError:
        return VtEnrichment(available=False, sha256=sha256, error="httpx not installed")

    url = f"{VT_API_BASE}/files/{sha256}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = httpx.get(url, headers=headers, timeout=30.0)
    except (httpx.HTTPError, OSError) as exc:
        log.warning("VT lookup failed for %s: %s", sha256[:12], exc)
        return VtEnrichment(available=False, sha256=sha256, error=f"network error: {exc}")

    if resp.status_code == 404:
        return VtEnrichment(available=True, sha256=sha256, error="hash not found on VirusTotal")
    if resp.status_code == 429:
        return VtEnrichment(available=False, sha256=sha256, error="VT rate limit exceeded")
    if resp.status_code != 200:
        return VtEnrichment(
            available=False, sha256=sha256,
            error=f"VT returned HTTP {resp.status_code}",
        )

    try:
        data = resp.json()
    except json.JSONDecodeError:
        return VtEnrichment(available=False, sha256=sha256, error="invalid JSON response")

    return _parse_vt_response(sha256, data)


def _parse_vt_response(sha256: str, data: dict[str, Any]) -> VtEnrichment:
    """Parse VT v3 /files response into our model."""
    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        return VtEnrichment(available=True, sha256=sha256, error="empty attributes in response")

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    undetected = stats.get("undetected", 0)
    total = sum(stats.values()) if stats else 0

    results = attrs.get("last_analysis_results", {})
    top_detections: list[dict[str, str]] = []
    for engine, info in sorted(results.items()):
        if isinstance(info, dict) and info.get("category") == "malicious":
            top_detections.append({
                "engine": engine,
                "result": info.get("result", ""),
            })
            if len(top_detections) >= 10:
                break

    threat_label = attrs.get("popular_threat_classification", {})
    popular = ""
    suggested = ""
    if isinstance(threat_label, dict):
        popular = threat_label.get("popular_threat_name", [{}])
        if isinstance(popular, list) and popular:
            popular = popular[0].get("value", "")
        else:
            popular = ""
        suggested = threat_label.get("suggested_threat_label", "")

    return VtEnrichment(
        available=True,
        sha256=sha256,
        detection_ratio=f"{malicious}/{total}",
        detections=malicious,
        total_engines=total,
        scan_date=str(attrs.get("last_analysis_date", "")),
        popular_threat_label=str(popular),
        suggested_threat_label=str(suggested),
        tags=attrs.get("tags", []) if isinstance(attrs.get("tags"), list) else [],
        top_detections=top_detections,
    )

"""VirusTotal v3 IoC enrichment: domain and IP lookups.

Queries VT v3 ``/domains/{domain}`` and ``/ip_addresses/{ip}`` endpoints.
Read-only, opt-in, and degradation-safe.
"""

from __future__ import annotations

import json
import time
from typing import Any

from ...logging import get_logger
from ...models.ioc_enrichment import IocEnrichmentResult, IocVtResult

log = get_logger("vt_ioc")

VT_API_BASE = "https://www.virustotal.com/api/v3"


def lookup_domain(domain: str, *, api_key: str) -> IocVtResult:
    """Query VT v3 for a domain."""
    return _lookup(domain, "domain", f"{VT_API_BASE}/domains/{domain}", api_key=api_key)


def lookup_ip(ip: str, *, api_key: str) -> IocVtResult:
    """Query VT v3 for an IP address."""
    return _lookup(ip, "ip", f"{VT_API_BASE}/ip_addresses/{ip}", api_key=api_key)


def enrich_indicators(
    *,
    domains: list[str],
    ips: list[str],
    api_key: str,
    max_indicators: int = 20,
    rate_delay: float = 0.5,
) -> IocEnrichmentResult:
    """Enrich a set of domains and IPs via VT. Respects rate limits."""
    if not api_key:
        return IocEnrichmentResult(
            skipped=len(domains) + len(ips),
            errors=0,
        )

    result = IocEnrichmentResult()
    count = 0

    for domain in domains[:max_indicators]:
        if count > 0:
            time.sleep(rate_delay)
        r = lookup_domain(domain, api_key=api_key)
        result.domain_results.append(r)
        if r.error:
            result.errors += 1
        count += 1

    for ip in ips[:max_indicators - len(domains)]:
        if count > 0:
            time.sleep(rate_delay)
        r = lookup_ip(ip, api_key=api_key)
        result.ip_results.append(r)
        if r.error:
            result.errors += 1
        count += 1

    remaining = (len(domains) + len(ips)) - count
    if remaining > 0:
        result.skipped = remaining

    return result


def _lookup(indicator: str, ioc_type: str, url: str, *, api_key: str) -> IocVtResult:
    if not api_key:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error="no API key")

    try:
        import httpx
    except ImportError:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error="httpx not installed")

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = httpx.get(url, headers=headers, timeout=15.0)
    except (httpx.HTTPError, OSError) as exc:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error=f"network: {exc}")

    if resp.status_code == 404:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, available=True, error="not found on VT")
    if resp.status_code == 429:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error="rate limited")
    if resp.status_code != 200:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error=f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except json.JSONDecodeError:
        return IocVtResult(indicator=indicator, indicator_type=ioc_type, error="invalid JSON")

    return _parse_response(indicator, ioc_type, data)


def _parse_response(indicator: str, ioc_type: str, data: dict[str, Any]) -> IocVtResult:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    categories = []
    cats = attrs.get("categories", {})
    if isinstance(cats, dict):
        categories = list(set(cats.values()))

    return IocVtResult(
        indicator=indicator,
        indicator_type=ioc_type,
        available=True,
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        reputation=attrs.get("reputation"),
        categories=categories[:10],
        tags=attrs.get("tags", [])[:10] if isinstance(attrs.get("tags"), list) else [],
        as_owner=attrs.get("as_owner", ""),
        last_modification_date=str(attrs.get("last_modification_date", "")),
    )

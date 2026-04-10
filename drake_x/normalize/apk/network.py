"""Extract network indicators (URLs, domains, IPs) from text corpora."""

from __future__ import annotations

import re

from ...models.apk import NetworkIndicator

_URL_RE = re.compile(r'https?://[^\s\'"<>(){}\[\]]+', re.I)
_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Common false-positive domains to filter
_IGNORE_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "ns.adobe.com",
    "xmlpull.org",
    "xml.org",
    "apache.org",
    "javax.xml",
    "127.0.0.1",
    "0.0.0.0",
    "localhost",
}


def extract_network_indicators(
    text: str, *, source_label: str = ""
) -> list[NetworkIndicator]:
    """Extract URLs and IPs from *text*, filtering common false positives."""
    indicators: list[NetworkIndicator] = []
    seen: set[str] = set()

    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip("/.,;:)")
        if url in seen:
            continue
        seen.add(url)
        if _is_noise(url):
            continue
        indicators.append(NetworkIndicator(
            value=url,
            indicator_type="url",
            source_file=source_label,
        ))

    for m in _IP_RE.finditer(text):
        ip = m.group(1)
        if ip in seen or ip.startswith(("0.", "127.", "10.", "192.168.", "255.")):
            continue
        # Basic validation: each octet 0-255
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            seen.add(ip)
            indicators.append(NetworkIndicator(
                value=ip,
                indicator_type="ip",
                source_file=source_label,
            ))

    return indicators


def _is_noise(url: str) -> bool:
    lower = url.lower()
    for d in _IGNORE_DOMAINS:
        if d in lower:
            return True
    return False

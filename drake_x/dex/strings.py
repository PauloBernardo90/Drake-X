"""String classifier — categorize strings extracted from DEX files.

Classifies raw strings into security-relevant categories:
URLs, IPs, domains, IoCs, crypto artifacts, encoded blobs,
phishing indicators, package targets, C2 indicators, filesystem
paths, and shell commands.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address

from ..logging import get_logger
from ..models.dex import ClassifiedString, StringCategory

log = get_logger("dex.strings")

# ---------------------------------------------------------------------------
# Classification regexes
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s'\"<>(){}\[\]]{4,}", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"(?:com|net|org|info|biz|ru|cn|top|xyz|tk|pw|cc|ws|io|me|co|"
    r"onion|su|pro|mobi|club|online|site|live|app|dev))\b",
    re.I,
)
_B64_BLOB_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
_HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_CRYPTO_RE = re.compile(
    r"AES|DES|RSA|Blowfish|RC4|SHA-?256|SHA-?512|MD5|HMAC|PBKDF|"
    r"BEGIN.*KEY|BEGIN.*CERTIFICATE",
    re.I,
)
_PHISHING_RE = re.compile(
    r"card.?number|cvv|expir|pin.?code|login.?bank|verify.?account|"
    r"confirm.?identity|security.?update|your.?account|"
    r"google.?play|play\.google|update.?required|system.?update",
    re.I,
)
_PACKAGE_RE = re.compile(
    r"^(com\.|org\.|net\.|io\.|me\.|br\.|de\.)[a-z][a-z0-9_.]{4,}$"
)
_C2_RE = re.compile(
    r"/gate\.php|/panel/|/bot|/c2/|/command|/beacon|"
    r"User-Agent:.*bot|callback|heartbeat|check-?in|"
    r"register.*device|upload.*data|exfil",
    re.I,
)
_FS_PATH_RE = re.compile(
    r"^/(?:data|sdcard|storage|system|proc|etc|tmp|mnt)/", re.I
)
_COMMAND_RE = re.compile(
    r"^(?:su|sh|chmod|chown|mount|pm\s|am\s|dumpsys|getprop|setprop|"
    r"cat\s|ls\s|cp\s|mv\s|rm\s|kill|iptables|busybox)",
    re.I,
)

# False positives to skip
_IGNORE_DOMAINS = {
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "xmlpull.org",
    "xml.org", "apache.org", "javax.xml", "google.com",
    "android.com", "googleapis.com", "gstatic.com",
}
_IGNORE_PREFIXES = (
    "android.", "java.", "javax.", "dalvik.", "kotlin.",
    "androidx.", "com.google.android.", "com.android.",
)

_MIN_INTERESTING_LENGTH = 6


def classify_strings(
    strings: list[str],
    *,
    source_dex: str = "",
) -> list[ClassifiedString]:
    """Classify a list of raw strings into security-relevant categories.

    Returns only strings that match at least one classification rule.
    Generic/uninteresting strings are filtered out.
    """
    results: list[ClassifiedString] = []
    seen: set[str] = set()

    for s in strings:
        s = s.strip()
        if not s or len(s) < _MIN_INTERESTING_LENGTH or s in seen:
            continue
        seen.add(s)

        classified = _classify_one(s, source_dex)
        if classified:
            results.append(classified)

    log.debug(
        "Classified %d / %d strings from %s",
        len(results), len(strings), source_dex or "input",
    )
    return results


def _classify_one(s: str, source_dex: str) -> ClassifiedString | None:
    """Attempt to classify a single string. Returns None if uninteresting."""

    # URL
    if _URL_RE.match(s):
        if _is_noise_url(s):
            return None
        return ClassifiedString(
            value=s,
            category=StringCategory.URL,
            source_dex=source_dex,
            confidence=0.8,
            is_potential_ioc=True,
        )

    # C2 indicators (check before domain/path)
    if _C2_RE.search(s):
        return ClassifiedString(
            value=s,
            category=StringCategory.C2_INDICATOR,
            source_dex=source_dex,
            confidence=0.7,
            is_potential_ioc=True,
        )

    # IP address
    ip_match = _IP_RE.search(s)
    if ip_match and s == ip_match.group(0):
        ip = ip_match.group(1)
        if _is_interesting_ip(ip):
            return ClassifiedString(
                value=ip,
                category=StringCategory.IP,
                source_dex=source_dex,
                confidence=0.75,
                is_potential_ioc=True,
            )

    # Domain
    domain_match = _DOMAIN_RE.search(s)
    if domain_match and len(s) < 100:
        domain = domain_match.group(1).lower()
        if domain not in _IGNORE_DOMAINS:
            return ClassifiedString(
                value=domain,
                category=StringCategory.DOMAIN,
                source_dex=source_dex,
                confidence=0.65,
                is_potential_ioc=True,
            )

    # Phishing / social engineering
    if _PHISHING_RE.search(s):
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.PHISHING,
            source_dex=source_dex,
            confidence=0.7,
            is_potential_ioc=False,
        )

    # Base64 / hex blobs
    if _B64_BLOB_RE.match(s) and len(s) >= 40:
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.ENCODED_BLOB,
            source_dex=source_dex,
            confidence=0.6,
        )
    if _HEX_BLOB_RE.match(s) and len(s) >= 32:
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.ENCODED_BLOB,
            source_dex=source_dex,
            confidence=0.55,
        )

    # Crypto artifacts
    if _CRYPTO_RE.search(s):
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.CRYPTO,
            source_dex=source_dex,
            confidence=0.5,
        )

    # Package names (possible targets)
    if _PACKAGE_RE.match(s) and not _is_noise_package(s):
        return ClassifiedString(
            value=s,
            category=StringCategory.PACKAGE_TARGET,
            source_dex=source_dex,
            confidence=0.6,
            is_potential_ioc=True,
        )

    # Filesystem paths
    if _FS_PATH_RE.match(s):
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.FILESYSTEM_PATH,
            source_dex=source_dex,
            confidence=0.5,
        )

    # Shell commands
    if _COMMAND_RE.match(s):
        return ClassifiedString(
            value=s[:200],
            category=StringCategory.COMMAND,
            source_dex=source_dex,
            confidence=0.7,
            is_potential_ioc=True,
        )

    return None


def _is_noise_url(url: str) -> bool:
    """Filter common false-positive URLs."""
    lower = url.lower()
    return any(d in lower for d in _IGNORE_DOMAINS)


def _is_interesting_ip(ip: str) -> bool:
    """Filter private/reserved IPs."""
    try:
        addr = IPv4Address(ip)
        return not (addr.is_private or addr.is_loopback
                    or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def _is_noise_package(pkg: str) -> bool:
    """Filter common framework packages."""
    return any(pkg.startswith(p) for p in _IGNORE_PREFIXES)

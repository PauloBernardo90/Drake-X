"""Normalizers turn raw tool output into structured artifacts."""

from .common import normalize_result
from .dns import normalize_dig
from .ffuf import normalize_ffuf
from .httpx import normalize_httpx
from .nmap import normalize_nmap
from .web import normalize_curl, normalize_nikto, normalize_sslscan, normalize_whatweb
from .whois import normalize_whois

__all__ = [
    "normalize_result",
    "normalize_dig",
    "normalize_ffuf",
    "normalize_httpx",
    "normalize_nmap",
    "normalize_whois",
    "normalize_curl",
    "normalize_nikto",
    "normalize_sslscan",
    "normalize_whatweb",
]

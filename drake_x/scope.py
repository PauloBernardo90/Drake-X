"""Target validation, normalization, and scope-aware safety checks.

The goal of this module is to take an arbitrary user-supplied string and:

1. Reject obviously broken inputs.
2. Classify the target as IPv4, IPv6, CIDR, domain, or URL.
3. Produce a canonical :class:`drake_x.models.target.Target` object.
4. Refuse to scan things that are clearly out of scope (loopback, link-local,
   multicast, the broader RFC1122 reserved ranges, and ranges that look
   "uncomfortably big" for an opportunistic scan).

This module is intentionally conservative. When in doubt: refuse.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .constants import (
    TARGET_CIDR,
    TARGET_DOMAIN,
    TARGET_IPV4,
    TARGET_IPV6,
    TARGET_URL,
)
from .exceptions import InvalidTargetError, ScopeViolationError
from .models.target import Target

# Hostnames per RFC 1123: labels of 1-63 chars, separated by dots, total ≤ 253.
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

# Maximum CIDR sizes we'll accept by default. These are conservative — large
# scans should be planned, not opportunistic.
_MAX_IPV4_CIDR_HOSTS = 1024  # /22 and tighter
_MAX_IPV6_PREFIX = 120        # /120 and tighter (≈ 256 addresses)


def _is_valid_hostname(value: str) -> bool:
    if len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    if not value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        # Single-label hostnames are typically internal — refuse for safety.
        return False
    return all(_HOSTNAME_LABEL.match(part) for part in parts)


def _classify_ip(addr: ipaddress._BaseAddress) -> None:
    """Reject IP addresses that should never be opportunistically scanned."""
    if addr.is_loopback:
        raise ScopeViolationError(f"Refusing to scan loopback address: {addr}")
    if addr.is_unspecified:
        raise ScopeViolationError(f"Refusing to scan unspecified address: {addr}")
    if addr.is_multicast:
        raise ScopeViolationError(f"Refusing to scan multicast address: {addr}")
    if addr.is_link_local:
        raise ScopeViolationError(f"Refusing to scan link-local address: {addr}")
    if addr.is_reserved:
        raise ScopeViolationError(f"Refusing to scan reserved address: {addr}")


def _validate_ip(value: str) -> Target:
    addr = ipaddress.ip_address(value)
    _classify_ip(addr)
    target_type = TARGET_IPV4 if addr.version == 4 else TARGET_IPV6
    return Target(
        raw=value,
        canonical=str(addr),
        target_type=target_type,
        host=str(addr),
    )


def _validate_cidr(value: str) -> Target:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise InvalidTargetError(f"Invalid CIDR: {value!r}: {exc}") from exc

    # Refuse private/loopback/etc that point at the host. Allow private RFC1918
    # networks because most authorized assessments target internal lab ranges,
    # but reject anything dangerous like 0.0.0.0/0.
    if net.network_address.is_loopback:
        raise ScopeViolationError(f"Refusing CIDR that targets loopback: {net}")
    if net.network_address.is_unspecified and net.prefixlen < 8:
        raise ScopeViolationError(f"Refusing absurdly broad CIDR: {net}")
    if net.is_multicast:
        raise ScopeViolationError(f"Refusing multicast CIDR: {net}")
    if net.is_link_local:
        raise ScopeViolationError(f"Refusing link-local CIDR: {net}")

    if net.version == 4 and net.num_addresses > _MAX_IPV4_CIDR_HOSTS:
        raise ScopeViolationError(
            f"CIDR {net} contains {net.num_addresses} addresses; "
            f"max allowed is {_MAX_IPV4_CIDR_HOSTS}. Tighten the prefix."
        )
    if net.version == 6 and net.prefixlen < _MAX_IPV6_PREFIX:
        raise ScopeViolationError(
            f"IPv6 CIDR {net} is too broad (prefix /{net.prefixlen}); "
            f"minimum allowed prefix is /{_MAX_IPV6_PREFIX}."
        )

    return Target(
        raw=value,
        canonical=str(net),
        target_type=TARGET_CIDR,
        host=str(net.network_address),
        cidr_prefix=net.prefixlen,
    )


def _validate_domain(value: str) -> Target:
    domain = value.strip().rstrip(".").lower()
    if domain in {"localhost"}:
        raise ScopeViolationError(f"Refusing to scan {domain!r}")
    if not _is_valid_hostname(domain):
        raise InvalidTargetError(f"Invalid hostname: {value!r}")
    return Target(
        raw=value,
        canonical=domain,
        target_type=TARGET_DOMAIN,
        host=domain,
    )


def _validate_url(value: str) -> Target:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise InvalidTargetError(
            f"Only http(s) URLs are accepted, got scheme {parsed.scheme!r}"
        )
    if not parsed.hostname:
        raise InvalidTargetError(f"URL is missing a hostname: {value!r}")

    host = parsed.hostname.lower()

    # Host inside the URL might itself be an IP or a domain. Validate it
    # through the right path so we still get scope checks. Localhost is
    # checked first because it's a single-label name that the hostname
    # validator would otherwise reject as merely "invalid".
    if host == "localhost":
        raise ScopeViolationError(f"Refusing to scan {host!r}")
    try:
        addr = ipaddress.ip_address(host)
        _classify_ip(addr)
    except ValueError:
        if not _is_valid_hostname(host):
            raise InvalidTargetError(f"Invalid hostname inside URL: {host!r}") from None

    # Build the resource-level canonical form. We deliberately preserve the
    # query string (and fragment) so we don't silently change the resource
    # the user asked us to probe.
    path = parsed.path or "/"
    canonical = f"{parsed.scheme}://{host}"
    if parsed.port:
        canonical = f"{canonical}:{parsed.port}"
    canonical += path
    if parsed.query:
        canonical += f"?{parsed.query}"
    if parsed.fragment:
        canonical += f"#{parsed.fragment}"

    return Target(
        raw=value,
        canonical=canonical,
        target_type=TARGET_URL,
        host=host,
        url_scheme=parsed.scheme,
        url_port=parsed.port,
        url_path=path,
        url_query=parsed.query or None,
        url_fragment=parsed.fragment or None,
    )


def parse_target(value: str) -> Target:
    """Parse and validate a user-supplied target.

    Raises:
        InvalidTargetError: when the input cannot be parsed at all.
        ScopeViolationError: when the input is parseable but unsafe to scan.
    """

    if not isinstance(value, str):
        raise InvalidTargetError("Target must be a string")
    candidate = value.strip()
    if not candidate:
        raise InvalidTargetError("Target cannot be empty")

    # URL?
    if "://" in candidate:
        return _validate_url(candidate)

    # CIDR?
    if "/" in candidate:
        return _validate_cidr(candidate)

    # IP address?
    try:
        ipaddress.ip_address(candidate)
        return _validate_ip(candidate)
    except ValueError:
        pass

    # Otherwise treat as a domain.
    return _validate_domain(candidate)


__all__ = ["parse_target"]

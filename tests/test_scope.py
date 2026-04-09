"""Target parsing and scope-validation tests."""

from __future__ import annotations

import pytest

from drake_x.exceptions import InvalidTargetError, ScopeViolationError
from drake_x.scope import parse_target


class TestIPv4:
    def test_routable_ipv4_is_accepted(self) -> None:
        t = parse_target("93.184.216.34")
        assert t.target_type == "ipv4"
        assert t.canonical == "93.184.216.34"
        assert t.host == "93.184.216.34"

    def test_loopback_ipv4_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("127.0.0.1")

    def test_link_local_ipv4_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("169.254.10.5")

    def test_multicast_ipv4_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("239.255.0.1")


class TestIPv6:
    def test_routable_ipv6_is_accepted(self) -> None:
        t = parse_target("2606:4700:4700::1111")
        assert t.target_type == "ipv6"

    def test_loopback_ipv6_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("::1")


class TestCIDR:
    def test_small_ipv4_cidr_is_accepted(self) -> None:
        t = parse_target("192.0.2.0/24")
        assert t.target_type == "cidr"
        assert t.cidr_prefix == 24

    def test_huge_ipv4_cidr_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("10.0.0.0/8")

    def test_zero_cidr_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("0.0.0.0/0")

    def test_loopback_cidr_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("127.0.0.0/24")

    def test_invalid_cidr_raises_invalid(self) -> None:
        with pytest.raises(InvalidTargetError):
            parse_target("999.999.999.0/24")


class TestDomain:
    def test_valid_domain(self) -> None:
        t = parse_target("Example.COM")
        assert t.target_type == "domain"
        assert t.canonical == "example.com"
        assert t.host == "example.com"

    def test_localhost_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("localhost")

    def test_single_label_is_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            parse_target("internalbox")

    def test_empty_input_is_rejected(self) -> None:
        with pytest.raises(InvalidTargetError):
            parse_target("")

    def test_subdomain_is_accepted(self) -> None:
        t = parse_target("api.example.com")
        assert t.target_type == "domain"
        assert t.host == "api.example.com"


class TestURL:
    def test_https_url(self) -> None:
        t = parse_target("https://Example.com/login")
        assert t.target_type == "url"
        assert t.host == "example.com"
        assert t.url_scheme == "https"
        assert t.url_path == "/login"

    def test_url_with_port(self) -> None:
        t = parse_target("http://example.com:8080/")
        assert t.url_port == 8080

    def test_unsupported_scheme(self) -> None:
        with pytest.raises(InvalidTargetError):
            parse_target("ftp://example.com")

    def test_url_pointing_at_loopback_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("http://127.0.0.1/")

    def test_url_with_localhost_is_rejected(self) -> None:
        with pytest.raises(ScopeViolationError):
            parse_target("http://localhost/")

    def test_url_query_string_is_preserved(self) -> None:
        t = parse_target("https://example.com/search?q=hello&page=2")
        assert t.url_path == "/search"
        assert t.url_query == "q=hello&page=2"
        assert t.canonical == "https://example.com/search?q=hello&page=2"
        # Host-level form drops the query.
        assert t.host_canonical == "https://example.com"

    def test_url_with_explicit_port_in_canonical(self) -> None:
        t = parse_target("https://Example.com:8443/login?next=/admin")
        assert t.url_port == 8443
        assert t.host == "example.com"
        assert t.canonical == "https://example.com:8443/login?next=/admin"
        assert t.host_canonical == "https://example.com:8443"

    def test_url_fragment_is_preserved(self) -> None:
        t = parse_target("https://example.com/docs#section-3")
        assert t.url_fragment == "section-3"
        assert t.canonical == "https://example.com/docs#section-3"

    def test_url_root_canonical_uses_slash(self) -> None:
        t = parse_target("https://example.com")
        assert t.url_path == "/"
        assert t.canonical == "https://example.com/"

    def test_non_url_target_host_canonical_matches_canonical(self) -> None:
        t = parse_target("example.com")
        assert t.host_canonical == t.canonical

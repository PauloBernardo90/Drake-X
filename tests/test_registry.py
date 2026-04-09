"""Tool registry tests.

We mock :func:`shutil.which` so the tests are deterministic regardless of
which binaries are actually present on the host.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from drake_x.constants import (
    PROFILE_NETWORK_BASIC,
    PROFILE_PASSIVE,
    PROFILE_SAFE,
    PROFILE_WEB_BASIC,
)
from drake_x.registry import ToolRegistry
from drake_x.scope import parse_target


@pytest.fixture
def all_tools_present():
    with patch("drake_x.tools.base.shutil.which", return_value="/usr/bin/fake"):
        yield


@pytest.fixture
def no_tools_present():
    with patch("drake_x.tools.base.shutil.which", return_value=None):
        yield


def test_registry_lists_all_known_tools(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    names = {e.name for e in reg.all_entries()}
    assert {"nmap", "dig", "whois", "whatweb", "nikto", "curl", "sslscan"} <= names


def test_select_for_safe_profile_with_domain(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    target = parse_target("example.com")
    eligible, missing = reg.select_for(profile=PROFILE_SAFE, target=target)
    eligible_names = {e.name for e in eligible}
    assert "dig" in eligible_names
    assert "whois" in eligible_names
    assert "curl" in eligible_names
    assert missing == []


def test_select_for_passive_profile_drops_active_tools(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    target = parse_target("example.com")
    eligible, _ = reg.select_for(profile=PROFILE_PASSIVE, target=target)
    eligible_names = {e.name for e in eligible}
    assert "dig" in eligible_names
    assert "whois" in eligible_names
    # nmap and nikto must NOT participate in the passive profile.
    assert "nmap" not in eligible_names
    assert "nikto" not in eligible_names


def test_select_for_network_basic_with_ip(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    target = parse_target("93.184.216.34")
    eligible, _ = reg.select_for(profile=PROFILE_NETWORK_BASIC, target=target)
    assert "nmap" in {e.name for e in eligible}


def test_select_for_web_basic_with_url(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    target = parse_target("https://example.com/")
    eligible, _ = reg.select_for(profile=PROFILE_WEB_BASIC, target=target)
    names = {e.name for e in eligible}
    assert "whatweb" in names
    assert "nikto" in names
    assert "sslscan" in names


def test_missing_tools_are_reported_separately(no_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    target = parse_target("example.com")
    eligible, missing = reg.select_for(profile=PROFILE_SAFE, target=target)
    assert eligible == []
    assert {m.name for m in missing} >= {"dig", "whois", "curl"}


def test_get_returns_entry(all_tools_present) -> None:
    reg = ToolRegistry(default_timeout=10)
    entry = reg.get("nmap")
    assert entry is not None
    assert entry.name == "nmap"
    assert reg.get("nope") is None

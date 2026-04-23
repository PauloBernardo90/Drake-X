"""Tests for drake_x.sandbox.network_guard — network policy enforcement."""

from __future__ import annotations

import pytest

from drake_x.sandbox.base import NetworkPolicy, SandboxConfig
from drake_x.sandbox.network_guard import describe_network_policy, validate_network_policy


class TestValidateNetworkPolicy:
    def test_deny_passes(self) -> None:
        config = SandboxConfig(network=NetworkPolicy.DENY)
        validate_network_policy(config)  # Should not raise

    def test_lab_passes_with_warning(self) -> None:
        config = SandboxConfig(network=NetworkPolicy.LAB)
        validate_network_policy(config)  # Should not raise (just warns)


class TestDescribeNetworkPolicy:
    def test_deny_description(self) -> None:
        config = SandboxConfig(network=NetworkPolicy.DENY)
        desc = describe_network_policy(config)
        assert "DENIED" in desc

    def test_lab_description(self) -> None:
        config = SandboxConfig(network=NetworkPolicy.LAB)
        desc = describe_network_policy(config)
        assert "ALLOWED" in desc
        assert "lab" in desc.lower()

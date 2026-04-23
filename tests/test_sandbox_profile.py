"""Tests for drake_x.sandbox.profile_builder — Firejail profile generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.sandbox.base import NetworkPolicy, SandboxConfig
from drake_x.sandbox.profile_builder import build_firejail_profile, write_profile


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "sample").mkdir()
    (ws / "output").mkdir()
    return ws


class TestBuildFirejailProfile:
    def test_deny_network_default(self, workspace: Path) -> None:
        config = SandboxConfig()  # Default: DENY
        profile = build_firejail_profile(workspace, config)
        assert "net none" in profile

    def test_lab_network(self, workspace: Path) -> None:
        config = SandboxConfig(network=NetworkPolicy.LAB)
        profile = build_firejail_profile(workspace, config)
        assert "net none" not in profile
        assert "LAB MODE" in profile

    def test_private_filesystem(self, workspace: Path) -> None:
        config = SandboxConfig()
        profile = build_firejail_profile(workspace, config)
        assert "private" in profile
        assert "private-tmp" in profile
        assert "private-dev" in profile

    def test_security_hardening(self, workspace: Path) -> None:
        config = SandboxConfig()
        profile = build_firejail_profile(workspace, config)
        assert "caps.drop all" in profile
        assert "nonewprivs" in profile
        assert "noroot" in profile
        assert "seccomp" in profile

    def test_sensitive_paths_blocked(self, workspace: Path) -> None:
        config = SandboxConfig()
        profile = build_firejail_profile(workspace, config)
        assert "blacklist /etc/shadow" in profile
        assert "blacklist /etc/ssh" in profile
        assert "blacklist /root" in profile

    def test_subsystems_disabled(self, workspace: Path) -> None:
        config = SandboxConfig()
        profile = build_firejail_profile(workspace, config)
        assert "nosound" in profile
        assert "no3d" in profile
        assert "novideo" in profile

    def test_read_only_sample(self, workspace: Path) -> None:
        config = SandboxConfig(read_only_sample=True)
        profile = build_firejail_profile(workspace, config)
        assert "read-only" in profile


class TestWriteProfile:
    def test_writes_file(self, workspace: Path) -> None:
        config = SandboxConfig()
        path = write_profile(workspace, config)
        assert path.exists()
        assert path.name == "sandbox.profile"
        content = path.read_text()
        assert "net none" in content

    def test_profile_not_empty(self, workspace: Path) -> None:
        config = SandboxConfig()
        path = write_profile(workspace, config)
        assert path.stat().st_size > 100

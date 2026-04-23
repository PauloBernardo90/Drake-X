"""Tests for drake_x.sandbox.docker_runner — Docker backend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.sandbox.base import NetworkPolicy, SandboxConfig, SandboxStatus
from drake_x.sandbox.docker_runner import DockerBackend
from drake_x.sandbox.exceptions import IsolationError, SandboxUnavailableError


class TestDockerAvailability:
    def test_available_when_installed(self) -> None:
        with patch("drake_x.sandbox.docker_runner.shutil.which", return_value="/usr/bin/docker"):
            with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                backend = DockerBackend()
                assert backend.is_available() is True

    def test_unavailable_no_binary(self) -> None:
        with patch("drake_x.sandbox.docker_runner.shutil.which", return_value=None):
            backend = DockerBackend()
            assert backend.is_available() is False

    def test_unavailable_daemon_not_running(self) -> None:
        with patch("drake_x.sandbox.docker_runner.shutil.which", return_value="/usr/bin/docker"):
            with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                backend = DockerBackend()
                assert backend.is_available() is False

    def test_name(self) -> None:
        assert DockerBackend().name == "docker"

    def test_custom_image(self) -> None:
        backend = DockerBackend(image="alpine:3.18")
        assert backend._image == "alpine:3.18"


class TestDockerIsolation:
    def test_raises_when_unavailable(self) -> None:
        backend = DockerBackend()
        with patch.object(backend, "is_available", return_value=False):
            with pytest.raises(SandboxUnavailableError):
                backend.verify_isolation(SandboxConfig())

    def test_success(self) -> None:
        backend = DockerBackend()
        with patch.object(backend, "is_available", return_value=True):
            with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                assert backend.verify_isolation(SandboxConfig()) is True


class TestDockerExecution:
    def test_successful_execution(self, tmp_path: Path) -> None:
        backend = DockerBackend()
        ws = tmp_path
        (ws / "sample").mkdir()
        (ws / "output").mkdir()
        config = SandboxConfig()

        with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"output",
                stderr=b"",
            )
            result = backend.execute(["echo", "test"], ws, config)
            assert result.status == SandboxStatus.SUCCESS
            assert result.exit_code == 0
            assert result.stdout == "output"
            assert result.isolation_verified is True

    def test_network_none_flag(self, tmp_path: Path) -> None:
        backend = DockerBackend()
        ws = tmp_path
        (ws / "sample").mkdir()
        (ws / "output").mkdir()
        config = SandboxConfig(network=NetworkPolicy.DENY)

        with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            backend.execute(["test"], ws, config)
            cmd = mock_run.call_args[0][0]
            assert "--network=none" in cmd

    def test_lab_network_no_none(self, tmp_path: Path) -> None:
        backend = DockerBackend()
        ws = tmp_path
        (ws / "sample").mkdir()
        (ws / "output").mkdir()
        config = SandboxConfig(network=NetworkPolicy.LAB)

        with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            backend.execute(["test"], ws, config)
            cmd = mock_run.call_args[0][0]
            assert "--network=none" not in cmd

    def test_timeout(self, tmp_path: Path) -> None:
        import subprocess
        backend = DockerBackend()
        ws = tmp_path
        (ws / "sample").mkdir()
        (ws / "output").mkdir()
        config = SandboxConfig(timeout_seconds=5)

        with patch("drake_x.sandbox.docker_runner.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5)):
            result = backend.execute(["sleep", "999"], ws, config)
            assert result.status == SandboxStatus.TIMEOUT
            assert result.timed_out is True

    def test_security_flags(self, tmp_path: Path) -> None:
        backend = DockerBackend()
        ws = tmp_path
        (ws / "sample").mkdir()
        (ws / "output").mkdir()

        with patch("drake_x.sandbox.docker_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            backend.execute(["test"], ws, SandboxConfig())
            cmd = mock_run.call_args[0][0]
            assert "--rm" in cmd
            assert "--read-only" in cmd
            assert "--cap-drop=ALL" in cmd
            assert "--security-opt=no-new-privileges" in cmd

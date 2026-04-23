"""Tests for drake_x.sandbox.firejail_runner — Firejail backend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.sandbox.base import NetworkPolicy, SandboxConfig, SandboxStatus
from drake_x.sandbox.exceptions import IsolationError, SandboxUnavailableError
from drake_x.sandbox.firejail_runner import FirejailBackend


class TestFirejailAvailability:
    def test_available_when_installed(self) -> None:
        with patch("drake_x.sandbox.firejail_runner.shutil.which", return_value="/usr/bin/firejail"):
            backend = FirejailBackend()
            assert backend.is_available() is True

    def test_unavailable_when_not_installed(self) -> None:
        with patch("drake_x.sandbox.firejail_runner.shutil.which", return_value=None):
            backend = FirejailBackend()
            assert backend.is_available() is False

    def test_name(self) -> None:
        assert FirejailBackend().name == "firejail"


class TestFirejailIsolationVerification:
    def test_raises_when_not_installed(self) -> None:
        backend = FirejailBackend()
        with patch.object(backend, "is_available", return_value=False):
            with pytest.raises(SandboxUnavailableError, match="not installed"):
                backend.verify_isolation(SandboxConfig())

    def test_raises_on_version_failure(self) -> None:
        backend = FirejailBackend()
        with patch.object(backend, "is_available", return_value=True):
            with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stderr=b"error",
                )
                with pytest.raises(IsolationError, match="sanity check failed"):
                    backend.verify_isolation(SandboxConfig())

    def test_raises_on_timeout(self) -> None:
        import subprocess
        backend = FirejailBackend()
        with patch.object(backend, "is_available", return_value=True):
            with patch("drake_x.sandbox.firejail_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="firejail", timeout=10)):
                with pytest.raises(IsolationError, match="timed out"):
                    backend.verify_isolation(SandboxConfig())

    def test_success_on_valid_firejail(self) -> None:
        backend = FirejailBackend()
        with patch.object(backend, "is_available", return_value=True):
            with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                assert backend.verify_isolation(SandboxConfig()) is True


class TestFirejailExecution:
    def test_timeout_returns_timeout_status(self, tmp_path: Path) -> None:
        import subprocess
        backend = FirejailBackend()
        config = SandboxConfig(timeout_seconds=1)

        with patch("drake_x.sandbox.firejail_runner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="firejail", timeout=1)):
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                result = backend.execute(["test"], tmp_path, config)
                assert result.status == SandboxStatus.TIMEOUT
                assert result.timed_out is True

    def test_file_not_found_returns_unavailable(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig()

        with patch("drake_x.sandbox.firejail_runner.subprocess.run", side_effect=FileNotFoundError()):
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                result = backend.execute(["test"], tmp_path, config)
                assert result.status == SandboxStatus.BACKEND_UNAVAILABLE

    def test_os_error_returns_error(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig()

        with patch("drake_x.sandbox.firejail_runner.subprocess.run", side_effect=OSError("test")):
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                result = backend.execute(["test"], tmp_path, config)
                assert result.status == SandboxStatus.ERROR

    def test_successful_execution(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig()

        with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"output data",
                stderr=b"",
            )
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                result = backend.execute(["echo", "test"], tmp_path, config)
                assert result.status == SandboxStatus.SUCCESS
                assert result.exit_code == 0
                assert result.stdout == "output data"
                assert result.isolation_verified is True

    def test_nonzero_exit_returns_error(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig()

        with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout=b"",
                stderr=b"some error",
            )
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                result = backend.execute(["false"], tmp_path, config)
                assert result.status == SandboxStatus.ERROR
                assert result.exit_code == 1
                assert "some error" in result.stderr

    def test_net_none_flag_added(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig(network=NetworkPolicy.DENY)

        with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                backend.execute(["test"], tmp_path, config)
                actual_cmd = mock_run.call_args[0][0]
                assert "--net=none" in actual_cmd

    def test_profile_override_blocked(self, tmp_path: Path) -> None:
        backend = FirejailBackend()
        config = SandboxConfig(extra_args=["--profile=/evil", "--private=/evil"])

        with patch("drake_x.sandbox.firejail_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            with patch("drake_x.sandbox.firejail_runner.write_profile", return_value=tmp_path / "p"):
                backend.execute(["test"], tmp_path, config)
                actual_cmd = mock_run.call_args[0][0]
                assert "--profile=/evil" not in actual_cmd
                assert "--private=/evil" not in actual_cmd

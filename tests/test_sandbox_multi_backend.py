"""Tests for multi-backend runner and CLI integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.sandbox.base import SandboxConfig, SandboxResult, SandboxStatus
from drake_x.sandbox.exceptions import SandboxUnavailableError
from drake_x.sandbox.runner import resolve_backend, run_sandboxed


class TestResolveBackend:
    def test_firejail(self) -> None:
        backend = resolve_backend("firejail")
        assert backend.name == "firejail"

    def test_docker(self) -> None:
        backend = resolve_backend("docker")
        assert backend.name == "docker"

    def test_emulator(self) -> None:
        backend = resolve_backend("emulator")
        assert backend.name == "emulator"

    def test_unknown_raises(self) -> None:
        with pytest.raises(SandboxUnavailableError, match="Unknown"):
            resolve_backend("qemu_nonexistent")

    def test_case_insensitive(self) -> None:
        backend = resolve_backend("Docker")
        assert backend.name == "docker"

    def test_docker_with_image(self) -> None:
        backend = resolve_backend("docker", image="alpine:3.18")
        assert backend.name == "docker"

    def test_emulator_with_avd(self) -> None:
        backend = resolve_backend("emulator", avd_name="test_avd")
        assert backend.name == "emulator"


class TestRunSandboxedMultiBackend:
    @pytest.fixture
    def sample_file(self, tmp_path: Path) -> Path:
        f = tmp_path / "sample.apk"
        f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
        return f

    def test_docker_backend_used(self, sample_file: Path) -> None:
        with patch("drake_x.sandbox.runner.resolve_backend") as mock_resolve:
            mock_backend = mock_resolve.return_value
            mock_backend.name = "docker"
            mock_backend.is_available.return_value = True
            mock_backend.verify_isolation.return_value = True
            mock_backend.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0, stdout="ok", stderr="",
                backend="docker", isolation_verified=True,
            )

            report = run_sandboxed(
                sample_file, ["test"],
                backend_name="docker",
            )
            assert report.backend == "docker"
            assert report.status == SandboxStatus.SUCCESS.value

    def test_emulator_backend_used(self, sample_file: Path) -> None:
        with patch("drake_x.sandbox.runner.resolve_backend") as mock_resolve:
            mock_backend = mock_resolve.return_value
            mock_backend.name = "emulator"
            mock_backend.is_available.return_value = True
            mock_backend.verify_isolation.return_value = True
            mock_backend.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0, stdout="logcat", stderr="",
                backend="emulator", isolation_verified=True,
            )

            report = run_sandboxed(
                sample_file, ["sample.apk", "--launch"],
                backend_name="emulator",
            )
            assert report.backend == "emulator"

    def test_unknown_backend_fails(self, sample_file: Path) -> None:
        report = run_sandboxed(
            sample_file, ["test"],
            backend_name="nonexistent_backend",
        )
        assert report.status == SandboxStatus.BACKEND_UNAVAILABLE.value
        assert "Unknown" in (report.error or "")

    def test_artifact_collection(self, sample_file: Path, tmp_path: Path) -> None:
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with patch("drake_x.sandbox.runner.resolve_backend") as mock_resolve:
            mock_backend = mock_resolve.return_value
            mock_backend.name = "firejail"
            mock_backend.is_available.return_value = True
            mock_backend.verify_isolation.return_value = True
            mock_backend.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0, stdout="", stderr="",
                backend="firejail", isolation_verified=True,
            )

            report = run_sandboxed(
                sample_file, ["test"],
                output_dir=output_dir,
                collect_output=True,
            )
            assert report.status == SandboxStatus.SUCCESS.value

    def test_cli_sandbox_flag_accepted(self) -> None:
        """Verify analyze commands accept --sandbox flag."""
        import inspect
        # APK
        from drake_x.cli.apk_cmd import analyze as apk_analyze
        sig = inspect.signature(apk_analyze)
        assert "sandbox" in sig.parameters
        assert "sandbox_backend" in sig.parameters

    def test_cli_pe_sandbox_flag_accepted(self) -> None:
        import inspect
        from drake_x.cli.pe_cmd import analyze as pe_analyze
        sig = inspect.signature(pe_analyze)
        assert "sandbox" in sig.parameters
        assert "sandbox_backend" in sig.parameters

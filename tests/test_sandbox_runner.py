"""Tests for drake_x.sandbox.runner — main sandbox orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.sandbox.base import NetworkPolicy, SandboxConfig, SandboxStatus
from drake_x.sandbox.runner import run_sandboxed


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample.apk"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    return f


class TestRunSandboxed:
    def test_fail_closed_no_firejail(self, sample_file: Path) -> None:
        """Without Firejail, execution must be refused (fail-closed)."""
        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            instance = MockBackend.return_value
            instance.is_available.return_value = False

            report = run_sandboxed(
                sample_path=sample_file,
                command=["file", "sample/sample.apk"],
            )

            assert report.status == SandboxStatus.BACKEND_UNAVAILABLE.value
            assert "FAIL-CLOSED" in " ".join(report.audit_observations)

    def test_fail_closed_isolation_failure(self, sample_file: Path) -> None:
        """If isolation cannot be verified, execution must be refused."""
        from drake_x.sandbox.exceptions import IsolationError

        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.side_effect = IsolationError("test fail")

            report = run_sandboxed(
                sample_path=sample_file,
                command=["file", "sample/sample.apk"],
            )

            assert report.status == SandboxStatus.ISOLATION_FAILURE.value
            assert "FAIL-CLOSED" in " ".join(report.audit_observations)

    def test_successful_execution(self, sample_file: Path) -> None:
        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True
            instance.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0,
                stdout="test output",
                stderr="",
                backend="firejail",
                isolation_verified=True,
            )

            report = run_sandboxed(
                sample_path=sample_file,
                command=["file", "sample/sample.apk"],
            )

            assert report.status == SandboxStatus.SUCCESS.value
            assert report.exit_code == 0
            assert report.stdout == "test output"
            assert report.isolation_verified is True
            assert report.sample_sha256  # SHA computed
            assert report.run_id.startswith("sbx-")

    def test_timeout_reported(self, sample_file: Path) -> None:
        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True
            instance.execute.return_value = SandboxResult(
                status=SandboxStatus.TIMEOUT,
                timed_out=True,
                error="Timed out",
                backend="firejail",
                isolation_verified=True,
            )

            report = run_sandboxed(
                sample_path=sample_file,
                command=["sleep", "999"],
                config=SandboxConfig(timeout_seconds=5),
            )

            assert report.status == SandboxStatus.TIMEOUT.value
            assert report.timed_out is True

    def test_report_written_to_output_dir(self, sample_file: Path, tmp_path: Path) -> None:
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True
            instance.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0,
                stdout="",
                stderr="",
                backend="firejail",
                isolation_verified=True,
            )

            report = run_sandboxed(
                sample_path=sample_file,
                command=["test"],
                output_dir=output_dir,
            )

            # Report file should be written
            report_files = list(output_dir.glob("sbx-*.json"))
            assert len(report_files) == 1

    def test_workspace_cleaned_up(self, sample_file: Path) -> None:
        workspace_root = None

        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True

            def capture_workspace(command, workspace, config):
                nonlocal workspace_root
                workspace_root = workspace
                return SandboxResult(
                    status=SandboxStatus.SUCCESS,
                    exit_code=0, stdout="", stderr="",
                    backend="firejail", isolation_verified=True,
                )

            instance.execute.side_effect = capture_workspace

            run_sandboxed(
                sample_path=sample_file,
                command=["test"],
            )

        # Workspace should be cleaned up
        assert workspace_root is not None
        assert not workspace_root.exists()

    def test_default_config(self, sample_file: Path) -> None:
        """Default config should have deny network and 120s timeout."""
        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True
            instance.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0, stdout="", stderr="",
                backend="firejail", isolation_verified=True,
            )

            report = run_sandboxed(
                sample_path=sample_file,
                command=["test"],
            )

            assert report.network_policy == "deny"
            assert report.timeout_seconds == 120

    def test_audit_trail_populated(self, sample_file: Path) -> None:
        with patch("drake_x.sandbox.runner.FirejailBackend") as MockBackend:
            from drake_x.sandbox.base import SandboxResult

            instance = MockBackend.return_value
            instance.is_available.return_value = True
            instance.verify_isolation.return_value = True
            instance.execute.return_value = SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0, stdout="", stderr="",
                backend="firejail", isolation_verified=True,
            )

            report = run_sandboxed(
                sample_path=sample_file,
                command=["test"],
            )

            assert len(report.audit_observations) >= 2
            assert any("Workspace created" in o for o in report.audit_observations)
            assert any("cleanup" in o.lower() for o in report.audit_observations)

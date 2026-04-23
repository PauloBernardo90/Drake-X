"""Tests for drake_x.sandbox.emulator_runner — Android emulator backend."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from drake_x.sandbox.base import SandboxConfig
from drake_x.sandbox.emulator_runner import EmulatorBackend, _find_sdk_tool
from drake_x.sandbox.exceptions import IsolationError, SandboxUnavailableError


class TestEmulatorAvailability:
    def test_available_with_both_tools(self) -> None:
        backend = EmulatorBackend()
        backend._adb = "/usr/bin/adb"
        backend._emulator = "/usr/bin/emulator"
        assert backend.is_available() is True

    def test_unavailable_no_adb(self) -> None:
        backend = EmulatorBackend()
        backend._adb = None
        backend._emulator = "/usr/bin/emulator"
        assert backend.is_available() is False

    def test_unavailable_no_emulator(self) -> None:
        backend = EmulatorBackend()
        backend._adb = "/usr/bin/adb"
        backend._emulator = None
        assert backend.is_available() is False

    def test_name(self) -> None:
        assert EmulatorBackend().name == "emulator"


class TestEmulatorIsolation:
    def test_raises_when_tools_missing(self) -> None:
        backend = EmulatorBackend()
        backend._adb = None
        backend._emulator = None
        with pytest.raises(SandboxUnavailableError, match="not found"):
            backend.verify_isolation(SandboxConfig())

    def test_raises_when_avd_missing(self) -> None:
        backend = EmulatorBackend(avd_name="nonexistent_avd")
        backend._adb = "/usr/bin/adb"
        backend._emulator = "/usr/bin/emulator"

        with patch("drake_x.sandbox.emulator_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=b"other_avd\nsome_avd\n",
                returncode=0,
            )
            with pytest.raises(IsolationError, match="not found"):
                backend.verify_isolation(SandboxConfig())

    def test_success_when_avd_exists(self) -> None:
        backend = EmulatorBackend(avd_name="drake_sandbox")
        backend._adb = "/usr/bin/adb"
        backend._emulator = "/usr/bin/emulator"

        with patch("drake_x.sandbox.emulator_runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=b"drake_sandbox\nother_avd\n",
                returncode=0,
            )
            assert backend.verify_isolation(SandboxConfig()) is True


class TestFindSdkTool:
    def test_finds_on_path(self) -> None:
        with patch("drake_x.sandbox.emulator_runner.shutil.which", return_value="/usr/bin/adb"):
            assert _find_sdk_tool("adb") == "/usr/bin/adb"

    def test_finds_in_android_home(self, tmp_path: Path) -> None:
        # Create a fake SDK structure
        pt = tmp_path / "platform-tools"
        pt.mkdir()
        adb = pt / "adb"
        adb.write_text("#!/bin/sh\n")

        with patch("drake_x.sandbox.emulator_runner.shutil.which", return_value=None):
            with patch.dict("os.environ", {"ANDROID_HOME": str(tmp_path)}):
                result = _find_sdk_tool("adb")
                assert result is not None
                assert "adb" in result

    def test_none_when_not_found(self) -> None:
        with patch("drake_x.sandbox.emulator_runner.shutil.which", return_value=None):
            with patch.dict("os.environ", {}, clear=True):
                assert _find_sdk_tool("nonexistent_tool") is None

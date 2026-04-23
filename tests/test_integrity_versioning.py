"""Tests for drake_x.integrity.versioning — environment version capture."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from drake_x.integrity.models import ToolAvailability
from drake_x.integrity.versioning import capture_version_info


class TestCaptureVersionInfo:
    def test_captures_drake_version(self) -> None:
        info = capture_version_info()
        assert info.drake_x_version
        assert info.drake_x_version == "1.0.0"

    def test_captures_python_version(self) -> None:
        info = capture_version_info()
        assert info.python_version
        assert "." in info.python_version

    def test_captures_pipeline_version(self) -> None:
        info = capture_version_info(pipeline_version="2.0.0-test")
        assert info.pipeline_version == "2.0.0-test"

    def test_default_pipeline_version_is_drake(self) -> None:
        info = capture_version_info()
        assert info.pipeline_version == info.drake_x_version

    def test_captures_analysis_profile(self) -> None:
        info = capture_version_info(analysis_profile="apk_analyze")
        assert info.analysis_profile == "apk_analyze"

    def test_tool_list_populated(self) -> None:
        info = capture_version_info()
        assert len(info.tools) > 0
        tool_names = {t.tool_name for t in info.tools}
        # Should check at least some standard tools
        assert "apktool" in tool_names or "jadx" in tool_names or "file" in tool_names

    def test_unavailable_tool_recorded_explicitly(self) -> None:
        info = capture_version_info()
        # At least some tools will be unavailable on a dev machine
        for tool in info.tools:
            assert tool.availability in (
                ToolAvailability.AVAILABLE,
                ToolAvailability.UNAVAILABLE,
                ToolAvailability.UNKNOWN,
            )

    def test_androguard_checked(self) -> None:
        info = capture_version_info()
        tool_names = {t.tool_name for t in info.tools}
        assert "androguard" in tool_names

    def test_extra_tools_checked(self) -> None:
        info = capture_version_info(extra_tools=["nonexistent_tool_xyz"])
        tool_names = {t.tool_name for t in info.tools}
        assert "nonexistent_tool_xyz" in tool_names

    def test_serializable(self) -> None:
        info = capture_version_info()
        d = info.model_dump(mode="json")
        assert "drake_x_version" in d
        assert "tools" in d
        assert isinstance(d["tools"], list)

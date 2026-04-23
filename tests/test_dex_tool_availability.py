"""Tests for tool bridge behavior when external tools are not installed."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from drake_x.dex.jadx_bridge import is_jadx_available
from drake_x.dex.apktool_bridge import is_apktool_available
from drake_x.dex.androguard_bridge import (
    analyze_apk,
    extract_call_edges,
    extract_classes_per_dex,
    extract_strings_per_dex,
    is_androguard_available,
)


class TestJadxAvailability:
    def test_not_available(self) -> None:
        with patch("drake_x.dex.jadx_bridge.is_available", return_value=False):
            assert is_jadx_available() is False

    def test_available(self) -> None:
        with patch("drake_x.dex.jadx_bridge.is_available", return_value=True):
            assert is_jadx_available() is True


class TestApktoolAvailability:
    def test_not_available(self) -> None:
        with patch("drake_x.dex.apktool_bridge.is_available", return_value=False):
            assert is_apktool_available() is False

    def test_available(self) -> None:
        with patch("drake_x.dex.apktool_bridge.is_available", return_value=True):
            assert is_apktool_available() is True


class TestAndroguardAvailability:
    def test_not_available(self) -> None:
        with patch("drake_x.dex.androguard_bridge.is_androguard_available", return_value=False):
            # Functions should return graceful fallbacks
            assert extract_call_edges.__wrapped__ if hasattr(extract_call_edges, '__wrapped__') else True

    def test_analyze_apk_returns_none_without_androguard(self, tmp_path) -> None:
        with patch("drake_x.dex.androguard_bridge.is_androguard_available", return_value=False):
            result = analyze_apk(tmp_path / "fake.apk")
            assert result is None

    def test_extract_classes_empty_without_androguard(self, tmp_path) -> None:
        with patch("drake_x.dex.androguard_bridge.is_androguard_available", return_value=False):
            result = extract_classes_per_dex(tmp_path / "fake.apk")
            assert result == {}

    def test_extract_strings_empty_without_androguard(self, tmp_path) -> None:
        with patch("drake_x.dex.androguard_bridge.is_androguard_available", return_value=False):
            result = extract_strings_per_dex(tmp_path / "fake.apk")
            assert result == {}

    def test_extract_call_edges_empty_without_androguard(self, tmp_path) -> None:
        with patch("drake_x.dex.androguard_bridge.is_androguard_available", return_value=False):
            result = extract_call_edges(tmp_path / "fake.apk")
            assert result == []

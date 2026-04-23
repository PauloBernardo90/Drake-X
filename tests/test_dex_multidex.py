"""Tests for drake_x.dex.multidex — multi-DEX enumeration and correlation."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from drake_x.dex.multidex import (
    cross_reference_classes,
    detect_packing_indicators,
    enumerate_dex_files,
    parse_all_dex,
)
from drake_x.models.dex import DexFileInfo


def _write_dex(path: Path, *, class_count: int = 10, method_count: int = 50) -> None:
    """Write a minimal synthetic DEX file."""
    buf = bytearray(512)
    buf[0:4] = b"dex\n"
    buf[4:8] = b"035\x00"
    struct.pack_into("<I", buf, 56, 100)   # string_ids_size
    struct.pack_into("<I", buf, 60, 112)   # string_ids_off
    struct.pack_into("<I", buf, 64, 50)    # type_ids_size
    struct.pack_into("<I", buf, 68, 200)   # type_ids_off
    struct.pack_into("<I", buf, 88, method_count)
    struct.pack_into("<I", buf, 92, 300)
    struct.pack_into("<I", buf, 96, class_count)
    struct.pack_into("<I", buf, 100, 400)
    path.write_bytes(bytes(buf))


@pytest.fixture
def apk_dir(tmp_path: Path) -> Path:
    d = tmp_path / "unpack"
    d.mkdir()
    _write_dex(d / "classes.dex")
    _write_dex(d / "classes2.dex", class_count=15)
    _write_dex(d / "classes3.dex", class_count=5)
    return d


class TestEnumerateDexFiles:
    def test_finds_all_standard_dex(self, apk_dir: Path) -> None:
        found = enumerate_dex_files(apk_dir)
        names = [f.name for f in found]
        assert "classes.dex" in names
        assert "classes2.dex" in names
        assert "classes3.dex" in names

    def test_finds_hidden_dex(self, apk_dir: Path) -> None:
        hidden_dir = apk_dir / "assets"
        hidden_dir.mkdir()
        _write_dex(hidden_dir / "payload.dex")
        found = enumerate_dex_files(apk_dir)
        names = [f.name for f in found]
        assert "payload.dex" in names

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        assert enumerate_dex_files(tmp_path / "nope") == []

    def test_empty_dir(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        assert enumerate_dex_files(d) == []


class TestParseAllDex:
    def test_parses_all(self, apk_dir: Path) -> None:
        paths = enumerate_dex_files(apk_dir)
        infos = parse_all_dex(paths)
        assert len(infos) == 3
        assert infos[0].class_count == 10
        assert infos[1].class_count == 15

    def test_skips_invalid(self, apk_dir: Path) -> None:
        bad = apk_dir / "bad.dex"
        bad.write_bytes(b"not a dex")
        paths = enumerate_dex_files(apk_dir)
        # bad.dex won't be found by enumerate (wrong name), but test parse_all
        infos = parse_all_dex(paths + [bad])
        # Should still parse the 3 valid ones
        assert len(infos) == 3


class TestDetectPackingIndicators:
    def test_high_dex_count(self) -> None:
        dex_infos = [
            DexFileInfo(filename=f"classes{i}.dex", path=f"/x/classes{i}.dex", class_count=10)
            for i in range(5)
        ]
        indicators = detect_packing_indicators(dex_infos)
        types = [i.indicator_type for i in indicators]
        assert "high_dex_count" in types

    def test_dropper_pattern(self) -> None:
        dex_infos = [
            DexFileInfo(filename="classes.dex", path="/x/classes.dex", class_count=5),
            DexFileInfo(filename="classes2.dex", path="/x/classes2.dex", class_count=200),
        ]
        indicators = detect_packing_indicators(dex_infos)
        types = [i.indicator_type for i in indicators]
        assert "dropper_pattern" in types

    def test_hidden_dex_location(self) -> None:
        dex_infos = [
            DexFileInfo(
                filename="payload.dex",
                path="/x/assets/payload.dex",
                class_count=50,
            ),
        ]
        indicators = detect_packing_indicators(dex_infos)
        types = [i.indicator_type for i in indicators]
        assert "hidden_dex" in types

    def test_non_standard_name(self) -> None:
        dex_infos = [
            DexFileInfo(filename="payload.dex", path="/x/payload.dex", class_count=10),
        ]
        indicators = detect_packing_indicators(dex_infos)
        types = [i.indicator_type for i in indicators]
        assert "non_standard_dex_name" in types

    def test_no_indicators_for_single_dex(self) -> None:
        dex_infos = [
            DexFileInfo(filename="classes.dex", path="/x/classes.dex", class_count=100),
        ]
        indicators = detect_packing_indicators(dex_infos)
        assert len(indicators) == 0

    def test_empty_input(self) -> None:
        assert detect_packing_indicators([]) == []


class TestCrossReferenceClasses:
    def test_basic(self) -> None:
        class_lists = {
            "classes.dex": ["com.app.Main", "com.app.Utils"],
            "classes2.dex": ["com.app.Service", "com.lib.Helper"],
        }
        xref = cross_reference_classes(class_lists)
        assert "com.app" in xref
        assert set(xref["com.app"]) == {"classes.dex", "classes2.dex"}
        assert xref["com.lib"] == ["classes2.dex"]

    def test_empty(self) -> None:
        assert cross_reference_classes({}) == {}

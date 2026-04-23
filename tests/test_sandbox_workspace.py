"""Tests for drake_x.sandbox.workspace — ephemeral workspace manager."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.sandbox.exceptions import InvalidSampleError, WorkspaceError
from drake_x.sandbox.workspace import EphemeralWorkspace


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "test_sample.apk"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    return f


@pytest.fixture
def large_sample(tmp_path: Path) -> Path:
    f = tmp_path / "large.apk"
    # Write just enough to test — don't actually create 2 GiB
    f.write_bytes(b"\x00" * 1000)
    return f


class TestEphemeralWorkspace:
    def test_creates_and_destroys(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            assert ws.root.exists()
            assert ws.sample.exists()
            assert ws.output_dir.exists()
            root = ws.root

        # Workspace should be destroyed
        assert not root.exists()

    def test_sample_copied(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            assert ws.sample.name == "test_sample.apk"
            assert ws.sample.read_bytes() == sample_file.read_bytes()

    def test_output_dir_exists(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            assert (ws.root / "output").is_dir()

    def test_sha256_computed(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            sha = ws.sample_sha256
            assert len(sha) == 64
            assert all(c in "0123456789abcdef" for c in sha)

    def test_cleanup_on_exception(self, sample_file: Path) -> None:
        root = None
        try:
            with EphemeralWorkspace(sample_file) as ws:
                root = ws.root
                raise RuntimeError("Simulated failure")
        except RuntimeError:
            pass
        assert root is not None
        assert not root.exists()

    def test_double_cleanup_safe(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            ws.cleanup()
            ws.cleanup()  # Should not raise

    def test_custom_base_dir(self, sample_file: Path, tmp_path: Path) -> None:
        base = tmp_path / "custom_base"
        base.mkdir()
        with EphemeralWorkspace(sample_file, base_dir=base) as ws:
            assert str(ws.root).startswith(str(base))

    def test_missing_sample_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.apk"
        with pytest.raises(InvalidSampleError, match="not found"):
            with EphemeralWorkspace(missing):
                pass

    def test_directory_as_sample_raises(self, tmp_path: Path) -> None:
        d = tmp_path / "a_directory"
        d.mkdir()
        with pytest.raises(InvalidSampleError, match="not a file"):
            with EphemeralWorkspace(d):
                pass

    def test_access_before_enter_raises(self, sample_file: Path) -> None:
        ws = EphemeralWorkspace(sample_file)
        with pytest.raises(WorkspaceError, match="not initialized"):
            _ = ws.root

    def test_workspace_prefix(self, sample_file: Path) -> None:
        with EphemeralWorkspace(sample_file) as ws:
            assert "drake_sandbox_" in ws.root.name

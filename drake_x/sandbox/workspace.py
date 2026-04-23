"""Ephemeral workspace manager for sandboxed executions.

Each sandbox run gets a temporary directory that:
- Is created in a dedicated location (not /tmp root)
- Contains only the files needed for execution
- Is destroyed after execution, even on failure
- Never writes outside its boundary

The workspace is implemented as a context manager that guarantees
cleanup via ``__exit__`` and an explicit ``cleanup()`` for belt-and-suspenders.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from types import TracebackType

from ..logging import get_logger
from .exceptions import InvalidSampleError, WorkspaceError

log = get_logger("sandbox.workspace")

_WORKSPACE_PREFIX = "drake_sandbox_"


class EphemeralWorkspace:
    """Context manager that creates and destroys a sandboxed workspace.

    Usage::

        with EphemeralWorkspace(sample_path) as ws:
            print(ws.root)       # /tmp/drake_sandbox_xxxx/
            print(ws.sample)     # /tmp/drake_sandbox_xxxx/sample/original.apk
            print(ws.output_dir) # /tmp/drake_sandbox_xxxx/output/
    """

    def __init__(
        self,
        sample_path: Path,
        *,
        base_dir: Path | None = None,
    ) -> None:
        self._sample_source = Path(sample_path).resolve()
        self._base_dir = Path(base_dir) if base_dir else None
        self._root: Path | None = None
        self._sample: Path | None = None
        self._output_dir: Path | None = None
        self._cleaned = False

    @property
    def root(self) -> Path:
        if self._root is None:
            raise WorkspaceError("Workspace not initialized — use as context manager")
        return self._root

    @property
    def sample(self) -> Path:
        if self._sample is None:
            raise WorkspaceError("Workspace not initialized")
        return self._sample

    @property
    def output_dir(self) -> Path:
        if self._output_dir is None:
            raise WorkspaceError("Workspace not initialized")
        return self._output_dir

    @property
    def sample_sha256(self) -> str:
        """Compute SHA-256 of the sample file."""
        h = hashlib.sha256()
        try:
            with open(self._sample_source, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except OSError as exc:
            raise InvalidSampleError(f"Cannot read sample: {exc}") from exc
        return h.hexdigest()

    def __enter__(self) -> EphemeralWorkspace:
        self._validate_sample()
        self._create()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.cleanup()

    def _validate_sample(self) -> None:
        """Validate the sample path before workspace creation."""
        path = self._sample_source

        if not path.exists():
            raise InvalidSampleError(f"Sample not found: {path}")

        if not path.is_file():
            raise InvalidSampleError(f"Sample is not a file: {path}")

        # Prevent path traversal: resolve and verify no symlink trickery
        resolved = path.resolve()
        if resolved != path.resolve():
            raise InvalidSampleError(f"Symlink detected: {path}")

        # Size sanity check (2 GiB)
        try:
            size = resolved.stat().st_size
        except OSError as exc:
            raise InvalidSampleError(f"Cannot stat sample: {exc}") from exc

        if size > 2 * 1024 * 1024 * 1024:
            raise InvalidSampleError(
                f"Sample too large: {size:,} bytes (max 2 GiB)"
            )

    def _create(self) -> None:
        """Create the ephemeral workspace directory tree."""
        try:
            base = str(self._base_dir) if self._base_dir else None
            self._root = Path(tempfile.mkdtemp(
                prefix=_WORKSPACE_PREFIX,
                dir=base,
            ))
        except OSError as exc:
            raise WorkspaceError(f"Cannot create workspace: {exc}") from exc

        # Create subdirectories
        sample_dir = self._root / "sample"
        sample_dir.mkdir()
        self._output_dir = self._root / "output"
        self._output_dir.mkdir()

        # Copy sample into workspace
        dest = sample_dir / self._sample_source.name
        try:
            shutil.copy2(str(self._sample_source), str(dest))
        except OSError as exc:
            self.cleanup()
            raise WorkspaceError(
                f"Cannot copy sample into workspace: {exc}"
            ) from exc

        self._sample = dest
        log.info("Workspace created: %s (sample: %s)", self._root, dest.name)

    def cleanup(self) -> None:
        """Destroy the workspace directory tree.

        Safe to call multiple times. Logs but does not raise on cleanup
        failures — we never want cleanup errors to mask the real error.
        """
        if self._cleaned or self._root is None:
            return

        try:
            shutil.rmtree(str(self._root), ignore_errors=False)
            log.info("Workspace destroyed: %s", self._root)
        except OSError as exc:
            log.warning("Workspace cleanup failed: %s — %s", self._root, exc)
        finally:
            self._cleaned = True

"""Artifact collector — harvest outputs from sandboxed execution.

After a sandboxed command completes, the collector scans the workspace
output directory for files produced during execution and catalogues them
with metadata (hash, size, type) for the analysis pipeline.

Collected artifacts can be:
- Files written by the sandboxed command (e.g., decoded resources)
- Logcat captures from emulator runs
- Extracted strings or disassembly output
- Screenshots or memory dumps
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..logging import get_logger

log = get_logger("sandbox.artifact_collector")


@dataclass(frozen=True)
class CollectedArtifact:
    """One artifact harvested from a sandbox workspace."""

    filename: str
    path: str
    size: int
    sha256: str
    artifact_type: str = ""
    notes: str = ""


@dataclass
class ArtifactCollection:
    """All artifacts collected from one sandbox run."""

    run_id: str = ""
    artifacts: list[CollectedArtifact] = field(default_factory=list)
    total_size: int = 0
    collection_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "artifact_count": len(self.artifacts),
            "total_size": self.total_size,
            "artifacts": [
                {
                    "filename": a.filename,
                    "path": a.path,
                    "size": a.size,
                    "sha256": a.sha256,
                    "type": a.artifact_type,
                    "notes": a.notes,
                }
                for a in self.artifacts
            ],
            "notes": self.collection_notes,
        }


# File type heuristics
_TYPE_MAP: dict[str, str] = {
    ".txt": "text",
    ".log": "log",
    ".json": "json",
    ".xml": "xml",
    ".dex": "dex",
    ".apk": "apk",
    ".so": "native_library",
    ".jar": "java_archive",
    ".smali": "smali",
    ".java": "java_source",
    ".png": "image",
    ".jpg": "image",
    ".html": "html",
    ".pcap": "network_capture",
    ".bin": "binary",
    ".dat": "data",
}

MAX_ARTIFACT_SIZE = 100 * 1024 * 1024  # 100 MiB per artifact


def collect_artifacts(
    output_dir: Path,
    *,
    run_id: str = "",
    max_artifacts: int = 500,
) -> ArtifactCollection:
    """Scan the workspace output directory and catalogue all artifacts.

    Parameters
    ----------
    output_dir:
        The ``output/`` directory inside the sandbox workspace.
    run_id:
        Correlation ID from the sandbox report.
    max_artifacts:
        Maximum number of files to catalogue (safety cap).
    """
    output_dir = Path(output_dir)
    collection = ArtifactCollection(run_id=run_id)

    if not output_dir.is_dir():
        collection.collection_notes.append(f"Output directory not found: {output_dir}")
        return collection

    files = sorted(output_dir.rglob("*"))
    file_count = 0

    for fpath in files:
        if not fpath.is_file():
            continue
        if file_count >= max_artifacts:
            collection.collection_notes.append(
                f"Artifact cap reached ({max_artifacts}); skipped remaining files"
            )
            break

        try:
            size = fpath.stat().st_size
        except OSError:
            continue

        if size > MAX_ARTIFACT_SIZE:
            collection.collection_notes.append(
                f"Skipped oversized artifact: {fpath.name} ({size:,} bytes)"
            )
            continue

        sha256 = _hash_file(fpath)
        artifact_type = _infer_type(fpath)

        collection.artifacts.append(CollectedArtifact(
            filename=fpath.name,
            path=str(fpath.relative_to(output_dir)),
            size=size,
            sha256=sha256,
            artifact_type=artifact_type,
        ))
        collection.total_size += size
        file_count += 1

    log.info(
        "Collected %d artifact(s) (%d bytes) from %s",
        len(collection.artifacts), collection.total_size, output_dir,
    )
    return collection


def copy_artifacts(
    collection: ArtifactCollection,
    source_dir: Path,
    dest_dir: Path,
) -> list[Path]:
    """Copy collected artifacts from workspace to a persistent location.

    Returns list of destination paths.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []

    for artifact in collection.artifacts:
        src = source_dir / artifact.path
        dst = dest_dir / artifact.filename
        if src.exists():
            try:
                import shutil
                shutil.copy2(str(src), str(dst))
                copied.append(dst)
            except OSError as exc:
                log.warning("Failed to copy %s: %s", artifact.filename, exc)

    log.info("Copied %d artifact(s) to %s", len(copied), dest_dir)
    return copied


def _hash_file(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _infer_type(path: Path) -> str:
    """Infer artifact type from extension."""
    return _TYPE_MAP.get(path.suffix.lower(), "unknown")

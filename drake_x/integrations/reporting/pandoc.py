"""Pandoc wrapper for PDF generation from Markdown."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ...logging import get_logger

log = get_logger("pandoc")


def is_available() -> bool:
    return shutil.which("pandoc") is not None


def markdown_to_pdf(
    md_path: Path,
    pdf_path: Path,
    *,
    title: str = "Drake-X Report",
    timeout: int = 120,
) -> tuple[bool, str]:
    """Convert a Markdown file to PDF via pandoc.

    Returns ``(success, error_message)``.
    """
    if not is_available():
        return False, "pandoc is not installed. Install with: sudo apt install pandoc texlive-xetex"

    if not md_path.exists():
        return False, f"Markdown file not found: {md_path}"

    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "pandoc",
        str(md_path),
        "-o", str(pdf_path),
        "--pdf-engine=xelatex",
        f"--metadata=title:{title}",
        "--variable=geometry:margin=2.5cm",
        "--variable=fontsize:11pt",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"pandoc timed out after {timeout}s"
    except FileNotFoundError:
        return False, "pandoc not found at execution time"

    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
        # If xelatex is missing, try without it
        if "xelatex" in stderr.lower():
            cmd_fallback = [
                "pandoc", str(md_path), "-o", str(pdf_path),
                f"--metadata=title:{title}",
                "--variable=geometry:margin=2.5cm",
            ]
            try:
                proc2 = subprocess.run(cmd_fallback, capture_output=True, timeout=timeout)
                if proc2.returncode == 0:
                    return True, ""
            except Exception:
                pass
        return False, f"pandoc failed (exit {proc.returncode}): {stderr}"

    return True, ""

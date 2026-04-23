"""DEX/APK deep disassembly and semantic extraction layer.

This package provides multi-DEX aware static analysis for Android malware
research. It integrates with external tools (jadx, apktool, androguard)
through clean abstraction layers and produces structured, evidence-based
findings suitable for downstream reporting and correlation.

Main entry point: :func:`drake_x.dex.pipeline.run_dex_analysis`
"""

from .pipeline import run_dex_analysis

__all__ = ["run_dex_analysis"]

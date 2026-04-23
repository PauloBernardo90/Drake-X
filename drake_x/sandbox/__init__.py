"""Local-first sandbox layer for controlled APK/artifact execution.

This package provides isolated execution environments for Android malware
research. The primary backend is Firejail on Linux, with strict defaults:

- **No network access** by default
- **Ephemeral workspace** destroyed after each run
- **Fail-closed**: if isolation cannot be guaranteed, execution is refused
- **Audit trail**: every run is logged with correlation ID and outcome

Main entry point: :func:`drake_x.sandbox.runner.run_sandboxed`
"""

from .runner import run_sandboxed

__all__ = ["run_sandboxed"]

"""APK static-analysis tool wrappers.

Each wrapper invokes a native Kali tool as a subprocess, captures its
output, and returns a structured result. Wrappers check tool availability
via ``shutil.which`` and degrade gracefully when a binary is missing.

These wrappers operate on **local files**, not network targets, so they
do not use the existing :class:`BaseTool` class (which is target-oriented).
Instead they share a small :func:`run_tool` helper defined in
:mod:`.runner`.
"""

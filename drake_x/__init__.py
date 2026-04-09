"""Drake-X: a CLI reconnaissance assistant for authorized security assessments.

Drake-X orchestrates locally installed Kali tools, normalizes their output into
structured artifacts, persists everything to SQLite, and (optionally) asks a
local Ollama model for a careful triage. It is intentionally non-offensive:
no exploitation, brute forcing, payload generation, or post-exploitation.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

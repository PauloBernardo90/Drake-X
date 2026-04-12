"""Drake-X: local-first evidence-driven malware analysis platform.

Drake-X structures evidence across malware analysis, native inspection,
external intelligence enrichment, and supporting collection workflows. It
normalizes output into structured evidence and optionally asks a local Ollama
model for triage and classification. It does not perform exploitation, brute
forcing, payload generation, or post-exploitation.
"""

__version__ = "0.9.1"
__all__ = ["__version__"]

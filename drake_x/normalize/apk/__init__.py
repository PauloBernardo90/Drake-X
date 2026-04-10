"""APK static-analysis normalizers.

Each module parses raw tool output or extracted file content and produces
structured observations using the models from :mod:`drake_x.models.apk`.
"""

from .behavior import analyze_behavior
from .components import parse_components
from .manifest import parse_badging
from .network import extract_network_indicators
from .obfuscation import assess_obfuscation
from .permissions import parse_permissions, flag_suspicious
from .protections import detect_protections

__all__ = [
    "analyze_behavior",
    "parse_components",
    "parse_badging",
    "extract_network_indicators",
    "assess_obfuscation",
    "parse_permissions",
    "flag_suspicious",
    "detect_protections",
]

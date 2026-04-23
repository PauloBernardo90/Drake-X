"""Androguard bridge — use androguard (if installed) for precise DEX analysis.

Androguard provides the most accurate DEX parsing available in Python.
This bridge is optional: if androguard is not installed, all functions
return graceful fallbacks and the pipeline continues with other tools.

When available, androguard provides:
- Precise class/method/field enumeration per DEX
- String table extraction
- Cross-reference analysis
- Accurate call graph edges
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging import get_logger
from ..models.dex import CallEdge, DexClassInfo, DexFileInfo, DexMethodInfo

log = get_logger("dex.androguard_bridge")


def is_androguard_available() -> bool:
    """Check if androguard is importable."""
    try:
        import androguard  # noqa: F401
        return True
    except ImportError:
        return False


def analyze_apk(apk_path: Path) -> dict[str, Any] | None:
    """Run androguard APK analysis and return structured results.

    Returns None if androguard is not installed.
    """
    if not is_androguard_available():
        log.info("androguard not available — skipping")
        return None

    try:
        from androguard.misc import AnalyzeAPK
        a, d_list, dx = AnalyzeAPK(str(apk_path))
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard analysis failed: %s", exc)
        return None

    result: dict[str, Any] = {
        "package": a.get_package(),
        "permissions": list(a.get_permissions()),
        "activities": list(a.get_activities()),
        "services": list(a.get_services()),
        "receivers": list(a.get_receivers()),
        "providers": list(a.get_providers()),
        "dex_count": len(d_list),
        "dex_data": [],
    }

    for i, d in enumerate(d_list):
        dex_name = f"classes{'' if i == 0 else i + 1}.dex"
        dex_data: dict[str, Any] = {
            "name": dex_name,
            "classes": [],
            "strings": [],
        }

        try:
            for cls in d.get_classes():
                class_name = cls.get_name()
                dex_data["classes"].append(class_name)
        except Exception:  # noqa: BLE001
            pass

        try:
            strings = [s for s in d.get_strings()]
            dex_data["strings"] = strings[:50_000]  # safety cap
        except Exception:  # noqa: BLE001
            pass

        result["dex_data"].append(dex_data)

    return result


def extract_classes_per_dex(apk_path: Path) -> dict[str, list[str]]:
    """Extract class names per DEX file using androguard.

    Returns mapping of DEX filename → list of class names.
    Falls back to empty dict if androguard is unavailable.
    """
    data = analyze_apk(apk_path)
    if not data:
        return {}

    result: dict[str, list[str]] = {}
    for dex_entry in data.get("dex_data", []):
        name = dex_entry["name"]
        classes = [
            c.lstrip("L").rstrip(";").replace("/", ".")
            for c in dex_entry.get("classes", [])
        ]
        result[name] = classes

    return result


def extract_strings_per_dex(apk_path: Path) -> dict[str, list[str]]:
    """Extract string tables per DEX file using androguard.

    Returns mapping of DEX filename → list of strings.
    """
    data = analyze_apk(apk_path)
    if not data:
        return {}

    result: dict[str, list[str]] = {}
    for dex_entry in data.get("dex_data", []):
        result[dex_entry["name"]] = dex_entry.get("strings", [])

    return result


def extract_call_edges(apk_path: Path) -> list[CallEdge]:
    """Extract method call edges using androguard's cross-reference analysis.

    Returns empty list if androguard is unavailable.
    """
    if not is_androguard_available():
        return []

    try:
        from androguard.misc import AnalyzeAPK
        a, d_list, dx = AnalyzeAPK(str(apk_path))
    except Exception as exc:  # noqa: BLE001
        log.warning("androguard xref extraction failed: %s", exc)
        return []

    edges: list[CallEdge] = []
    seen: set[tuple[str, str, str, str]] = set()

    try:
        for method in dx.get_methods():
            m_analysis = method.get_method()
            if m_analysis is None:
                continue

            caller_class = _normalize_class(m_analysis.get_class_name())
            caller_method = m_analysis.get_name()

            for _, callee, _ in method.get_xref_to():
                callee_class = _normalize_class(callee.get_class_name())
                callee_method = callee.get_name()

                key = (caller_class, caller_method, callee_class, callee_method)
                if key in seen:
                    continue
                seen.add(key)

                edges.append(CallEdge(
                    caller_class=caller_class,
                    caller_method=caller_method,
                    callee_class=callee_class,
                    callee_method=callee_method,
                    edge_type="invoke",
                ))

                if len(edges) >= 100_000:  # safety cap
                    log.warning("Call edge extraction capped at 100k edges")
                    return edges
    except Exception as exc:  # noqa: BLE001
        log.warning("xref walk failed: %s", exc)

    log.info("Extracted %d call edges via androguard", len(edges))
    return edges


def extract_android_components(apk_path: Path) -> dict[str, list[str]]:
    """Extract Android component declarations via androguard.

    Returns dict with keys: activities, services, receivers, providers.
    """
    data = analyze_apk(apk_path)
    if not data:
        return {}

    return {
        "activities": data.get("activities", []),
        "services": data.get("services", []),
        "receivers": data.get("receivers", []),
        "providers": data.get("providers", []),
    }


def _normalize_class(name: str) -> str:
    """Convert ``Lcom/foo/Bar;`` to ``com.foo.Bar``."""
    return name.lstrip("L").rstrip(";").replace("/", ".")

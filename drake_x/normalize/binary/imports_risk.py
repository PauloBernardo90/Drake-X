"""Windows API import risk classification for PE analysis.

Classifies imported functions by their relevance to malware behavior
categories: injection, execution, persistence, evasion, credential
access, discovery, and communication. Risk levels are assigned based
on the function's potential for abuse, not its inherent danger.

All outputs are observed evidence labeled with analytic assessment.
"""

from __future__ import annotations

from typing import Any

from ...models.pe import PeImport

# Risk categories with associated Windows API functions.
# Format: { "function_name_lowercase": ("category", "risk", "notes", "technique_id") }

_INJECTION_APIS: dict[str, tuple[str, str, str]] = {
    "virtualalloc": ("injection", "high", "T1055"),
    "virtualallocex": ("injection", "high", "T1055"),
    "virtualprotect": ("injection", "high", "T1055"),
    "virtualprotectex": ("injection", "high", "T1055"),
    "writeprocessmemory": ("injection", "high", "T1055"),
    "ntwritevirtualmemory": ("injection", "high", "T1055"),
    "createremotethread": ("injection", "high", "T1055.001"),
    "createremotethreadex": ("injection", "high", "T1055.001"),
    "ntcreatethreadex": ("injection", "high", "T1055"),
    "queueuserapc": ("injection", "high", "T1055.004"),
    "ntqueueapcthread": ("injection", "high", "T1055.004"),
    "rtlcreateuserthread": ("injection", "high", "T1055"),
    "setthreadcontext": ("injection", "high", "T1055.012"),
    "ntsetcontextthread": ("injection", "high", "T1055.012"),
    "ntallocatevirtualmemory": ("injection", "high", "T1055"),
    "ntmapviewofsection": ("injection", "medium", "T1055.012"),
    "ntunmapviewofsection": ("injection", "medium", "T1055.012"),
}

_EXECUTION_APIS: dict[str, tuple[str, str, str]] = {
    "createprocessa": ("execution", "medium", "T1106"),
    "createprocessw": ("execution", "medium", "T1106"),
    "createprocessasuserw": ("execution", "medium", "T1106"),
    "winexec": ("execution", "medium", "T1106"),
    "shellexecutea": ("execution", "medium", "T1106"),
    "shellexecutew": ("execution", "medium", "T1106"),
    "shellexecuteexa": ("execution", "medium", "T1106"),
    "shellexecuteexw": ("execution", "medium", "T1106"),
    "system": ("execution", "medium", "T1106"),
    "loadlibrarya": ("execution", "medium", "T1129"),
    "loadlibraryw": ("execution", "medium", "T1129"),
    "loadlibraryexa": ("execution", "medium", "T1129"),
    "loadlibraryexw": ("execution", "medium", "T1129"),
    "getprocaddress": ("execution", "low", "T1106"),
    "getmodulehandlea": ("execution", "low", "T1106"),
    "getmodulehandlew": ("execution", "low", "T1106"),
}

_PERSISTENCE_APIS: dict[str, tuple[str, str, str]] = {
    "regsetvalueexa": ("persistence", "medium", "T1547.001"),
    "regsetvalueexw": ("persistence", "medium", "T1547.001"),
    "regcreatekeyexa": ("persistence", "medium", "T1547.001"),
    "regcreatekeyexw": ("persistence", "medium", "T1547.001"),
    "createservicea": ("persistence", "high", "T1543.003"),
    "createservicew": ("persistence", "high", "T1543.003"),
    "setwindowshookexa": ("persistence", "medium", "T1547"),
    "setwindowshookexw": ("persistence", "medium", "T1547"),
    "schtaskcreate": ("persistence", "medium", "T1053.005"),
}

_EVASION_APIS: dict[str, tuple[str, str, str]] = {
    "isdebuggerpresent": ("evasion", "medium", "T1622"),
    "checkremotedebuggerpresent": ("evasion", "medium", "T1622"),
    "ntqueryinformationprocess": ("evasion", "medium", "T1622"),
    "outputdebugstringa": ("evasion", "low", "T1622"),
    "outputdebugstringw": ("evasion", "low", "T1622"),
    "gettickcount": ("evasion", "low", "T1497.003"),
    "queryperformancecounter": ("evasion", "low", "T1497.003"),
    "sleep": ("evasion", "low", "T1497.003"),
    "ntdelayexecution": ("evasion", "low", "T1497.003"),
}

_CREDENTIAL_APIS: dict[str, tuple[str, str, str]] = {
    "lsaenumeratelogonsessions": ("credential_access", "high", "T1003"),
    "credreada": ("credential_access", "medium", "T1555"),
    "credreadw": ("credential_access", "medium", "T1555"),
    "cryptunprotectdata": ("credential_access", "medium", "T1555"),
    "samconnect": ("credential_access", "high", "T1003.002"),
}

_DISCOVERY_APIS: dict[str, tuple[str, str, str]] = {
    "createtoolhelp32snapshot": ("discovery", "low", "T1057"),
    "process32first": ("discovery", "low", "T1057"),
    "process32next": ("discovery", "low", "T1057"),
    "enumprocesses": ("discovery", "low", "T1057"),
    "getsysteminfo": ("discovery", "low", "T1082"),
    "getcomputernamea": ("discovery", "low", "T1082"),
    "getcomputernamew": ("discovery", "low", "T1082"),
    "getusernamea": ("discovery", "low", "T1033"),
    "getusernamew": ("discovery", "low", "T1033"),
    "getadapterinfo": ("discovery", "low", "T1016"),
    "getnativeysteminfo": ("discovery", "low", "T1082"),
}

_COMMUNICATION_APIS: dict[str, tuple[str, str, str]] = {
    "internetopena": ("communication", "medium", "T1071"),
    "internetopenw": ("communication", "medium", "T1071"),
    "internetopenurla": ("communication", "medium", "T1071"),
    "internetopenurlw": ("communication", "medium", "T1071"),
    "httpsendrequesta": ("communication", "medium", "T1071.001"),
    "httpsendrequestw": ("communication", "medium", "T1071.001"),
    "httpopenrequesta": ("communication", "medium", "T1071.001"),
    "httpopenrequestw": ("communication", "medium", "T1071.001"),
    "wsastartup": ("communication", "low", "T1071"),
    "connect": ("communication", "low", "T1071"),
    "send": ("communication", "low", "T1071"),
    "recv": ("communication", "low", "T1071"),
    "urldownloadtofilea": ("communication", "high", "T1105"),
    "urldownloadtofilew": ("communication", "high", "T1105"),
}

# Merge all into a single lookup
_ALL_RISK: dict[str, tuple[str, str, str]] = {}
for _db in [_INJECTION_APIS, _EXECUTION_APIS, _PERSISTENCE_APIS,
            _EVASION_APIS, _CREDENTIAL_APIS, _DISCOVERY_APIS, _COMMUNICATION_APIS]:
    _ALL_RISK.update(_db)


def classify_imports(imports: list[PeImport]) -> list[dict[str, Any]]:
    """Classify PE imports by risk category.

    Returns a list of dicts with: dll, function, category, risk,
    technique_id. Only imports matching known risk patterns are returned.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for imp in imports:
        key = imp.function.lower()
        if key in _ALL_RISK and key not in seen:
            seen.add(key)
            category, risk, technique = _ALL_RISK[key]
            findings.append({
                "dll": imp.dll,
                "function": imp.function,
                "category": category,
                "risk": risk,
                "technique_id": technique,
            })

    # Sort: high risk first, then by category
    risk_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (risk_order.get(f["risk"], 3), f["category"]))
    return findings

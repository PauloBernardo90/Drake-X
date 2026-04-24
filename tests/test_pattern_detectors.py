"""Unit tests for drake_x.integrations.binary.pattern_detectors (v1.3)."""

from __future__ import annotations


def test_vb6_detector_fires_on_minimal_vb6_stub():
    from drake_x.integrations.binary.pattern_detectors import detect_vb6_downloader_stub
    finding = detect_vb6_downloader_stub(
        imports_dlls=["MSVBVM60.DLL"],
        imports_functions=["_CIcos", "EVENT_SINK_AddRef"],
        sections=[{"name": ".text", "raw_size": 28672, "entropy": 5.6}],
        strings_tagged=[],
    )
    assert finding is not None
    assert finding["indicator_type"] == "vb6_downloader_stub"
    assert "T1105" in finding["mitre_attck"]
    assert finding["requires_dynamic_validation"] is True


def test_vb6_detector_skips_multi_dll_vb6_program():
    """A normal VB6 app with many DLLs is not a stub."""
    from drake_x.integrations.binary.pattern_detectors import detect_vb6_downloader_stub
    finding = detect_vb6_downloader_stub(
        imports_dlls=["MSVBVM60.DLL", "KERNEL32.DLL", "USER32.DLL", "GDI32.DLL"],
        imports_functions=["_CIcos"] + ["FuncX"] * 100,
        sections=[{"name": ".text", "raw_size": 500000, "entropy": 6.0}],
        strings_tagged=[],
    )
    assert finding is None


def test_vb6_detector_skips_large_text_section():
    from drake_x.integrations.binary.pattern_detectors import detect_vb6_downloader_stub
    finding = detect_vb6_downloader_stub(
        imports_dlls=["MSVBVM60.DLL"],
        imports_functions=["_CIcos"],
        sections=[{"name": ".text", "raw_size": 500 * 1024, "entropy": 5.0}],
        strings_tagged=[],
    )
    assert finding is None


def test_vb6_detector_skips_sample_with_strong_strings():
    """If the sample has real C2 URLs etc., it isn't a stub."""
    from drake_x.integrations.binary.pattern_detectors import detect_vb6_downloader_stub
    finding = detect_vb6_downloader_stub(
        imports_dlls=["MSVBVM60.DLL"],
        imports_functions=["_CIcos"],
        sections=[{"name": ".text", "raw_size": 28672, "entropy": 5.6}],
        strings_tagged=[{"value": "https://evil1.com/c2", "category": "url"},
                         {"value": "10.0.0.1", "category": "ip"},
                         {"value": "https://evil2.com", "category": "url"},
                         {"value": "https://evil3.com", "category": "url"},
                         {"value": "https://evil4.com", "category": "url"},
                         {"value": "https://evil5.com", "category": "url"}],
    )
    assert finding is None


def test_dotnet_reflection_detector_fires_on_stripped_heap():
    from drake_x.integrations.binary.pattern_detectors import detect_dotnet_reflection_obfuscation
    managed = {
        "is_dotnet": True,
        "user_strings": [],  # stripped
        "member_refs": [
            "Microsoft.VisualBasic.CompilerServices.NewLateBinding.LateGet",
            "Microsoft.VisualBasic.CompilerServices.NewLateBinding.LateCall",
            "System.Activator.CreateInstance",
        ],
    }
    finding = detect_dotnet_reflection_obfuscation(managed)
    assert finding is not None
    assert finding["indicator_type"] == "dotnet_reflection_obfuscation"
    assert "T1027" in finding["mitre_attck"]


def test_dotnet_reflection_detector_skips_normal_dotnet():
    """A .NET binary with a populated #US heap is NOT flagged."""
    from drake_x.integrations.binary.pattern_detectors import detect_dotnet_reflection_obfuscation
    finding = detect_dotnet_reflection_obfuscation({
        "is_dotnet": True,
        "user_strings": ["https://api.example.com", "config-v1", "Hello"],
        "member_refs": ["System.Diagnostics.DebuggerHiddenAttribute..ctor"],
    })
    assert finding is None


def test_dotnet_reflection_detector_skips_non_dotnet():
    from drake_x.integrations.binary.pattern_detectors import detect_dotnet_reflection_obfuscation
    assert detect_dotnet_reflection_obfuscation({"is_dotnet": False}) is None
    assert detect_dotnet_reflection_obfuscation(None) is None


def test_detect_all_runs_both():
    from drake_x.integrations.binary.pattern_detectors import detect_all
    findings = detect_all(
        imports_dlls=["MSVBVM60.DLL"],
        imports_functions=["_CIcos"],
        sections=[{"name": ".text", "raw_size": 28672, "entropy": 5.6}],
        strings_tagged=[],
        managed={
            "is_dotnet": True,
            "user_strings": [],
            "member_refs": ["Microsoft.VisualBasic.CompilerServices.NewLateBinding.LateGet"],
        },
    )
    # Both detectors fire for this (pathological) combined sample
    assert len(findings) == 2
    assert {f["indicator_type"] for f in findings} == {
        "vb6_downloader_stub", "dotnet_reflection_obfuscation"}

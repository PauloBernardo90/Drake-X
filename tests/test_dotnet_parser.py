"""Unit tests for drake_x.integrations.binary.dotnet_parser.

These tests avoid requiring a real .NET binary fixture by using
synthetic mock objects; the end-to-end integration with ``dnfile`` is
exercised implicitly by the pipeline when a .NET sample is analyzed.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def test_dnfile_is_available():
    """dnfile is listed as an optional dep; the test suite installs it."""
    from drake_x.integrations.binary.dotnet_parser import is_available
    assert is_available(), (
        "dnfile must be installed for the .NET parser tests. "
        "Install with: pip install dnfile"
    )


def test_is_dotnet_detects_com_descriptor():
    """is_dotnet reads DATA_DIRECTORY[14] (COM_DESCRIPTOR)."""
    from drake_x.integrations.binary.dotnet_parser import (
        COM_DESCRIPTOR_DIRECTORY_INDEX,
        is_dotnet,
    )

    directory = [SimpleNamespace(VirtualAddress=0, Size=0)
                 for _ in range(16)]
    mock_pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(
        DATA_DIRECTORY=directory,
    ))
    assert is_dotnet(mock_pe) is False, (
        "PE without a COM descriptor must not be classified as .NET"
    )

    directory[COM_DESCRIPTOR_DIRECTORY_INDEX] = SimpleNamespace(
        VirtualAddress=0x2008, Size=0x48,
    )
    assert is_dotnet(mock_pe) is True


def test_is_dotnet_handles_malformed_pe():
    """A PE object missing OPTIONAL_HEADER or DATA_DIRECTORY must not
    raise — is_dotnet returns False instead, so the caller falls back
    to native-only parsing."""
    from drake_x.integrations.binary.dotnet_parser import is_dotnet
    assert is_dotnet(object()) is False
    assert is_dotnet(SimpleNamespace()) is False
    assert is_dotnet(SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace())) is False


def test_parse_dotnet_on_missing_file_returns_empty_with_warning():
    """Graceful degradation: non-existent paths must not raise."""
    from pathlib import Path

    from drake_x.integrations.binary.dotnet_parser import parse_dotnet
    from drake_x.models.pe import ManagedMetadata

    result = parse_dotnet(Path("/tmp/definitely-not-a-real-path.exe"))
    assert isinstance(result, ManagedMetadata)
    assert result.is_dotnet is False
    assert result.member_refs == []
    assert result.warnings, "missing-file parse must record a warning"


def test_synthesize_native_imports_uniform_projection():
    """P/Invokes and MemberRefs must both surface as PeImport records
    so the downstream graph writer, risk classifier, and rule baseline
    operate uniformly on native and managed samples.
    """
    from drake_x.integrations.binary.dotnet_parser import (
        synthesize_native_imports,
    )
    from drake_x.models.pe import ManagedMetadata

    managed = ManagedMetadata(
        pinvokes=[
            {"dll": "user32.dll", "function": "SetWindowsHookExA"},
            {"dll": "kernel32.dll", "function": "VirtualAllocEx"},
        ],
        member_refs=[
            "System.Net.Mail.SmtpClient.Send",
            "Microsoft.Win32.Registry.SetValue",
        ],
    )
    synth = synthesize_native_imports(managed)
    assert len(synth) == 4

    pinvoke_fns = {i.function for i in synth if i.notes == "pinvoke"}
    assert pinvoke_fns == {"SetWindowsHookExA", "VirtualAllocEx"}

    member_fns = {i.function for i in synth if i.notes == "member_ref"}
    assert member_fns == {
        "System.Net.Mail.SmtpClient.Send",
        "Microsoft.Win32.Registry.SetValue",
    }

    # All synthesized imports preserve notes and have no ordinal.
    assert all(i.ordinal is None for i in synth)
    assert all(i.notes in {"pinvoke", "member_ref"} for i in synth)


def test_synthesize_native_imports_empty_managed():
    """Empty managed metadata must yield zero imports (no spurious
    records that would pollute native-only samples)."""
    from drake_x.integrations.binary.dotnet_parser import (
        synthesize_native_imports,
    )
    from drake_x.models.pe import ManagedMetadata
    assert synthesize_native_imports(ManagedMetadata()) == []


def test_managed_metadata_default_is_not_dotnet():
    """The ManagedMetadata default must be explicitly non-.NET to
    avoid false positives on every native sample."""
    from drake_x.models.pe import ManagedMetadata

    default = ManagedMetadata()
    assert default.is_dotnet is False
    assert default.assembly_refs == []
    assert default.member_refs == []
    assert default.pinvokes == []

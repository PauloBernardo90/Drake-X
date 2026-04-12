"""ELF static analysis engine (v1.0).

Parallels :mod:`drake_x.modules.pe_analyze` at a minimal level:
intake → parse → normalize → graph build.

Exploit-awareness (heuristic indicators, shellcode carving,
protection-interaction) is intentionally deferred beyond v1.0 for ELF
— we ship surface, imports, protections, and graph ingestion.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..integrations.binary.elf_parser import (
    is_available as pyelftools_available,
    parse_elf_full,
    parse_elf_stdlib,
)
from ..logging import get_logger
from ..models.elf import (
    ElfAnalysisResult,
    ElfArch,
    ElfHeader,
    ElfImport,
    ElfMetadata,
    ElfProtection,
    ElfSection,
)
from ..normalize.binary.elf_normalize import build_elf_graph, classify_elf_imports

log = get_logger("elf_analyze")


def run_analysis(elf_path: Path, work_dir: Path) -> ElfAnalysisResult:
    """Run ELF static analysis and return a structured result."""
    sample = Path(elf_path).resolve()
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    result = ElfAnalysisResult()

    # Intake + hashes
    data = sample.read_bytes()
    result.metadata = ElfMetadata(
        file_path=str(sample),
        file_size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        file_type="ELF",
    )

    # Parse
    if pyelftools_available():
        try:
            parsed = parse_elf_full(sample)
            result.tools_ran.append("pyelftools")
        except Exception as exc:
            log.warning("pyelftools parse failed: %s; falling back", exc)
            result.warnings.append(f"pyelftools parse failed: {exc}")
            parsed = parse_elf_stdlib(sample)
            result.tools_ran.append("stdlib-elf")
    else:
        parsed = parse_elf_stdlib(sample)
        result.tools_skipped.append("pyelftools")
        result.warnings.append(
            "pyelftools not installed — imports/sections/protections not populated. "
            "Install with: pip install pyelftools"
        )
        result.tools_ran.append("stdlib-elf")

    # Header
    arch_str = parsed.get("arch", "unknown")
    arch = next((member for member in ElfArch if member.value == arch_str), ElfArch.UNKNOWN)
    result.header = ElfHeader(
        arch=arch,
        bits=int(parsed.get("bits", 0)),
        little_endian=bool(parsed.get("little_endian", True)),
        file_type=str(parsed.get("file_type", "unknown")),
        entry_point=str(parsed.get("entry_point", "")),
        os_abi=str(parsed.get("os_abi", "")),
    )

    # Sections + imports + protections (only present on full parse)
    result.sections = [
        ElfSection(
            name=s.get("name", ""), size=int(s.get("size", 0)),
            flags=list(s.get("flags", [])),
            is_executable=bool(s.get("is_executable", False)),
            is_writable=bool(s.get("is_writable", False)),
        )
        for s in parsed.get("sections", [])
    ]
    result.imports = [
        ElfImport(
            library=str(i.get("library", "")),
            symbol=str(i.get("symbol", "")),
            binding=str(i.get("binding", "")),
            type=str(i.get("type", "")),
        )
        for i in parsed.get("imports", [])
    ]
    prot = parsed.get("protection", {}) or {}
    result.protection = ElfProtection(
        nx_enabled=bool(prot.get("nx_enabled", False)),
        pie_enabled=bool(prot.get("pie_enabled", False)),
        relro=str(prot.get("relro", "none")),
        canary=bool(prot.get("canary", False)),
        fortify_source=bool(prot.get("fortify_source", False)),
    )

    # Risk classification
    result.import_risk_findings = classify_elf_imports(result.imports)

    # Graph snapshot
    graph = build_elf_graph(result)
    result.graph_snapshot = graph.to_dict()

    log.info(
        "ELF analysis complete: arch=%s bits=%s imports=%d sections=%d",
        result.header.arch.value, result.header.bits,
        len(result.imports), len(result.sections),
    )
    return result

"""Turn :class:`ElfAnalysisResult` into findings and graph nodes (v1.0).

Mirrors the public surface of the PE normalizer so report/case
writers can treat ELF symmetrically for v1.0 reporting.
"""

from __future__ import annotations

from ...models.elf import ElfAnalysisResult, ElfImport
from ...models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)


# A small, conservative risk map (dlopen/execve family, memory ops).
_HIGH_RISK_SYMBOLS: dict[str, tuple[str, str]] = {
    "execve": ("execution", "T1059"),
    "execvp": ("execution", "T1059"),
    "system": ("execution", "T1059"),
    "popen": ("execution", "T1059"),
    "fork": ("execution", "T1106"),
    "dlopen": ("execution", "T1620"),
    "dlsym": ("execution", "T1620"),
    "mmap": ("injection", "T1055"),
    "mprotect": ("injection", "T1055"),
    "ptrace": ("evasion", "T1055"),
    "socket": ("communication", "T1071"),
    "connect": ("communication", "T1071"),
    "recv": ("communication", "T1071"),
    "send": ("communication", "T1071"),
}


def classify_elf_imports(imports: list[ElfImport]) -> list[dict]:
    """Deterministic risk classification for ELF imports."""
    out: list[dict] = []
    for imp in imports:
        hit = _HIGH_RISK_SYMBOLS.get(imp.symbol)
        if hit is None:
            continue
        category, technique = hit
        out.append({
            "library": imp.library,
            "symbol": imp.symbol,
            "category": category,
            "risk": "high",
            "technique_id": technique,
        })
    return out


def _short_sha(sha: str) -> str:
    return sha[:16] if sha else "unknown"


def build_elf_graph(result: ElfAnalysisResult) -> EvidenceGraph:
    """Ingest an ELF analysis into the Evidence Graph (v1.0)."""
    graph = EvidenceGraph()
    sha = result.metadata.sha256 or "unknown"
    root = f"elf:{_short_sha(sha)}:artifact"

    graph.add_node(EvidenceNode(
        node_id=root, kind=NodeKind.ARTIFACT, domain="elf",
        label=f"ELF sample {sha[:12]}",
        data={
            "sha256": sha,
            "md5": result.metadata.md5,
            "file_size": result.metadata.file_size,
            "file_type": result.metadata.file_type,
            "arch": result.header.arch.value,
            "bits": result.header.bits,
            "entry_point": result.header.entry_point,
        },
    ))

    # Sections
    for i, sec in enumerate(result.sections):
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in sec.name)
        nid = f"elf:{_short_sha(sha)}:section:{safe or 'unnamed'}:{i}"
        graph.add_node(EvidenceNode(
            node_id=nid, kind=NodeKind.EVIDENCE, domain="elf",
            label=f"section {sec.name}",
            data={
                "name": sec.name, "ordinal": i, "size": sec.size,
                "flags": list(sec.flags),
                "is_executable": sec.is_executable,
                "is_writable": sec.is_writable,
            },
        ))
        graph.add_edge(EvidenceEdge(
            source_id=nid, target_id=root, edge_type=EdgeType.DERIVED_FROM,
            notes="ELF section",
        ))

    # Imports
    risk_map = {(f.get("library", ""), f.get("symbol", "")): f
                for f in result.import_risk_findings}
    for imp in result.imports:
        nid = f"elf:{_short_sha(sha)}:import:{imp.library or '_'}:{imp.symbol}"
        risk = risk_map.get((imp.library, imp.symbol))
        data = {
            "library": imp.library, "symbol": imp.symbol,
            "binding": imp.binding, "type": imp.type,
        }
        if risk:
            data["risk"] = risk.get("risk")
            data["category"] = risk.get("category")
            data["attck"] = risk.get("technique_id")
            # also feed the cross-sample correlator's shared_import basis
            data["dll"] = imp.library or "libc"
            data["function"] = imp.symbol
        graph.add_node(EvidenceNode(
            node_id=nid, kind=NodeKind.EVIDENCE, domain="elf",
            label=f"import {imp.library or '?'}!{imp.symbol}",
            data=data,
        ))
        graph.add_edge(EvidenceEdge(
            source_id=nid, target_id=root, edge_type=EdgeType.DERIVED_FROM,
            notes="ELF import",
        ))

    # Protections
    prot = result.protection
    for name, enabled in [
        ("NX", prot.nx_enabled),
        ("PIE", prot.pie_enabled),
        ("CANARY", prot.canary),
        ("FORTIFY", prot.fortify_source),
    ]:
        nid = f"elf:{_short_sha(sha)}:protection:{name.lower()}"
        graph.add_node(EvidenceNode(
            node_id=nid, kind=NodeKind.PROTECTION, domain="elf",
            label=f"protection {name}",
            data={"protection": name, "enabled": bool(enabled)},
        ))
        graph.add_edge(EvidenceEdge(
            source_id=nid, target_id=root, edge_type=EdgeType.DERIVED_FROM,
        ))
    # RELRO is three-state; record as a single node.
    nid = f"elf:{_short_sha(sha)}:protection:relro"
    graph.add_node(EvidenceNode(
        node_id=nid, kind=NodeKind.PROTECTION, domain="elf",
        label="protection RELRO",
        data={"protection": "RELRO", "enabled": prot.relro != "none", "state": prot.relro},
    ))
    graph.add_edge(EvidenceEdge(
        source_id=nid, target_id=root, edge_type=EdgeType.DERIVED_FROM,
    ))

    return graph

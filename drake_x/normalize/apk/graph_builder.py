"""Build an :class:`EvidenceGraph` from an :class:`ApkAnalysisResult`.

This is the cross-domain bridge: it takes the APK-specific analysis
result and produces a generic evidence graph that the AI tasks,
reporting layer, and future CTI enrichment can consume without knowing
anything about APK internals.

Node IDs are prefixed with ``apk:`` to avoid collisions with web-domain
or recon-domain nodes in a unified graph.
"""

from __future__ import annotations

from ...models.apk import ApkAnalysisResult, CampaignSimilarity, ProtectionStatus
from ...models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)


def build_apk_evidence_graph(result: ApkAnalysisResult) -> EvidenceGraph:
    """Convert an APK analysis result into an evidence graph."""
    g = EvidenceGraph()

    # Root node — the sample itself
    root_id = f"apk:sample:{result.metadata.sha256[:12]}"
    g.add_node(EvidenceNode(
        node_id=root_id,
        kind=NodeKind.ARTIFACT,
        domain="apk",
        label=result.metadata.package_name or result.metadata.sha256[:12],
        data={
            "sha256": result.metadata.sha256,
            "package_name": result.metadata.package_name,
            "file_size": result.metadata.file_size,
        },
    ))

    # Permissions as evidence nodes
    for perm in result.permissions:
        pid = f"apk:perm:{perm.name}"
        g.add_node(EvidenceNode(
            node_id=pid,
            kind=NodeKind.EVIDENCE,
            domain="apk",
            label=perm.name.split(".")[-1],
            data={"full_name": perm.name, "dangerous": perm.is_dangerous, "suspicious": perm.is_suspicious},
        ))
        g.link(pid, root_id, EdgeType.DERIVED_FROM)

    # Behavior indicators as finding nodes
    for i, bi in enumerate(result.behavior_indicators):
        bid = f"apk:behavior:{i}:{bi.category}"
        g.add_node(EvidenceNode(
            node_id=bid,
            kind=NodeKind.FINDING,
            domain="apk",
            label=bi.pattern,
            data={"category": bi.category, "confidence": bi.confidence, "evidence": bi.evidence},
        ))
        g.link(bid, root_id, EdgeType.DERIVED_FROM, confidence=bi.confidence)

        # Link behavior to supporting permissions where relevant
        if bi.category == "exfiltration":
            for perm in result.permissions:
                if perm.is_suspicious and any(
                    kw in perm.name.lower() for kw in ["sms", "contacts", "location", "camera", "phone"]
                ):
                    g.link(f"apk:perm:{perm.name}", bid, EdgeType.SUPPORTS, confidence=0.7)

    # Network indicators
    for i, ni in enumerate(result.network_indicators):
        nid = f"apk:net:{i}:{ni.indicator_type}"
        g.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.INDICATOR,
            domain="apk",
            label=ni.value[:60],
            data={"value": ni.value, "type": ni.indicator_type, "source": ni.source_file},
        ))
        g.link(nid, root_id, EdgeType.DERIVED_FROM)
        # Link network IOCs to communication behaviors
        for e in g.edges:
            if "communication" in e.source_id:
                g.link(nid, e.source_id, EdgeType.SUPPORTS, confidence=0.6)
                break

    # Obfuscation traits
    for i, ot in enumerate(result.obfuscation_traits):
        oid = f"apk:obfuscation:{i}:{ot.trait}"
        g.add_node(EvidenceNode(
            node_id=oid,
            kind=NodeKind.EVIDENCE,
            domain="apk",
            label=ot.trait,
            data={"confidence": ot.confidence.value, "evidence": ot.evidence},
        ))
        g.link(oid, root_id, EdgeType.DERIVED_FROM)

    # Protection indicators
    for pi in result.protection_indicators:
        if pi.status == ProtectionStatus.NOT_OBSERVED:
            continue
        pid = f"apk:protection:{pi.protection_type}"
        g.add_node(EvidenceNode(
            node_id=pid,
            kind=NodeKind.PROTECTION,
            domain="apk",
            label=pi.protection_type,
            data={"status": pi.status.value, "evidence": pi.evidence},
        ))
        g.link(pid, root_id, EdgeType.DERIVED_FROM)

    # Campaign assessments
    for ca in result.campaign_assessments:
        if ca.similarity == CampaignSimilarity.INSUFFICIENT_EVIDENCE:
            continue
        cid = f"apk:campaign:{ca.category}"
        g.add_node(EvidenceNode(
            node_id=cid,
            kind=NodeKind.CAMPAIGN,
            domain="apk",
            label=ca.category,
            data={
                "similarity": ca.similarity.value,
                "confidence": ca.confidence,
                "traits": ca.matching_traits,
            },
        ))
        # Campaign is supported by the behaviors that contributed to it
        for i, bi in enumerate(result.behavior_indicators):
            bid = f"apk:behavior:{i}:{bi.category}"
            if bi.category in ca.category or bi.pattern in " ".join(ca.matching_traits):
                g.link(bid, cid, EdgeType.SUPPORTS, confidence=0.5)
        g.link(cid, root_id, EdgeType.RELATED_TO)

    # Native binary analysis (structured Ghidra export)
    for i, na in enumerate(result.native_analysis):
        bname = na.binary_path.rsplit("/", 1)[-1] if "/" in na.binary_path else na.binary_path
        nid = f"apk:native:{i}:{bname}"
        g.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.ARTIFACT,
            domain="apk",
            label=bname,
            data={
                "binary_path": na.binary_path,
                "architecture": na.architecture,
                "function_count": na.function_count,
                "jni_export_count": len(na.jni_exports),
                "suspicious_count": len(na.suspicious_functions),
                "source_label": na.source_label,
            },
        ))
        g.link(nid, root_id, EdgeType.DERIVED_FROM)

        # JNI exports as indicator nodes
        for j, export in enumerate(na.jni_exports[:10]):
            eid = f"apk:native_jni:{i}:{j}:{export.name}"
            g.add_node(EvidenceNode(
                node_id=eid,
                kind=NodeKind.INDICATOR,
                domain="apk",
                label=export.name,
                data={"address": export.address, "binary": na.binary_path},
            ))
            g.link(eid, nid, EdgeType.DERIVED_FROM, confidence=0.95)

        # Suspicious function indicators
        for j, fn_name in enumerate(na.suspicious_functions[:10]):
            sid = f"apk:native_suspicious:{i}:{j}"
            g.add_node(EvidenceNode(
                node_id=sid,
                kind=NodeKind.INDICATOR,
                domain="apk",
                label=fn_name[:60],
                data={"indicator": fn_name, "binary": na.binary_path},
            ))
            g.link(sid, nid, EdgeType.DERIVED_FROM, confidence=0.7)
            # Link to relevant protections if names match
            for pi in result.protection_indicators:
                if pi.status == ProtectionStatus.NOT_OBSERVED:
                    continue
                pid = f"apk:protection:{pi.protection_type}"
                if g.get_node(pid) and any(
                    kw in fn_name.lower()
                    for kw in pi.protection_type.replace("_", " ").split()
                ):
                    g.link(sid, pid, EdgeType.SUPPORTS, confidence=0.6)

    return g

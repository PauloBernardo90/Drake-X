"""Tests for response diffing (session-to-session artifact comparison)."""

from __future__ import annotations

from drake_x.models.artifact import Artifact
from drake_x.normalize.diff import SessionDiff, diff_sessions


def _art(kind: str, tool: str, payload: dict, confidence: float = 0.9) -> Artifact:
    return Artifact(
        tool_name=tool,
        kind=kind,
        payload=payload,
        confidence=confidence,
        notes=[],
    )


def test_identical_sessions_produce_empty_diff() -> None:
    arts = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    result = diff_sessions(
        session_a_id="aaa",
        session_b_id="bbb",
        artifacts_a=arts,
        artifacts_b=arts,
    )
    assert result.entries == []
    assert result.added == []
    assert result.removed == []
    assert result.changed == []


def test_added_artifact_detected() -> None:
    a = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    b = a + [_art("web.http_probe", "httpx", {"status_code": 200})]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    assert len(result.added) == 1
    assert result.added[0].kind == "web.http_probe"


def test_removed_artifact_detected() -> None:
    a = [
        _art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}}),
        _art("nmap.ports", "nmap", {"open_port_count": 3}),
    ]
    b = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    assert len(result.removed) == 1
    assert result.removed[0].kind == "nmap.ports"


def test_changed_artifact_detected() -> None:
    a = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    b = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4", "5.6.7.8"]}})]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    assert len(result.changed) == 1
    assert result.changed[0].kind == "dns.records"
    assert "changed_keys" in result.changed[0].detail


def test_to_dict_round_trips() -> None:
    a = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    b = [_art("dns.records", "dig", {"records": {"A": ["5.6.7.8"]}})]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    d = result.to_dict()
    assert d["session_a"] == "a"
    assert d["changed_count"] == 1
    assert d["entries"][0]["change"] == "changed"


def test_to_markdown_renders_sections() -> None:
    a = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}})]
    b = [
        _art("dns.records", "dig", {"records": {"A": ["5.6.7.8"]}}),
        _art("web.http_probe", "httpx", {"status_code": 200}),
    ]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    md = result.to_markdown()
    assert "# Surface diff" in md
    assert "## Added" in md
    assert "## Changed" in md
    assert "httpx" in md


def test_duplicate_artifacts_keep_higher_confidence() -> None:
    """When two artifacts share (kind, tool) in one session, keep the more confident one."""
    a = [
        _art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}}, confidence=0.5),
        _art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}}, confidence=0.9),
    ]
    b = [_art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}}, confidence=0.9)]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    assert result.entries == []  # same payload — no change


def test_mixed_add_remove_change() -> None:
    a = [
        _art("dns.records", "dig", {"records": {"A": ["1.2.3.4"]}}),
        _art("nmap.ports", "nmap", {"ports": [80]}),
    ]
    b = [
        _art("dns.records", "dig", {"records": {"A": ["5.6.7.8"]}}),
        _art("web.http_probe", "httpx", {"status_code": 200}),
    ]
    result = diff_sessions(session_a_id="a", session_b_id="b", artifacts_a=a, artifacts_b=b)
    assert len(result.added) == 1      # httpx
    assert len(result.removed) == 1    # nmap
    assert len(result.changed) == 1    # dig

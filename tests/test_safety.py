"""Tests for the v0.2 safety layer: scope file, enforcer, policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.exceptions import ScopeFileError
from drake_x.models.scope import ScopeAsset, ScopeFile
from drake_x.safety.enforcer import ScopeEnforcer
from drake_x.safety.policy import ActionPolicy, PolicyClassifier
from drake_x.safety.scope_file import (
    DEFAULT_SCOPE_TEMPLATE,
    load_scope_file,
    save_scope_file,
    write_scope_template,
)
from drake_x.scope import parse_target


def _scope(**overrides) -> ScopeFile:
    base = ScopeFile(
        engagement="test",
        authorization_reference="TEST-1",
        in_scope=[ScopeAsset(kind="domain", value="example.com")],
        out_of_scope=[],
    )
    return base.model_copy(update=overrides)


def test_write_scope_template_refuses_overwrite(tmp_path: Path) -> None:
    p = tmp_path / "scope.yaml"
    write_scope_template(p)
    assert p.exists()
    with pytest.raises(ScopeFileError):
        write_scope_template(p)


def test_load_default_scope_template(tmp_path: Path) -> None:
    p = tmp_path / "scope.yaml"
    p.write_text(DEFAULT_SCOPE_TEMPLATE, encoding="utf-8")
    sf = load_scope_file(p)
    assert sf.engagement == "example-engagement"
    assert sf.allow_active is False
    assert any(a.kind == "domain" and a.value == "example.com" for a in sf.in_scope)
    # Regression: the authorization_reference contains a literal `#` inside
    # the quoted string. The fallback YAML parser used to truncate at the
    # first `#`, leaving the field invalid.
    assert "REPLACE-ME" in sf.authorization_reference
    assert "PO #" in sf.authorization_reference


def test_save_and_reload_scope_file(tmp_path: Path) -> None:
    sf = _scope()
    out = tmp_path / "scope.json"
    save_scope_file(sf, out)
    loaded = load_scope_file(out)
    assert loaded.engagement == sf.engagement
    assert loaded.in_scope[0].value == "example.com"


def test_enforcer_allows_in_scope_domain() -> None:
    enforcer = ScopeEnforcer(_scope())
    decision = enforcer.check_target(parse_target("example.com"))
    assert decision.allowed
    assert decision.matched_in_scope is not None


def test_enforcer_denies_unrelated_domain() -> None:
    enforcer = ScopeEnforcer(_scope())
    decision = enforcer.check_target(parse_target("other.test"))
    assert decision.allowed is False


def test_enforcer_wildcard_domain() -> None:
    sf = _scope(
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")]
    )
    enforcer = ScopeEnforcer(sf)
    assert enforcer.check_target(parse_target("api.example.com")).allowed
    assert enforcer.check_target(parse_target("example.com")).allowed
    assert enforcer.check_target(parse_target("evil.test")).allowed is False


def test_enforcer_out_of_scope_wins() -> None:
    sf = _scope(
        in_scope=[ScopeAsset(kind="wildcard_domain", value="example.com")],
        out_of_scope=[ScopeAsset(kind="domain", value="api.example.com")],
    )
    enforcer = ScopeEnforcer(sf)
    api = enforcer.check_target(parse_target("api.example.com"))
    assert api.allowed is False
    assert api.matched_out_of_scope is not None


def test_enforcer_cidr_match() -> None:
    sf = _scope(
        in_scope=[ScopeAsset(kind="cidr", value="192.0.2.0/24")]
    )
    enforcer = ScopeEnforcer(sf)
    assert enforcer.check_target(parse_target("192.0.2.10")).allowed
    assert enforcer.check_target(parse_target("198.51.100.1")).allowed is False


def test_enforcer_url_prefix() -> None:
    sf = _scope(
        in_scope=[ScopeAsset(kind="url_prefix", value="https://example.com/api/")]
    )
    enforcer = ScopeEnforcer(sf)
    assert enforcer.check_target(parse_target("https://example.com/api/v1/users")).allowed
    assert enforcer.check_target(parse_target("https://example.com/login")).allowed is False


def test_policy_classifier_passive_always_ok() -> None:
    classifier = PolicyClassifier(_scope())
    decision = classifier.decide("whois")
    assert decision.allowed
    assert decision.requires_confirmation is False
    assert decision.policy == ActionPolicy.PASSIVE


def test_policy_classifier_active_blocked_without_allow_active() -> None:
    classifier = PolicyClassifier(_scope(allow_active=False))
    decision = classifier.decide("nmap")
    assert decision.allowed is False
    assert decision.requires_confirmation is True


def test_policy_classifier_active_allowed_when_authorized() -> None:
    classifier = PolicyClassifier(_scope(allow_active=True))
    decision = classifier.decide("nmap")
    assert decision.allowed is True
    assert decision.requires_confirmation is True

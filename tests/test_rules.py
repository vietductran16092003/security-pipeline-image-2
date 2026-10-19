from pathlib import Path

import pytest

from scanner.models import Finding
from scanner.rules import apply_rules, load_rules

RULES = Path(__file__).resolve().parent.parent / "rules.yaml"


@pytest.mark.parametrize("f,expected", [
    (Finding("gitleaks", "secret", "k", "CRITICAL", "t"), "P1"),
    (Finding("trivy", "vuln", "C", "CRITICAL", "t"), "P1"),
    (Finding("trivy", "vuln", "C", "HIGH", "t", fixed_version="1.2"), "P1"),
    (Finding("trivy", "vuln", "C", "HIGH", "t", fixed_version=None), "P2"),
    (Finding("trivy", "vuln", "C", "MEDIUM", "t", base_os_eol=True), "Backlog"),
    (Finding("trivy", "vuln", "C", "MEDIUM", "t"), "P2"),
    (Finding("trivy", "vuln", "C", "LOW", "t"), "Backlog"),
    (Finding("semgrep", "code", "r", "HIGH", "t"), "P1"),
    (Finding("trivy", "config", "KSV017", "HIGH", "t"), "P1"),
    (Finding("conftest", "policy", "deny:x", "HIGH", "t"), "P2"),
    (Finding("conftest", "policy", "warn:x", "LOW", "t"), "Backlog"),
    (Finding("semgrep", "code", "r", "UNKNOWN", "t"), "Backlog"),
])
def test_real_rules(f, expected):
    apply_rules([f], load_rules(RULES))
    assert f.priority == expected and f.reason and f.recommendation


def _rule(when="True", priority="P1"):
    return {"name": "x", "when": when, "priority": priority, "reason": "r", "recommendation": "r"}


def test_unmatched_raises():
    with pytest.raises(ValueError):
        apply_rules([Finding("t", "vuln", "C", "LOW", "t")], [_rule(when="False")])


def test_bad_priority_raises():
    with pytest.raises(ValueError):
        apply_rules([Finding("t", "vuln", "C", "LOW", "t")], [_rule(priority="P9")])


def test_broken_expression_treated_as_no_match():
    f = Finding("t", "vuln", "C", "LOW", "t")
    apply_rules([f], [_rule(when="nonexistent_field == 1", priority="P1"), _rule(priority="Backlog")])
    assert f.priority == "Backlog"


def test_first_match_wins():
    f = Finding("t", "vuln", "C", "LOW", "t")
    apply_rules([f], [_rule(priority="P2"), _rule(priority="P1")])
    assert f.priority == "P2"


def test_empty_list_ok():
    apply_rules([], load_rules(RULES))

import pytest

from scanner.models import Finding, Report
from conftest import make_report, vuln


def test_key_uses_package_then_file():
    assert Finding("trivy", "vuln", "CVE-1", "HIGH", "t", package="openssl").key() == "trivy:CVE-1:openssl"
    assert Finding("gitleaks", "secret", "aws-key", "CRITICAL", "t", file="a.env").key() == "gitleaks:aws-key:a.env"


def test_counts():
    r = make_report([vuln("A", "P1"), vuln("B", "P2"), vuln("C", "Backlog"), vuln("D", "P1")])
    assert r.counts() == {"P1": 2, "P2": 1, "Backlog": 1, "total": 4}


def test_json_roundtrip():
    r = make_report([vuln("A", "P1"), vuln("B", "P2", fixed=None)])
    assert Report.from_json(r.to_json()) == r


def test_section_lookup():
    r = make_report([])
    assert r.section("deps").id == "deps"
    assert r.section("nope") is None


@pytest.mark.parametrize("bad", ["not json", '{"schema_version": 2}', "{}", "[]"])
def test_from_json_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        Report.from_json(bad)

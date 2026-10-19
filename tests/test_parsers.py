import json
from dataclasses import asdict
from pathlib import Path

from scanner.parsers import parse_conftest, parse_gitleaks, parse_semgrep, parse_trivy

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_trivy_vuln_fields():
    f = parse_trivy(load("trivy-image.json"))[0]
    assert (f.kind, f.tool) == ("vuln", "trivy")
    assert f.rule_id.startswith("CVE-") and f.package and f.installed_version and f.file


def test_trivy_missing_fix_is_none():
    found = parse_trivy(load("trivy-image.json"))
    assert any(f.fixed_version is None for f in found)
    assert any(f.fixed_version for f in found)


def test_trivy_eosl_flag():
    assert all(f.base_os_eol for f in parse_trivy(load("trivy-image.json")))
    assert not any(f.base_os_eol for f in parse_trivy(load("trivy-fs.json")))


def test_trivy_misconfig():
    f = parse_trivy(load("trivy-config.json"))[0]
    assert f.kind == "config" and f.rule_id and f.file and f.line is not None


def test_trivy_empty_results():
    assert parse_trivy({"Results": None}) == []
    assert parse_trivy({}) == []
    assert parse_trivy({"Results": [{"Target": "x", "Vulnerabilities": None}]}) == []


def test_semgrep_fields_and_severity_map():
    found = parse_semgrep(load("semgrep.json"))
    assert found and all(f.kind == "code" and f.file and f.line for f in found)
    assert {f.severity for f in found} <= {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    assert "HIGH" in {f.severity for f in found}


def test_gitleaks_never_stores_secret():
    raw = load("gitleaks.json")
    found = parse_gitleaks(raw)
    dumped = json.dumps([asdict(f) for f in found])
    assert found[0].kind == "secret" and found[0].severity == "CRITICAL"
    assert raw[0]["Secret"] not in dumped and raw[0]["Match"] not in dumped


def test_conftest_deny_and_warn():
    found = parse_conftest(load("conftest.json"))
    assert sorted(f.severity for f in found) == ["HIGH", "LOW"]
    assert {f.rule_id.split(":")[0] for f in found} == {"deny", "warn"}
    assert all(f.kind == "policy" and f.file for f in found)

from pathlib import Path

import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scan.yml"


def _steps():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))["jobs"]["scan"]["steps"]


def test_scanner_module_not_shadowed_by_project_files():
    """`python -m scanner` chạy trong thư mục dự án; dự án có thư mục `scanner/` không được che bộ quét."""
    runs = [s["run"] for s in _steps() if "run" in s and "-m scanner" in s["run"]]
    assert runs and all("python -P -m scanner" in r for r in runs)


def test_project_and_scanner_in_separate_dirs():
    """Build context của dự án không được lẫn mã bộ quét hay thư mục output."""
    steps = _steps()
    checkouts = [s for s in steps if "actions/checkout" in s.get("uses", "")]
    paths = {s["with"].get("path") for s in checkouts}
    assert paths == {"project", "scanner-src"}
    run = next(s["run"] for s in steps if "run" in s and "scanner run" in s["run"])
    assert "--root project" in run and "--scanner-dir scanner-src" in run
    assert "--out ${{ runner.temp }}/scan-out" in run


def test_outputs_read_from_runner_temp():
    steps = _steps()
    upload = next(s for s in steps if "upload-artifact" in s.get("uses", ""))
    assert all(p.startswith("${{ runner.temp }}/scan-out/") for p in upload["with"]["path"].strip().splitlines())
    for s in steps:
        if "run" in s and ("summary.md" in s["run"] or "scanner send" in s["run"]):
            assert "${{ runner.temp }}/scan-out" in s["run"]


def test_self_scan_runs_policy_tests():
    from scanner.runner import TOOL_IMAGES
    self_scan = yaml.safe_load((WF.parent / "self-scan.yml").read_text(encoding="utf-8"))
    runs = " ".join(s.get("run", "") for s in self_scan["jobs"]["test"]["steps"])
    assert TOOL_IMAGES["conftest"] in runs and "verify" in runs and "tests/policy" in runs


def test_artifact_upload_survives_rerun():
    upload = next(s for s in _steps() if "upload-artifact" in s.get("uses", ""))
    assert upload["with"]["overwrite"] is True

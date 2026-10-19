from pathlib import Path

import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "scan.yml"


def _steps():
    return yaml.safe_load(WF.read_text(encoding="utf-8"))["jobs"]["scan"]["steps"]


def test_scanner_module_not_shadowed_by_project_files():
    """`python -m scanner` chạy trong thư mục dự án; dự án có thư mục `scanner/` không được che bộ quét."""
    runs = [s["run"] for s in _steps() if "run" in s and "-m scanner" in s["run"]]
    assert runs and all("python -P -m scanner" in r for r in runs)


def test_artifact_upload_survives_rerun():
    upload = next(s for s in _steps() if "upload-artifact" in s.get("uses", ""))
    assert upload["with"]["overwrite"] is True

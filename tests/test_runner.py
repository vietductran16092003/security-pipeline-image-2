import shutil
from pathlib import Path

import pytest

from scanner.models import SECTION_IDS
from scanner.runner import TOOL_IMAGES, build_commands, count_ignore_rules, run_scan

FIX = Path(__file__).parent / "fixtures"
SCANNER_DIR = Path(__file__).resolve().parent.parent


class FakeExecutor:
    """Giả lập công cụ: ghi fixture vào đúng file output, trả exit code theo kịch bản."""

    def __init__(self, out, exit_codes=None, write=True, overrides=None):
        self.out, self.exit_codes, self.write = out, exit_codes or {}, write
        self.overrides = overrides or {}
        self.calls = []

    def __call__(self, cmd, stdout_path=None, timeout=None):
        self.calls.append(cmd)
        joined = " ".join(cmd)
        for needle, code in self.exit_codes.items():
            if needle in joined:
                if code not in (0, 1):
                    return code
        target = stdout_path
        if target is None:
            outs = [a for a in cmd if a.startswith("/out/")]
            target = self.out / outs[0][len("/out/"):] if outs else None
        if target is not None and self.write:
            name = Path(target).name
            if name in self.overrides:
                Path(target).write_text(self.overrides[name], encoding="utf-8")
            elif (FIX / name).exists():
                shutil.copy(FIX / name, target)
        for needle, code in self.exit_codes.items():
            if needle in joined:
                return code
        return 0


def section(secs, sid):
    return next(s for s in secs if s.id == sid)


@pytest.fixture
def out(tmp_path):
    d = tmp_path / "out"
    d.mkdir()
    return d


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


def full_project(p):
    (p / "requirements.txt").write_text("requests==2.19.0\n")
    (p / "Dockerfile").write_text("FROM alpine\n")
    (p / "pod.yaml").write_text("apiVersion: v1\nkind: Pod\n")
    return p


def test_six_sections_in_order(proj, out):
    secs = run_scan(proj, out, SCANNER_DIR, FakeExecutor(out))
    assert [s.id for s in secs] == list(SECTION_IDS)


def test_skipped_has_reason(proj, out):
    s = section(run_scan(proj, out, SCANNER_DIR, FakeExecutor(out)), "image")
    assert s.status == "skipped" and "Dockerfile" in s.detail


def test_full_project_all_sections_have_findings(proj, out):
    secs = run_scan(full_project(proj), out, SCANNER_DIR, FakeExecutor(out))
    assert {s.id: s.status for s in secs} == {sid: "findings" for sid in SECTION_IDS}


def test_exit0_but_no_output_is_error(proj, out):
    s = section(run_scan(full_project(proj), out, SCANNER_DIR, FakeExecutor(out, write=False)), "deps")
    assert s.status == "error" and "output" in s.detail


def test_corrupt_json_is_error(proj, out):
    fake = FakeExecutor(out, overrides={"trivy-fs.json": "{bad"})
    s = section(run_scan(full_project(proj), out, SCANNER_DIR, fake), "deps")
    assert s.status == "error" and "JSON" in s.detail


def test_docker_build_fail_is_error_others_continue(proj, out):
    fake = FakeExecutor(out, exit_codes={"docker build": 1})
    secs = run_scan(full_project(proj), out, SCANNER_DIR, fake)
    img = section(secs, "image")
    assert img.status == "error" and "docker build" in img.detail
    assert section(secs, "secrets").status == "findings"
    assert not any(TOOL_IMAGES["trivy"] in c and "image" in c for c in fake.calls)  # không quét image khi build hỏng


def test_tool_nonzero_exit_is_error(proj, out):
    s = section(run_scan(proj, out, SCANNER_DIR, FakeExecutor(out, exit_codes={"semgrep": 2})), "code")
    assert s.status == "error" and "exit 2" in s.detail


def test_conftest_exit1_ok(proj, out):
    fake = FakeExecutor(out, exit_codes={"conftest": 1})
    assert section(run_scan(full_project(proj), out, SCANNER_DIR, fake), "dockerfile_policy").status == "findings"


def test_clean_when_tool_reports_nothing(proj, out):
    fake = FakeExecutor(out, overrides={"gitleaks.json": "[]"})
    assert section(run_scan(proj, out, SCANNER_DIR, fake), "secrets").status == "clean"


def test_container_paths_made_relative(proj, out):
    sg = '{"results": [{"check_id": "r", "path": "/repo/src/app.py", "start": {"line": 3}, "extra": {"message": "m", "severity": "ERROR"}}]}'
    fake = FakeExecutor(out, overrides={"semgrep.json": sg})
    f = section(run_scan(proj, out, SCANNER_DIR, fake), "code").findings[0]
    assert f.file == "src/app.py"


def test_commands_use_pinned_images_and_skip_scanner_dir(proj, out):
    cmds = [c for sid in SECTION_IDS for c in build_commands(sid, proj, out, SCANNER_DIR)]
    images = {a for c in cmds for a in c if a in TOOL_IMAGES.values()}
    assert images == set(TOOL_IMAGES.values())
    assert all(":latest" not in v and ":" in v for v in TOOL_IMAGES.values())
    trivy_scans = [c for c in cmds if TOOL_IMAGES["trivy"] in c and ("fs" in c or "config" in c)]
    assert all(".scanner" in " ".join(c) for c in trivy_scans)
    gitleaks = next(c for c in cmds if TOOL_IMAGES["gitleaks"] in c)
    assert "--redact" in gitleaks


def test_trivyignore_passed_to_every_trivy_scan(proj, out):
    (proj / ".trivyignore").write_text("CVE-1\n")
    for sid in ("deps", "image", "iac"):
        trivy = next(c for c in build_commands(sid, proj, out, SCANNER_DIR) if TOOL_IMAGES["trivy"] in c)
        assert "--ignorefile" in trivy and trivy[trivy.index("--ignorefile") + 1] == "/repo/.trivyignore"
        assert any(m.endswith(":/repo:ro") or m.endswith(":/repo") for m in trivy)


def test_no_ignorefile_flag_without_file(proj, out):
    trivy = build_commands("deps", proj, out, SCANNER_DIR)[0]
    assert "--ignorefile" not in trivy


def test_git_safe_directory_for_git_tools(proj, out):
    for sid in ("secrets", "code"):
        cmd = " ".join(build_commands(sid, proj, out, SCANNER_DIR)[0])
        assert "GIT_CONFIG_KEY_0=safe.directory" in cmd and "GIT_CONFIG_VALUE_0=/repo" in cmd


class Clock:
    def __init__(self, step):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


def test_deadline_marks_remaining_sections_error(proj, out):
    fake = FakeExecutor(out)
    secs = run_scan(full_project(proj), out, SCANNER_DIR, fake, deadline=100, clock=Clock(40))
    statuses = {s.id: s.status for s in secs}
    assert statuses["secrets"] == "findings"
    late = [s for s in secs if s.status == "error"]
    assert late and all("Hết thời gian" in s.detail for s in late)
    assert len(secs) == 6


def test_executor_gets_remaining_time(proj, out):
    seen = []

    def ex(cmd, stdout_path=None, timeout=None):
        seen.append(timeout)
        return FakeExecutor(out)(cmd, stdout_path)
    run_scan(proj, out, SCANNER_DIR, ex, deadline=500, clock=Clock(1))
    assert seen and all(t is not None and t <= 500 for t in seen)


def test_docker_run_commands_are_named(proj, out):
    for sid in SECTION_IDS:
        for c in build_commands(sid, full_project(proj), out, SCANNER_DIR):
            if c[:2] == ["docker", "run"]:
                assert "--name" in c


def test_count_ignore_rules(tmp_path):
    (tmp_path / ".trivyignore").write_text("# c\nCVE-1\n\nCVE-2\n")
    (tmp_path / ".gitleaksignore").write_text("abc:a.env:aws:1\n")
    (tmp_path / "a.py").write_text("x = 1  # nosemgrep\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.py").write_text("# nosemgrep\n")
    assert count_ignore_rules(tmp_path) == 4

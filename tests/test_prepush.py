import json
from pathlib import Path

import pytest

from scanner.__main__ import main
from scanner.prepush import RefUpdate, commit_range, parse_ref_lines, prepush
from test_cli import FakeDocker
from test_runner import FakeExecutor

SCANNER_DIR = Path(__file__).resolve().parent.parent
ZERO = "0" * 40
A, B = "a" * 40, "b" * 40
EMPTY_TRIVY = json.dumps({"Results": []})
MED_TRIVY = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
    "VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1", "FixedVersion": "2",
    "Title": "t", "Severity": "MEDIUM"}]}]})


class Exec(FakeExecutor):
    def __init__(self, tmp, overrides=None, boom=False):
        out = tmp / "unused"
        out.mkdir(exist_ok=True)
        super().__init__(out, overrides=overrides)
        self.boom = boom

    def __call__(self, cmd, stdout_path=None, timeout=None):
        if self.boom:
            raise RuntimeError("scanner exploded")
        # ghi vào thư mục /out thật: tìm mount "<dir>:/out"
        mount = next(a for a in cmd if a.endswith(":/out"))
        self.out = Path(mount[: -len(":/out")])
        return super().__call__(cmd, stdout_path, timeout)


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "requirements.txt").write_text("x==1\n")
    return p


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("SCAN_SKIP", raising=False)


def line(local=A, remote=B):
    return f"refs/heads/main {local} refs/heads/main {remote}\n"


def test_parse_and_ranges():
    ups = parse_ref_lines(line() + line(ZERO, B) + line(A, ZERO) + "\n")
    assert [(u.local_sha, u.remote_sha) for u in ups] == [(A, B), (ZERO, B), (A, ZERO)]
    assert commit_range(ups[0]) == f"{B}..{A}"
    assert commit_range(ups[1]) is None
    assert commit_range(ups[2]) == f"{A} --not --remotes"


def test_blocks_on_secret_in_pushed_commits(proj, tmp_path, capsys):
    ex = Exec(tmp_path, overrides={"trivy-fs.json": EMPTY_TRIVY})
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 1
    out = capsys.readouterr().out
    assert "config.env" in out and "aws-access-token" in out
    assert "git push --no-verify" in out and "SCAN_SKIP=1" in out
    assert "AKIAIOSFODNN7REALKEY" not in out
    gl = next(c for c in ex.calls if "detect" in c)
    assert f"--log-opts={B}..{A}" in gl


def test_blocks_on_p1_dependency(proj, tmp_path, capsys):
    ex = Exec(tmp_path, overrides={"gitleaks.json": "[]"})
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 1
    assert "[P1]" in capsys.readouterr().out


def test_allows_when_only_p2_or_backlog(proj, tmp_path):
    ex = Exec(tmp_path, overrides={"gitleaks.json": "[]", "trivy-fs.json": MED_TRIVY})
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 0


def test_delete_branch_is_not_scanned(proj, tmp_path):
    ex = Exec(tmp_path)
    assert prepush(proj, line(ZERO, B), SCANNER_DIR, ex, FakeDocker()) == 0
    assert ex.calls == []


def test_new_branch_range_covers_only_unpushed_commits(proj, tmp_path):
    ex = Exec(tmp_path, overrides={"gitleaks.json": "[]", "trivy-fs.json": EMPTY_TRIVY})
    assert prepush(proj, line(A, ZERO), SCANNER_DIR, ex, FakeDocker()) == 0
    gl = next(c for c in ex.calls if "detect" in c)
    assert f"--log-opts={A} --not --remotes" in gl
    assert "--no-git" not in gl


def test_docker_unavailable_allows_push_with_warning(proj, tmp_path, capsys):
    ex = Exec(tmp_path)
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker(error="Docker chưa chạy")) == 0
    out = capsys.readouterr().err
    assert "Docker chưa chạy" in out and "KHÔNG ĐƯỢC KIỂM TRA" in out
    assert ex.calls == []


def test_scan_skip_env_bypasses(proj, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCAN_SKIP", "1")
    ex = Exec(tmp_path)
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 0
    assert ex.calls == [] and "SCAN_SKIP" in capsys.readouterr().out


def test_scanner_crash_allows_push_with_warning(proj, tmp_path, capsys):
    assert prepush(proj, line(), SCANNER_DIR, Exec(tmp_path, boom=True), FakeDocker()) == 0
    assert "KHÔNG ĐƯỢC KIỂM TRA" in capsys.readouterr().err


def test_cli_prepush_reads_stdin(proj, tmp_path, monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(line(ZERO, B)))
    assert main(["prepush", "--root", str(proj)], executor=Exec(tmp_path), docker=FakeDocker()) == 0



def test_trivy_p1_plus_gitleaks_error_still_blocks(proj, tmp_path, capsys):
    ex = Exec(tmp_path)
    ex.exit_codes = {"zricethezav/gitleaks": 2}
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 1
    cap = capsys.readouterr()
    assert "[P1]" in cap.out and "secrets" in cap.err


def test_gitleaks_error_alone_allows_with_stderr_warning(proj, tmp_path, capsys):
    ex = Exec(tmp_path, overrides={"trivy-fs.json": EMPTY_TRIVY})
    ex.exit_codes = {"zricethezav/gitleaks": 2}
    assert prepush(proj, line(), SCANNER_DIR, ex, FakeDocker()) == 0
    err = capsys.readouterr().err
    assert "chưa kiểm tra được" in err and "secrets" in err


def test_multi_ref_log_opts_single_not_remotes(proj, tmp_path):
    ex = Exec(tmp_path, overrides={"gitleaks.json": "[]", "trivy-fs.json": EMPTY_TRIVY})
    C = "c" * 40
    text = line(A, B) + line(C, ZERO) + line(B, ZERO)
    assert prepush(proj, text, SCANNER_DIR, ex, FakeDocker()) == 0
    gl = next(c for c in ex.calls if "detect" in c)
    assert f"--log-opts={B}..{A} {C} {B} --not --remotes" in gl


def test_malformed_line_warns(proj, tmp_path, capsys):
    ex = Exec(tmp_path, overrides={"gitleaks.json": "[]", "trivy-fs.json": EMPTY_TRIVY})
    assert prepush(proj, "garbage line\n" + line(), SCANNER_DIR, ex, FakeDocker()) == 0
    assert "không đúng định dạng" in capsys.readouterr().err

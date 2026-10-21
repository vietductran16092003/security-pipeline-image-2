import json
from pathlib import Path

import pytest

from scanner import store
from scanner.__main__ import main
from scanner.local import check_project
from test_cli import FakeDocker
from test_runner import FakeExecutor

SCANNER_DIR = Path(__file__).resolve().parent.parent


class StoreExecutor:
    """Giả lập công cụ: ghi fixture vào thư mục lần quét mới nhất trong kho."""

    def __init__(self, slug):
        self.slug, self.inner = slug, None

    def __call__(self, cmd, stdout_path=None, timeout=None):
        runs = sorted((store.store_root() / self.slug).iterdir())
        self.inner = FakeExecutor(runs[-1])
        return self.inner(cmd, stdout_path=stdout_path, timeout=timeout)


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path / "store"))
    for n in ("GITHUB_REPOSITORY", "GITHUB_REF_NAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_TOKEN"):
        monkeypatch.delenv(n, raising=False)


def _proj(tmp_path, name="avatar"):
    p = tmp_path / name
    p.mkdir()
    return p


def test_check_writes_report_files_in_store_and_opens_email_html(tmp_path):
    proj = _proj(tmp_path)
    slug = store.slug_for(proj)
    opened = []
    code = check_project(proj, SCANNER_DIR, StoreExecutor(slug), FakeDocker(), open_report=opened.append)
    assert code == 0
    run = sorted((store.store_root() / slug).iterdir())[-1]
    assert {"report.json", "email.html", "subject.txt", "summary.md"} <= {p.name for p in run.iterdir()}
    assert opened == [run / "email.html"]
    assert json.loads((run / "report.json").read_text(encoding="utf-8"))["project"] == "avatar"


def test_check_second_run_compares_with_previous(tmp_path):
    proj = _proj(tmp_path)
    slug = store.slug_for(proj)
    check_project(proj, SCANNER_DIR, StoreExecutor(slug), FakeDocker(), open_report=lambda p: None)
    check_project(proj, SCANNER_DIR, StoreExecutor(slug), FakeDocker(), open_report=lambda p: None)
    run = sorted((store.store_root() / slug).iterdir())[-1]
    assert "đã sửa" in (run / "summary.md").read_text(encoding="utf-8")


def test_check_does_not_touch_other_projects_history(tmp_path):
    a, b = _proj(tmp_path, "a"), _proj(tmp_path, "b")
    check_project(a, SCANNER_DIR, StoreExecutor(store.slug_for(a)), FakeDocker(), open_report=lambda p: None)
    check_project(b, SCANNER_DIR, StoreExecutor(store.slug_for(b)), FakeDocker(), open_report=lambda p: None)
    assert len(list((store.store_root() / store.slug_for(a)).iterdir())) == 1
    run_b = next((store.store_root() / store.slug_for(b)).iterdir())
    assert "Lần quét đầu tiên" in (run_b / "subject.txt").read_text(encoding="utf-8")


def test_check_docker_unavailable_returns_2_and_message_in_vietnamese(tmp_path, capsys):
    proj = _proj(tmp_path)
    code = check_project(proj, SCANNER_DIR, StoreExecutor("x"), FakeDocker(error="Docker chưa chạy"),
                         open_report=lambda p: pytest.fail("không được mở"))
    assert code == 2
    assert "Không quét được" in capsys.readouterr().out


def test_check_nonexistent_root_returns_2(tmp_path, capsys):
    code = check_project(tmp_path / "nope", SCANNER_DIR, StoreExecutor("x"), FakeDocker(), open_report=lambda p: None)
    assert code == 2
    assert "Không tìm thấy" in capsys.readouterr().out


def test_check_folder_not_git_repo_still_scans(tmp_path):
    proj = _proj(tmp_path, "Dự án mới")
    assert not (proj / ".git").exists()
    code = check_project(proj, SCANNER_DIR, StoreExecutor(store.slug_for(proj)), FakeDocker(),
                         open_report=lambda p: None)
    assert code == 0


def test_check_stops_docker_it_started(tmp_path):
    proj = _proj(tmp_path)
    docker = FakeDocker(started=True)
    check_project(proj, SCANNER_DIR, StoreExecutor(store.slug_for(proj)), docker, open_report=lambda p: None)
    assert docker.stopped


def test_cli_check_subcommand(tmp_path):
    proj = _proj(tmp_path)
    code = main(["check", "--root", str(proj), "--scanner-dir", str(SCANNER_DIR)],
                executor=StoreExecutor(store.slug_for(proj)), docker=FakeDocker())
    assert code == 0


def test_check_prints_manual_path_when_browser_cannot_open(tmp_path, capsys):
    proj = _proj(tmp_path)
    slug = store.slug_for(proj)
    check_project(proj, SCANNER_DIR, StoreExecutor(slug), FakeDocker(), open_report=lambda p: False)
    out = capsys.readouterr().out
    assert "Không mở được trình duyệt, hãy mở file:" in out
    assert "email.html" in out

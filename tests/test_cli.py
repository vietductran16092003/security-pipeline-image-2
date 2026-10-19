import json
from pathlib import Path

from scanner.__main__ import main
from test_runner import FakeExecutor

SCANNER_DIR = str(Path(__file__).resolve().parent.parent)
GH_ENV = ("GITHUB_REPOSITORY", "GITHUB_REF_NAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_SERVER_URL", "GITHUB_TOKEN")
SMTP_ENV = ("SMTP_USERNAME", "SMTP_PASSWORD", "REPORT_EMAIL_TO")


def _clear(monkeypatch, names):
    for n in names:
        monkeypatch.delenv(n, raising=False)


def test_cli_run_writes_four_files_locally(tmp_path, monkeypatch):
    _clear(monkeypatch, GH_ENV)
    proj = tmp_path / "demo-proj"
    proj.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    code = main(["run", "--root", str(proj), "--out", str(out), "--scanner-dir", SCANNER_DIR],
                executor=FakeExecutor(out))
    assert code == 0
    assert {"report.json", "email.html", "subject.txt", "summary.md"} <= {p.name for p in out.iterdir()}
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["project"] == "demo-proj" and rep["branch"] == "local"
    assert all(f["priority"] in ("P1", "P2", "Backlog") for s in rep["sections"] for f in s["findings"])
    assert "Lần quét đầu tiên" in (out / "subject.txt").read_text(encoding="utf-8")


def test_cli_run_uses_github_env(tmp_path, monkeypatch):
    _clear(monkeypatch, GH_ENV)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/my-api")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    proj = tmp_path / "p"
    proj.mkdir()
    out = tmp_path / "out"
    main(["run", "--root", str(proj), "--out", str(out), "--scanner-dir", SCANNER_DIR], executor=FakeExecutor(out))
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert rep["project"] == "my-api" and rep["run_url"] == "https://github.com/owner/my-api/actions/runs/42"
    assert rep["commit"] == "abcdef1234567"


def test_cli_send_without_secrets_exits_0(tmp_path, monkeypatch, capsys):
    _clear(monkeypatch, SMTP_ENV)
    assert main(["send", "--out", str(tmp_path)]) == 0
    assert "Bỏ qua gửi email" in capsys.readouterr().out


def test_cli_send_smtp_failure_exits_0(tmp_path, monkeypatch, capsys):
    for n in SMTP_ENV:
        monkeypatch.setenv(n, "x@x.com")
    (tmp_path / "email.html").write_text("<b>x</b>", encoding="utf-8")
    (tmp_path / "subject.txt").write_text("s", encoding="utf-8")

    def broken(*a, **k):
        raise OSError("connection refused")
    assert main(["send", "--out", str(tmp_path)], smtp_factory=broken) == 0
    assert "Gửi email thất bại" in capsys.readouterr().out


def test_cli_run_fails_only_when_report_not_written(tmp_path, monkeypatch):
    _clear(monkeypatch, GH_ENV)
    proj = tmp_path / "p"
    proj.mkdir()
    out_file = tmp_path / "is-a-file"
    out_file.write_text("x")
    assert main(["run", "--root", str(proj), "--out", str(out_file), "--scanner-dir", SCANNER_DIR],
                executor=FakeExecutor(tmp_path)) != 0

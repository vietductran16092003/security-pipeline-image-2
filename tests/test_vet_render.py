import json
import re
from pathlib import Path

import pytest

from scanner import store
from scanner.__main__ import main
from scanner.vet import command as C
from scanner.vet.render import MAX_SIGNALS, render_vet_html
from scanner.vet.sandbox import VetOutcome
from scanner.vet.signals import ScanResult, Signal
from scanner.vet.source import Source
from scanner.vet.verdict import Verdict
from test_cli import FakeDocker

ROOT = Path(__file__).resolve().parent.parent
XSS = "<script>alert(1)</script>"
SRC = Source(host="github.com", path="o/r", branch=None, clone_url="https://github.com/o/r.git",
             display="github.com/o/r")
LEVELS = ("Không nên mở", "Đáng ngờ", "An toàn hơn")


def _outcome(verdict=Verdict.NOT_SAFE, signals=(), incomplete=(), tool_errors=(), truncated=False,
             fetch_error=None, source=SRC):
    return VetOutcome(verdict, ScanResult(list(signals), list(incomplete)), fetch_error, truncated,
                      list(tool_errors), source)


def test_html_is_self_contained():
    h = render_vet_html(_outcome(Verdict.SAFER))
    assert "<script" not in h and "http://" not in h and "https://" not in h.replace("https://github", "")
    assert "<style>" in h and 'name="viewport"' in h


def test_html_escapes_repo_supplied_text():
    bad = Source(host="github.com", path="o/r", branch=None, clone_url="x", display=XSS)
    sig = Signal(XSS, "high", XSS + ".js", 3, XSS)
    h = render_vet_html(_outcome(signals=[sig], incomplete=[XSS], tool_errors=[XSS], source=bad))
    assert "<script" not in h
    assert "&lt;script&gt;" in h
    h2 = render_vet_html(VetOutcome(None, None, XSS, False, [XSS], bad))
    assert "<script" not in h2 and "&lt;script&gt;" in h2


def test_html_shows_level_reason_file_line_and_limit_note():
    sig = Signal("npm-postinstall", "high", "package.json", 12, "script cài đặt tải mã từ mạng")
    h = render_vet_html(_outcome(signals=[sig]))
    assert "Không nên mở" in h and "npm-postinstall" in h and "package.json:12" in h
    assert "script cài đặt tải mã từ mạng" in h and "không chứng minh repo sạch" in h
    assert "Đừng tải hoặc mở" in h


@pytest.mark.parametrize("verdict", list(Verdict))
def test_limits_note_always_present(verdict):
    assert "không chứng minh repo sạch" in render_vet_html(_outcome(verdict))


def test_info_signals_in_separate_note_section_and_incomplete_notes():
    sigs = [Signal("a", "info", "f", None, "ghi chú nhỏ"), Signal("b", "medium", "g", 1, "w")]
    h = render_vet_html(_outcome(Verdict.SUSPICIOUS, sigs, incomplete=["thiếu X"], tool_errors=["lỗi Y"],
                                 truncated=True))
    assert "Ghi chú (1)" in h and "Kiểm tra chưa đầy đủ vì" in h
    assert "thiếu X" in h and "lỗi Y" in h and "Chỉ mở nếu bạn hiểu rõ" in h


def test_safer_sentence_is_not_a_guarantee():
    h = render_vet_html(_outcome(Verdict.SAFER))
    assert "An toàn hơn" in h and "KHÔNG phải bảo đảm" in h


def test_no_level_html_says_could_not_check_and_never_safe_wording():
    h = render_vet_html(VetOutcome(None, None, "Tải repo thất bại (git thoát mã 128)", False, [], SRC))
    assert "Không kiểm tra được" in h and "git thoát mã 128" in h
    assert not any(l in h for l in LEVELS) and "an toàn" not in h.lower()
    assert "không chứng minh repo sạch" in h


def test_bidi_and_control_chars_removed():
    sig = Signal("id", "low", "a\u202eb\x07c.txt", 1, "w\u2066x\x1by")
    h = render_vet_html(_outcome(Verdict.SUSPICIOUS, [sig]))
    assert "abc.txt" in h and "wxy" in h
    assert not re.search("[\u202a-\u202e\u2066-\u2069\x07\x1b]", h)


def test_signal_cap_line():
    sigs = [Signal(f"s{i}", "low", "f", i, "w") for i in range(MAX_SIGNALS + 7)]
    h = render_vet_html(_outcome(Verdict.SUSPICIOUS, sigs))
    assert "còn 7 tín hiệu nữa" in h and h.count("<li>") == MAX_SIGNALS


# ---------------------------------------------------------------- CLI

@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path / "store"))


class NoDocker:
    def ensure(self):
        raise AssertionError("Docker không được đụng tới")

    def stop(self):
        raise AssertionError("Docker không được đụng tới")


@pytest.mark.parametrize("link", ["http://github.com/o/r", "file:///etc/passwd", "https://github.com@evil.example/x",
                                  "https://localhost/a/b", "", "a b"])
def test_cli_vet_invalid_link_returns_2_without_touching_docker(link, capsys):
    def boom(*a, **k):
        raise AssertionError("executor không được gọi")
    assert main(["vet", "--source", link], executor=boom, docker=NoDocker()) == 2
    assert capsys.readouterr().out.strip()


def test_cli_vet_prints_level_and_opens_report(monkeypatch, capsys, tmp_path):
    opened = []
    docker = FakeDocker(started=True)
    code = C.vet_command("o/r", None, docker, open_report=opened.append, parse=lambda t: SRC,
                         vet=lambda s, e, d: _outcome(Verdict.SUSPICIOUS, [Signal("x", "medium", "f", 1, "w")]))
    out = capsys.readouterr().out
    assert code == 0 and "Đáng ngờ" in out
    assert len(opened) == 1 and opened[0].endswith("vet.html") and Path(opened[0]).is_file()
    run = Path(opened[0]).parent
    assert json.loads((run / "vet.json").read_text(encoding="utf-8"))["verdict"] == "Đáng ngờ"
    assert run.parent.parent.name == "vet" and store.store_root() in run.parents
    assert docker.stopped


def test_cli_vet_no_verdict_is_clean_exit_0(capsys):
    opened = []
    out_ = VetOutcome(None, None, "Tải repo thất bại", False, [], SRC)
    code = C.vet_command("o/r", None, FakeDocker(), open_report=opened.append, parse=lambda t: SRC,
                         vet=lambda s, e, d: out_)
    printed = capsys.readouterr().out
    assert code == 0 and "Không kiểm tra được" in printed and "An toàn" not in printed
    assert "Không kiểm tra được" in Path(opened[0]).read_text(encoding="utf-8")


def test_cli_vet_docker_unavailable_returns_2(capsys):
    from scanner.docker_desktop import DockerUnavailable  # noqa: F401
    code = C.vet_command("o/r", None, FakeDocker(error="Không tìm thấy Docker Desktop"),
                         open_report=lambda p: True, parse=lambda t: SRC,
                         vet=lambda s, e, d: (_ for _ in ()).throw(AssertionError("vet")))
    assert code == 2 and "Docker" in capsys.readouterr().out


def test_cli_vet_stops_docker_even_if_vet_crashes():
    docker = FakeDocker(started=True)
    with pytest.raises(RuntimeError):
        C.vet_command("o/r", None, docker, open_report=lambda p: True, parse=lambda t: SRC,
                      vet=lambda s, e, d: (_ for _ in ()).throw(RuntimeError("x")))
    assert docker.stopped


def test_open_report_fallback_message(capsys):
    for opener in (lambda p: False, lambda p: (_ for _ in ()).throw(OSError("no browser"))):
        C.vet_command("o/r", None, FakeDocker(), open_report=opener, parse=lambda t: SRC,
                      vet=lambda s, e, d: _outcome(Verdict.SAFER))
        assert "Không mở được trình duyệt, hãy mở file:" in capsys.readouterr().out


def test_vet_keeps_last_20_runs():
    for _ in range(23):
        C.vet_command("o/r", None, FakeDocker(), open_report=lambda p: True, parse=lambda t: SRC,
                      vet=lambda s, e, d: _outcome(Verdict.SAFER))
    base = store.store_root() / "vet" / store.slug_for_text(SRC.display)
    assert len(list(base.iterdir())) == 20


def test_slug_for_text_is_safe_and_distinct():
    a, b = store.slug_for_text("github.com/o/Dự-án@main"), store.slug_for_text("github.com/o/Dự-án@dev")
    assert a != b and re.fullmatch(r"[a-z0-9-]+", a)
    assert re.fullmatch(r"[a-z0-9-]+", store.slug_for_text("..\\..\\<x>|:"))


def test_main_source_file_reads_utf8_and_never_via_shell(tmp_path, monkeypatch):
    f = tmp_path / "l.txt"
    f.write_bytes("\ufeffo/r\r\n".encode("utf-8"))
    seen = []
    monkeypatch.setattr("scanner.vet.command.vet_command",
                        lambda text, executor, docker, **k: seen.append(text) or 0)
    assert main(["vet", "--source-file", str(f)], docker=FakeDocker()) == 0
    assert seen == ["o/r"]
    assert main(["vet", "--source-file", str(tmp_path / "missing.txt")], docker=FakeDocker()) == 2
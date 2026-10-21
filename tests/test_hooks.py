import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.hooks import END, START, install_hook, uninstall_hook

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="cần git")
PY = str(Path("C:/fake dir/Dự án/.venv/Scripts/python.exe"))


def _repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def _hook(repo):
    return repo / ".git" / "hooks" / "pre-push"


def test_install_creates_executable_hook_in_git_hooks(tmp_path):
    repo = _repo(tmp_path)
    msg = install_hook(repo, PY)
    text = _hook(repo).read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert START in text and END in text
    assert "C:/fake dir/Dự án/.venv/Scripts/python.exe" in text
    assert "prepush" in text
    assert msg
    if os.name != "nt":
        assert os.access(_hook(repo), os.X_OK)


def test_install_twice_is_idempotent(tmp_path):
    repo = _repo(tmp_path)
    install_hook(repo, PY)
    first = _hook(repo).read_bytes()
    install_hook(repo, PY)
    assert _hook(repo).read_bytes() == first
    assert first.count(START.encode()) == 1


def test_install_preserves_existing_hook_and_runs_it_first(tmp_path):
    repo = _repo(tmp_path)
    old = b"#!/bin/sh\necho OLD\n"
    _hook(repo).write_bytes(old)
    install_hook(repo, PY)
    data = _hook(repo).read_bytes()
    assert data.startswith(old)
    assert data.index(b"echo OLD") < data.index(START.encode())


def test_existing_hook_without_trailing_newline_and_with_crlf(tmp_path):
    repo = _repo(tmp_path)
    old = b"#!/bin/sh\r\necho OLD"
    _hook(repo).write_bytes(old)
    install_hook(repo, PY)
    data = _hook(repo).read_bytes()
    assert data.startswith(old + b"\r\n" + START.encode())
    assert b"\n" not in data.replace(b"\r\n", b"")
    uninstall_hook(repo)
    assert _hook(repo).read_bytes() == old


def test_uninstall_restores_original_bytes_of_existing_hook(tmp_path):
    repo = _repo(tmp_path)
    for old in (b"#!/bin/sh\necho OLD\n", b"#!/bin/sh\necho OLD"):
        _hook(repo).write_bytes(old)
        install_hook(repo, PY)
        uninstall_hook(repo)
        assert _hook(repo).read_bytes() == old


def test_uninstall_removes_file_when_ours_only(tmp_path):
    repo = _repo(tmp_path)
    install_hook(repo, PY)
    uninstall_hook(repo)
    assert not _hook(repo).exists()


def test_not_a_git_repo_returns_message_not_exception(tmp_path):
    for fn in (lambda: install_hook(tmp_path, PY), lambda: uninstall_hook(tmp_path)):
        msg = fn()
        assert "git" in msg.lower()


def test_core_hookspath_returns_not_supported_message(tmp_path):
    repo = _repo(tmp_path)
    subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", ".husky"], check=True)
    assert "core.hooksPath" in install_hook(repo, PY)
    assert not _hook(repo).exists()
    assert "core.hooksPath" in uninstall_hook(repo)


def test_hook_is_valid_sh_and_allows_when_scanner_missing(tmp_path):
    sh = shutil.which("sh")
    if sh is None:
        for cand in (Path(shutil.which("git")).parent.parent / "bin" / "sh.exe",):
            if cand.exists():
                sh = str(cand)
    if sh is None:
        pytest.skip("cần sh")
    repo = _repo(tmp_path)
    install_hook(repo, str(tmp_path / "không có" / "python"))
    r = subprocess.run([sh, str(_hook(repo))], input="", capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=repo)
    assert r.returncode == 0
    _hook(repo).write_bytes(b"#!/bin/sh\nexit 3\n")
    install_hook(repo, str(tmp_path / "x"))
    r = subprocess.run([sh, str(_hook(repo))], input="", capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=repo)
    assert r.returncode == 3

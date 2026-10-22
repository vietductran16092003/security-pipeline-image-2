import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.hooks import ORIG, START, install_hook, uninstall_hook

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
    assert START in text and "# <<< security-scan <<<" in text
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


def test_install_preserves_existing_hook_as_orig(tmp_path):
    repo = _repo(tmp_path)
    old = b"#!/bin/sh\r\necho OLD"
    _hook(repo).write_bytes(old)
    install_hook(repo, PY)
    install_hook(repo, PY)
    assert (_hook(repo).parent / ORIG).read_bytes() == old
    assert START.encode() in _hook(repo).read_bytes()


def test_reinstall_over_foreign_hook_never_loses_the_previous_orig(tmp_path):
    # Hook A đã được cài (A -> ORIG). Một công cụ khác ghi đè pre-push bằng hook B.
    # Cài lại phải giữ B làm hook gốc mới và KHÔNG làm mất A.
    repo = _repo(tmp_path)
    hook_a, hook_b = b"#!/bin/sh\necho A\n", b"#!/bin/sh\necho B\n"
    _hook(repo).write_bytes(hook_a)
    install_hook(repo, PY)
    _hook(repo).write_bytes(hook_b)
    install_hook(repo, PY)
    hooks_dir = _hook(repo).parent
    assert (hooks_dir / ORIG).read_bytes() == hook_b
    saved = [p.read_bytes() for p in hooks_dir.iterdir() if p.name.startswith(ORIG + ".")]
    assert hook_a in saved
    assert START.encode() in _hook(repo).read_bytes()


def test_uninstall_restores_original_bytes_of_existing_hook(tmp_path):
    repo = _repo(tmp_path)
    for old in (b"#!/bin/sh\necho OLD\n", b"#!/bin/sh\r\necho OLD", b"#!/usr/bin/env python3\nprint(1)\r\n"):
        _hook(repo).write_bytes(old)
        install_hook(repo, PY)
        install_hook(repo, PY)
        uninstall_hook(repo)
        assert _hook(repo).read_bytes() == old
        assert not (_hook(repo).parent / ORIG).exists()


def test_uninstall_with_missing_orig_removes_ours(tmp_path):
    repo = _repo(tmp_path)
    _hook(repo).write_bytes(b"#!/bin/sh\nexit 0\n")
    install_hook(repo, PY)
    (_hook(repo).parent / ORIG).unlink()
    uninstall_hook(repo)
    assert not _hook(repo).exists()

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


def _find_sh():
    sh = shutil.which("sh")
    if sh is None:
        cand = Path(shutil.which("git")).parent.parent / "bin" / "sh.exe"
        if cand.exists():
            sh = str(cand)
    if sh is None:
        pytest.skip("cần sh")
    return sh


def _fake_scanner(tmp_path):
    rec = tmp_path / "rec.txt"
    fake = tmp_path / "py"
    fake.write_bytes(b'#!/bin/sh\necho RAN >> "' + str(rec).replace("\\", "/").encode() + b'"\ncat >> "'
                     + str(rec).replace("\\", "/").encode() + b'"\nexit ${FAKE_RC:-0}\n')
    fake.chmod(0o755)
    return fake, rec


@pytest.mark.parametrize("old,rc,ran", [
    (b"#!/bin/sh\nexit 0\n", 0, True),
    (b"#!/bin/sh\ncat >/dev/null\n", 0, True),
    (b"#!/bin/sh\nexit 3\n", 3, False),
    (b"#!/bin/sh\ntrap 'echo x' EXIT\n", 0, True),
    (b"#!/bin/sh\nexec true\n", 0, True),
    (b"#!/bin/sh\nset -e\nfalse\necho no\n", 1, False),
    (b"#!/bin/sh\r\necho hi\r\n", 0, True),
])
def test_combined_script_runs_scanner_after_old_hook(tmp_path, old, rc, ran):
    sh = _find_sh()
    repo = _repo(tmp_path / "r") if (tmp_path / "r").mkdir() is None else None
    fake, rec = _fake_scanner(tmp_path)
    _hook(repo).write_bytes(old)
    install_hook(repo, str(fake))
    kw = dict(capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=repo)
    r = subprocess.run([sh, str(_hook(repo))], input="refs/heads/a 1 refs/heads/a 0\n", **kw)
    assert r.returncode == rc
    if ran:
        assert "refs/heads/a 1 refs/heads/a 0" in rec.read_text()
    else:
        assert not rec.exists()
    r = subprocess.run([sh, str(_hook(repo))], input="x\n", env={**os.environ, "FAKE_RC": "1"}, **kw)
    if ran:
        assert r.returncode == 1


def test_worktree_gets_hook_where_git_reads_it(tmp_path):
    main = tmp_path / "main"
    main.mkdir()
    _repo(main)
    env = ["-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "-C", str(main), *env, "commit", "-q", "--allow-empty", "-m", "x"], check=True)
    wt = tmp_path / "wt"
    subprocess.run(["git", "-C", str(main), "worktree", "add", "-q", str(wt), "-b", "w"], check=True)
    install_hook(wt, PY)
    assert _hook(main).exists()
    uninstall_hook(wt)
    assert not _hook(main).exists()

def test_non_sh_shebang_old_hook_runs_untouched(tmp_path):
    sh = _find_sh()
    repo = _repo(tmp_path / "r") if (tmp_path / "r").mkdir() is None else None
    fake, rec = _fake_scanner(tmp_path)
    mark = tmp_path / "interp.txt"
    interp = tmp_path / "fakeinterp"
    interp.write_bytes(b'#!/bin/sh\necho "interp $1" > "' + str(mark).replace("\\", "/").encode() + b'"\nexit 0\n')
    interp.chmod(0o755)
    _hook(repo).write_bytes(b"#!" + str(interp).replace("\\", "/").encode() + b"\nprint('x')\n")
    install_hook(repo, str(fake))
    r = subprocess.run([sh, str(_hook(repo))], input="a\n", capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=repo)
    assert r.returncode == 0
    assert mark.exists() and rec.exists()
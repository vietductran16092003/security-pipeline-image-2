import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CMDS = [ROOT / "Quet-du-an.cmd", ROOT / "scripts" / "bootstrap.cmd"]


def test_cmd_files_exist_and_reference_scanner_check():
    for p in CMDS + [ROOT / "scripts" / "pick-folder.ps1"]:
        assert p.is_file(), p
    main = (ROOT / "Quet-du-an.cmd").read_text(encoding="utf-8")
    assert "scanner check --root" in main
    assert "bootstrap.cmd" in main and "pick-folder.ps1" in main
    assert "pause" in main.rstrip().lower().splitlines()[-2]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="cần Windows PowerShell")
def test_pick_folder_script_parses():
    script = ROOT / "scripts" / "pick-folder.ps1"
    cmd = f"[scriptblock]::Create((Get-Content -Raw -LiteralPath '{script}')) | Out-Null"
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True)
    assert r.returncode == 0, r.stderr


def test_cmd_files_use_crlf_and_utf8_codepage():
    for p in CMDS:
        raw = p.read_bytes()
        assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b""), p
        text = raw.decode("utf-8")
        assert "chcp 65001" in text, p
    main = (ROOT / "Quet-du-an.cmd").read_text(encoding="utf-8")
    assert "%~dp0" in main and '"%ROOT%' in main
    assert '"%PICKED%"' in main and '%PICKED:~-1%' in main
    assert "__PICKFAIL__" in main and "Không mở được hộp thoại" in main
    assert b"\xef\xbb\xbf" == (ROOT / "scripts" / "pick-folder.ps1").read_bytes()[:3]


def _all_cmd_files():
    skip = {".git", ".venv", ".superpowers", "scan-out", "node_modules"}
    return [p for p in ROOT.rglob("*.cmd") if not skip & set(p.relative_to(ROOT).parts)]


def test_every_cmd_file_has_only_crlf_line_endings():
    # cmd.exe đọc file .bat/.cmd dùng LF trần sai (cắt dòng, nhảy nhãn lung tung): mọi .cmd phải là CRLF.
    files = _all_cmd_files()
    assert len(files) >= 4, files
    for p in files:
        raw = p.read_bytes()
        assert b"\r\n" in raw, p
        assert b"\n" not in raw.replace(b"\r\n", b""), f"{p.name} có dòng kết thúc bằng LF trần"
        assert b"\xef\xbb\xbf" != raw[:3], f"{p.name} có BOM"
        assert b"chcp 65001" in raw, p


ASK = ROOT / "scripts" / "ask-repo.ps1"
VET_CMD = ROOT / "Kiem-tra-repo-la.cmd"


def test_vet_cmd_conventions_and_never_expands_link():
    raw = VET_CMD.read_bytes()
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")
    text = raw.decode("utf-8")
    assert "chcp 65001" in text and "%~dp0" in text and "pushd" in text and "popd" in text
    assert "bootstrap.cmd" in text and "ask-repo.ps1" in text
    assert '--source-file "%LINKFILE%"' in text and "-OutFile" in text
    lines = [l for l in text.splitlines() if l.strip() and not l.lower().startswith("rem")]
    assert lines[-1] == "popd" and lines[-2].strip().lower() == "pause" and ":end" in lines
    # link chỉ đi qua file tạm: không có "--source " hay for /f đọc link, không set biến từ link
    assert "--source " not in text and "for /f" not in text.lower()
    assert "enabledelayedexpansion" not in text.lower()
    assert b"\xef\xbb\xbf" == ASK.read_bytes()[:3]


@pytest.mark.skipif(shutil.which("powershell") is None, reason="cần Windows PowerShell")
def test_ask_repo_script_parses():
    cmd = f"[scriptblock]::Create((Get-Content -Raw -LiteralPath '{ASK}')) | Out-Null"
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True)
    assert r.returncode == 0, r.stderr


def test_vet_cmd_link_only_travels_through_temp_file():
    text = VET_CMD.read_text(encoding="utf-8")
    assert "set /p" not in text.lower()
    allowed = ('set "LINKFILE=', 'exist "%LINKFILE%"', 'del "%LINKFILE%"',
               '-OutFile "%LINKFILE%"', '--source-file "%LINKFILE%"')
    for line in (l for l in text.splitlines() if not l.lower().startswith('rem')):
        if "%LINKFILE%" in line:
            assert any(a in line for a in allowed), line
        if "python.exe" in line.lower() or "powershell" in line.lower():
            names = set(re.findall(r"%([A-Za-z_][A-Za-z0-9_]*)(?::[^%]*)?%", line))
            assert names <= {"ROOT", "LINKFILE", "TEMP"}, line

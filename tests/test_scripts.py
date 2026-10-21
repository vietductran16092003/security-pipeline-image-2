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

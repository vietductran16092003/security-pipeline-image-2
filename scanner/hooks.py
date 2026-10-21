"""Cài/gỡ hook pre-push của bộ quét mà không ghi đè hook sẵn có."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

START = "# >>> security-scan >>>"
END = "# <<< security-scan <<<"
ORIG = "pre-push.security-scan-orig"
SCANNER_DIR = Path(__file__).resolve().parent.parent


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _hooks_file(repo: Path) -> tuple[Path | None, str]:
    """Trả (đường dẫn pre-push, '') hoặc (None, thông báo lỗi tiếng Việt)."""
    top = _git(repo, "rev-parse", "--git-path", "hooks/pre-push")
    if top is None:
        return None, "Không chạy được git. Hãy cài Git rồi thử lại."
    if top.returncode != 0:
        return None, f"Thư mục này không phải dự án git: {repo}"
    hp = _git(repo, "config", "core.hooksPath")
    if hp is not None and hp.stdout.strip():
        return None, ("Dự án này dùng core.hooksPath (ví dụ husky) nên chưa hỗ trợ cài hook tự động. "
                      "Bạn có thể thêm lệnh quét vào hook của công cụ đó.")
    hook = Path(top.stdout.strip())
    if not hook.is_absolute():
        hook = Path(repo) / hook
    return hook, ""


def _sh_quote(value: str) -> str:
    value = value.replace("\\", "/")
    for ch in ('\\', '"', "$", "`"):
        value = value.replace(ch, "\\" + ch)
    return f'"{value}"'


def _block(scanner_cmd: str) -> str:
    # Hook cũ (nếu có) được dời sang file ORIG và chạy như tiến trình con, nên shebang riêng,
    # `exit`, `exec`, trap... của nó không ảnh hưởng tới việc quét.
    py = _sh_quote(scanner_cmd)
    lines = [
        START,
        '_ss_dir="$(dirname "$0")"',
        '_ss_in="$(mktemp)"',
        "trap 'rm -f \"$_ss_in\"' EXIT INT TERM",
        'cat >"$_ss_in"',
        '_ss_st=0',
        f'if [ -x "$_ss_dir/{ORIG}" ]; then',
        f'  "$_ss_dir/{ORIG}" "$@" <"$_ss_in" || _ss_st=$?',
        'fi',
        'if [ "$_ss_st" -eq 0 ]; then',
        '  _ss_root="$(git rev-parse --show-toplevel)"',
        f'  if [ -x {py} ]; then',
        f'    PYTHONPATH={_sh_quote(str(SCANNER_DIR))} {py} -m scanner prepush --root "$_ss_root" <"$_ss_in" || _ss_st=$?',
        '  else',
        '    echo "security-scan: KHÔNG tìm thấy bộ quét, bỏ qua kiểm tra (hãy cài lại hook)." >&2',
        '  fi',
        'fi',
        'rm -f "$_ss_in"',
        'exit "$_ss_st"',
        END,
    ]
    return "#!/bin/sh\n" + "\n".join(lines) + "\n"


def _ours(path: Path) -> bool:
    try:
        return START.encode() in path.read_bytes()
    except OSError:
        return False


def install_hook(repo: Path, scanner_cmd: str) -> str:
    path, err = _hooks_file(Path(repo))
    if path is None:
        return err
    path.parent.mkdir(parents=True, exist_ok=True)
    orig = path.with_name(ORIG)
    if path.exists() and not _ours(path):
        os.replace(path, orig)
    path.write_bytes(_block(scanner_cmd).encode("utf-8"))
    try:
        path.chmod(0o755)
    except OSError:
        pass
    return f"Đã cài hook kiểm tra trước khi push cho: {Path(repo)}"


def uninstall_hook(repo: Path) -> str:
    path, err = _hooks_file(Path(repo))
    if path is None:
        return err
    if not path.exists() or not _ours(path):
        return "Dự án này chưa cài hook của bộ quét, không có gì để gỡ."
    orig = path.with_name(ORIG)
    if orig.exists():
        os.replace(orig, path)
    else:
        path.unlink()
    return f"Đã gỡ hook kiểm tra trước khi push khỏi: {Path(repo)}"
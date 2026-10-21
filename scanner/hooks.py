"""Cài/gỡ hook pre-push của bộ quét mà không ghi đè hook sẵn có."""

from __future__ import annotations

import subprocess
from pathlib import Path

START = "# >>> security-scan >>>"
END = "# <<< security-scan <<<"
NL_FLAG = "# security-scan: nl-added"
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
    top = _git(repo, "rev-parse", "--git-dir")
    if top is None:
        return None, "Không chạy được git. Hãy cài Git rồi thử lại."
    if top.returncode != 0:
        return None, f"Thư mục này không phải dự án git: {repo}"
    hp = _git(repo, "config", "core.hooksPath")
    if hp is not None and hp.stdout.strip():
        return None, ("Dự án này dùng core.hooksPath (ví dụ husky) nên chưa hỗ trợ cài hook tự động. "
                      "Bạn có thể thêm lệnh quét vào hook của công cụ đó.")
    git_dir = Path(top.stdout.strip())
    if not git_dir.is_absolute():
        git_dir = Path(repo) / git_dir
    return git_dir / "hooks" / "pre-push", ""


def _sh_quote(value: str) -> str:
    value = value.replace("\\", "/")
    for ch in ('\\', '"', "$", "`"):
        value = value.replace(ch, "\\" + ch)
    return f'"{value}"'


def _block(scanner_cmd: str, nl: str) -> str:
    py = _sh_quote(scanner_cmd)
    lines = [
        START,
        '_ss_prev=$?',
        'if [ "$_ss_prev" -ne 0 ]; then exit "$_ss_prev"; fi',
        f'if [ ! -x {py} ]; then',
        '  echo "security-scan: không tìm thấy bộ quét, bỏ qua kiểm tra." >&2',
        '  exit 0',
        'fi',
        '_ss_root="$(git rev-parse --show-toplevel)"',
        f'PYTHONPATH={_sh_quote(str(SCANNER_DIR))} {py} -m scanner prepush --root "$_ss_root"',
        'exit $?',
        END,
    ]
    return nl.join(lines) + nl


def _strip(data: bytes) -> tuple[bytes, bool]:
    """Cắt khối của ta, trả (nội dung còn lại, có khối hay không)."""
    s = data.decode("utf-8", errors="surrogateescape")
    i = s.find(START)
    if i < 0:
        return data, False
    j = s.find(END, i)
    if j < 0:
        return data, False
    j += len(END)
    if s.startswith("\r\n", j):
        j += 2
    elif s.startswith("\n", j):
        j += 1
    head = s[:i]
    if NL_FLAG in s[i:j]:
        # ta đã thêm một dấu xuống dòng cuối hook cũ: bỏ nó đi
        if head.endswith("\r\n"):
            head = head[:-2]
        elif head.endswith("\n"):
            head = head[:-1]
    return (head + s[j:]).encode("utf-8", errors="surrogateescape"), True


def install_hook(repo: Path, scanner_cmd: str) -> str:
    path, err = _hooks_file(Path(repo))
    if path is None:
        return err
    nl = "\n"
    added_nl = False
    if path.exists():
        old, found = _strip(path.read_bytes())
        if "\r\n" in old.decode("utf-8", errors="surrogateescape"):
            nl = "\r\n"
        body = old
        if found:
            pass
        if body and not body.endswith(b"\n"):
            added_nl = True
            body += nl.encode()
    else:
        body = f"#!/bin/sh{nl}".encode()
    block = _block(scanner_cmd, nl)
    if added_nl:
        block = block.replace(START + nl, START + nl + NL_FLAG + nl, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body + block.encode("utf-8"))
    try:
        path.chmod(0o755)
    except OSError:
        pass
    return f"Đã cài hook kiểm tra trước khi push cho: {Path(repo)}"


def uninstall_hook(repo: Path) -> str:
    path, err = _hooks_file(Path(repo))
    if path is None:
        return err
    if not path.exists():
        return "Dự án này chưa cài hook của bộ quét, không có gì để gỡ."
    rest, found = _strip(path.read_bytes())
    if not found:
        return "Hook hiện có không phải của bộ quét, giữ nguyên không đụng tới."
    text = rest.decode("utf-8", errors="surrogateescape")
    if text.strip() == "" or (text.startswith("#!") and text.strip().count("\n") == 0):
        path.unlink()
    else:
        path.write_bytes(rest)
    return f"Đã gỡ hook kiểm tra trước khi push khỏi: {Path(repo)}"

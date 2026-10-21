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
    # Khối nằm ngay sau dòng shebang, mọi dòng chỉ dùng LF. stdin được lưu một lần để hook cũ
    # đọc cùng danh sách ref; bẫy EXIT chạy bộ quét sau khi hook cũ kết thúc (kể cả `exit 0`).
    # Hook cũ dùng `exec` để thay tiến trình thì vẫn thoát được khối này.
    py = _sh_quote(scanner_cmd)
    lines = [
        START,
        '_ss_in="$(mktemp)"; cat >"$_ss_in"; exec <"$_ss_in"',
        "trap '_ss_st=$?; trap - EXIT; "
        'if [ "$_ss_st" -eq 0 ]; then _ss_root="$(git rev-parse --show-toplevel)"; '
        f'if [ -x {py} ]; then PYTHONPATH={_sh_quote(str(SCANNER_DIR))} {py} -m scanner prepush --root "$_ss_root" <"$_ss_in"; _ss_st=$?; '
        'else echo "security-scan: KHÔNG tìm thấy bộ quét, bỏ qua kiểm tra (hãy cài lại hook)." >&2; fi; fi; '
        'rm -f "$_ss_in"; exit "$_ss_st"\' EXIT',
        END,
    ]
    return "\n".join(lines) + "\n"

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
    if path.exists():
        old, _ = _strip(path.read_bytes())
    else:
        old = b"#!/bin/sh\n"
    block = _block(scanner_cmd)
    if old.startswith(b"#!"):
        nl = old.find(b"\n")
        if nl < 0:
            old += b"\n"
            block = block.replace(START + "\n", START + "\n" + NL_FLAG + "\n", 1)
            nl = len(old) - 1
        head, rest = old[: nl + 1], old[nl + 1:]
    else:
        head, rest = b"", old
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(head + block.encode("utf-8") + rest)
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

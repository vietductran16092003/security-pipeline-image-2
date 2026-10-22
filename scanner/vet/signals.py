"""Bộ phát hiện dấu hiệu đáng ngờ trong repo lạ (tĩnh, chỉ stdlib).

Chạy TRONG container `--network none`, repo mount chỉ đọc. Nguyên tắc: không chạy/import
code của repo, không theo symlink, đọc bytes (errors="ignore"), giới hạn kích thước file
và tổng thời gian, và KHÔNG BAO GIỜ đưa nội dung khớp vào kết quả (chỉ tên mẫu + file + dòng).

Mức tín hiệu: high | medium | low | info. `info` chỉ để liệt kê trong báo cáo, KHÔNG đổi kết luận
(decide() bỏ qua).
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import patterns as P

MAX_SIGNALS = 1000
MAX_LINE = 10_000
OVERLAP = 512
MAX_NOTES = 20


@dataclass
class Signal:
    id: str
    level: str  # "high" | "medium" | "low" | "info" (info: chỉ liệt kê, không ảnh hưởng mức kết luận)
    file: str
    line: int | None
    why: str


@dataclass
class ScanResult:
    signals: list[Signal] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)


@dataclass
class Dep:
    eco: str  # "npm" | "pypi"
    name: str
    spec: str
    file: str
    line: int | None
    manifest: bool = True


def _safe(s: str, limit: int = 120) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:limit]


def _u8(s):
    """Chuỗi do repo kiểm soát (tên file, tên gói...) -> UTF-8 hợp lệ (surrogate lẻ -> U+FFFD)."""
    return s.encode("utf-8", "replace").decode("utf-8") if isinstance(s, str) else s


def _find_line(lines: list[str], needle: str, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return None


class _Scan:
    def __init__(self, osv: dict | None) -> None:
        self.res = ScanResult()
        self.osv = osv
        self.seen: set[tuple] = set()
        self.deps: list[Dep] = []
        self.sym_notes = 0
        self.file_lines: dict[str, list[str]] = {}

    def add(self, sid, level, file, line, why, key=None) -> None:
        sid, file, why = _u8(sid), _u8(file), _u8(why)
        k = (sid, file, key)
        if k in self.seen:
            return
        self.seen.add(k)
        if len(self.res.signals) >= MAX_SIGNALS:
            msg = f"quá nhiều dấu hiệu (> {MAX_SIGNALS}), đã cắt bớt"
            if msg not in self.res.incomplete:
                self.res.incomplete.append(msg)
            return
        self.res.signals.append(Signal(sid, level, file, line, why))

    def note(self, msg: str) -> None:
        msg = _u8(msg)
        if len(self.res.incomplete) < 200:
            self.res.incomplete.append(msg)


# ---------------------------------------------------------------- text patterns

K_PIPE = ("curl", "wget", "iwr", "irm", "invoke-", "iex")
K_DECODE = ("b64decode", "atob", "buffer.from", "fromhex", "unhexlify", "frombase64string", "\\x",
            "codecs.decode", "fromcharcode")
K_CRED = ("~", "$home", "${home}", "%", "expanduser", "homedir", "path.home", "userprofile", "user_home",
          "id_rsa", "id_ed25519", "id_ecdsa", ".ssh", ".aws", "login data", "wallet", "local storage",
          "google-chrome", "user data", "metamask", "nkbihf", "os.environ", "process.env")
K_EXFIL = ("request", "urlopen", "http.client", "fetch", "axios", "curl", "wget", "invoke-", "iwr",
           "webclient", "socket", "net.connect", "net::http")


def _has(low: str, kws) -> bool:
    return any(k in low for k in kws)


def _logical_lines(text: str):
    """(số dòng bắt đầu, nội dung); nối các dòng kết thúc bằng dấu gạch chéo ngược (curl ... NL | sh)."""
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if raw.endswith("\\") and len(buf) < 4 * MAX_LINE:
            buf += raw[:-1] + " "
            continue
        yield start, buf + raw
        buf = ""
    if buf:
        yield start, buf


def _windows(line: str):
    """Dòng dài được quét theo cửa sổ MAX_LINE gối nhau OVERLAP ký tự (regex tuyến tính)."""
    if len(line) <= MAX_LINE:
        yield line
        return
    step = MAX_LINE - OVERLAP
    for s in range(0, len(line), step):
        yield line[s:s + MAX_LINE]
        if s + MAX_LINE >= len(line):
            break


def _scan_text(sc: _Scan, rel: str, name: str, ext: str, text: str) -> None:
    code = ext in P.CODE_EXTS and not (ext == "" and name.startswith("."))  # dotfile: cấu hình, không phải mã
    soft = name.lower() in P.SOFT_NAMES or ext in P.SOFT_EXTS or not code
    pipe_level = "medium" if soft else "high"
    cred = exfil = None
    last_decode = -99
    for i, full in _logical_lines(text):
        for line in _windows(full):
            low = line.lower()  # tiền lọc bằng chuỗi con (nhanh) trước khi chạy regex
            if _has(low, K_PIPE) and any(r.search(line) for r in P.PIPE_RES):
                sc.add("pipe-to-shell", pipe_level, rel, i, "Tải nội dung từ mạng rồi chuyển thẳng cho shell/trình thông dịch chạy")
            if _has(low, ("powershell", "pwsh")) and P.PS_ENC_RE.search(line):
                sc.add("obfuscated-exec", "high", rel, i, "PowerShell chạy lệnh mã hoá (-enc)")
            if _has(low, K_DECODE) and P.DECODE_RE.search(line):
                last_decode = i
            if i - last_decode <= 8 and _has(low, ("eval", "exec", "function", "iex", "invoke-expression")) \
                    and (P.EXEC_RE.search(line) or P.IEX_RE.search(line)):
                sc.add("obfuscated-exec", "high", rel, i, "Giải mã base64/hex rồi thực thi (eval/exec/Function/iex)")
            if _has(low, ("discord", "telegram", "webhook.site")) and P.WEBHOOK_RE.search(line):
                sc.add("exfil-webhook", "medium", rel, i, "Tham chiếu webhook Discord/Telegram (kênh gửi dữ liệu ra ngoài)")
            if code and cred is None and _has(low, K_CRED) and any(r.search(line) for r in P.CRED_RES):
                cred = i
            if exfil is None and _has(low, K_EXFIL) and P.EXFIL_RE.search(line):
                exfil = i
    if cred is not None:
        if exfil is not None:
            sc.add("credential-access", "high", rel, cred,
                   "Đọc khoá/thông tin đăng nhập (SSH, AWS, trình duyệt, ví...) và có gửi dữ liệu qua mạng trong cùng file")
            sc.add("exfil-network", "high", rel, exfil, "Gửi dữ liệu qua mạng trong file có đọc thông tin nhạy cảm")
        else:
            sc.add("credential-access", "medium", rel, cred,
                   "Đọc khoá/thông tin đăng nhập (SSH, AWS, trình duyệt, ví...)")


# ------------------------------------------------------------- structured files

def _scan_package_json(sc: _Scan, rel: str, text: str) -> None:
    lines = text.splitlines()
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict):
        for i, ln in enumerate(lines, 1):
            m = re.search(r'"(preinstall|install|postinstall|prepare)"\s*:\s*"([^"]{0,2000})"', ln[:MAX_LINE])
            if m and P.NET_RE.search(m.group(2)):
                sc.add("autorun-install-script", "high", rel, i,
                       f"Script npm '{m.group(1)}' tự chạy khi cài và có tải/chạy mã từ mạng", key=m.group(1))
        return
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for k in P.INSTALL_SCRIPT_KEYS:
            v = scripts.get(k)
            if isinstance(v, str) and P.NET_RE.search(v):
                sc.add("autorun-install-script", "high", rel, _find_line(lines, f'"{k}"'),
                       f"Script npm '{k}' tự chạy khi cài và có tải/chạy mã từ mạng", key=k)
    for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        d = data.get(sect)
        if not isinstance(d, dict):
            continue
        start = (_find_line(lines, f'"{sect}"') or 1) - 1
        for n, spec in d.items():
            if isinstance(n, str) and isinstance(spec, str):
                sc.deps.append(Dep("npm", n, spec, rel, _find_line(lines, f'"{n}"', start)))


def _scan_package_lock(sc: _Scan, rel: str, text: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    pk = data.get("packages")
    if isinstance(pk, dict):
        for key, meta in pk.items():
            if isinstance(meta, dict) and "node_modules/" in key and isinstance(meta.get("version"), str):
                sc.deps.append(Dep("npm", key.rsplit("node_modules/", 1)[1], meta["version"], rel, None, False))
    dp = data.get("dependencies")
    if isinstance(dp, dict):
        for n, meta in dp.items():
            if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                sc.deps.append(Dep("npm", n, meta["version"], rel, None, False))


_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|<|>|@|;|$)")


def _req_line(sc: _Scan, rel: str, i: int, s: str) -> None:
    s = s.split(" #")[0].strip()
    if not s or s.startswith(("-r", "-c", "--")):
        return
    if s.startswith("-e"):
        s = s[2:].strip()
    if re.match(r"^(git\+|https?://|git://|ssh://)", s):
        _direct(sc, rel, i, s, s)
        return
    m = _REQ_RE.match(s)
    if not m:
        return
    name, op = m.group(1), m.group(3)
    if op == "@":
        _direct(sc, rel, i, s.split("@", 1)[1].strip(), name)
    spec = s[m.end(1):].strip()
    sc.deps.append(Dep("pypi", name, spec.lstrip("=").strip() if op == "==" else spec, rel, i))


def _scan_requirements(sc: _Scan, rel: str, text: str) -> None:
    for i, ln in enumerate(text.splitlines(), 1):
        _req_line(sc, rel, i, ln[:MAX_LINE])


def _scan_pyproject(sc: _Scan, rel: str, text: str) -> None:
    in_arr = False
    section = ""
    for i, ln in enumerate(text.splitlines(), 1):
        ln = ln[:MAX_LINE]
        s = ln.strip()
        if s.startswith("["):
            section = s.strip("[] ")
            in_arr = False
        if re.match(r"^(dependencies|requires)\s*=\s*\[", s):
            in_arr = True
        if in_arr:
            for q in re.findall(r"[\"']([^\"']+)[\"']", s.split("=", 1)[1] if "=" in s and s[0].isalpha() else s):
                _req_line(sc, rel, i, q)
            if "]" in s:
                in_arr = False
        elif section.endswith("poetry.dependencies") or section.endswith("poetry.dev-dependencies"):
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(.*)$", s)
            if m and m.group(1).lower() != "python":
                sc.deps.append(Dep("pypi", m.group(1), m.group(2)[:100], rel, i))
                if re.search(r"\b(git|url)\s*=", m.group(2)):
                    sc.add("direct-url-dependency", "low", rel, i, "Phụ thuộc cài trực tiếp từ git/URL", key=i)


def _direct(sc: _Scan, rel: str, line: int | None, url: str, key) -> None:
    gitish = bool(re.match(r"^(git\+|git://|ssh://|github:|gitlab:|bitbucket:)", url)) or "git+" in url
    sc.add("direct-url-dependency", "low" if gitish else "medium", rel, line,
           "Phụ thuộc cài trực tiếp từ " + ("git" if gitish else "URL tải về") + " thay vì kho gói công khai",
           key=(line, str(key)[:60]))


_NPM_DIRECT_RE = re.compile(r"^(https?://|git\+|git://|ssh://|github:|gitlab:|bitbucket:|[\w.-]+/[\w.-]+(#.*)?$)")


def _check_deps(sc: _Scan) -> None:
    for d in sc.deps:
        if not d.manifest:
            continue
        t = P.typosquat_target(d.eco, d.name)
        if t:
            sc.add("typosquat-dependency", "medium", d.file, d.line,
                   f"Tên gói gần giống gói nổi tiếng '{t}' (nghi giả mạo tên)", key=d.name)
        if d.eco == "npm" and _NPM_DIRECT_RE.match(d.spec.strip()):
            _direct(sc, d.file, d.line, d.spec.strip(), d.name)


def _check_osv(sc: _Scan, file_lines: dict[str, list[str]]) -> None:
    osv = sc.osv
    if not osv:
        return
    if osv.get("error"):
        sc.note("Tra cứu OSV (gói độc hại) không thành công: " + _safe(osv["error"], 100))
    bad: dict[tuple[str, str], list[tuple[str | None, str]]] = {}
    for e in osv.get("malicious") or []:
        if not isinstance(e, dict) or not e.get("name"):
            continue
        eco = str(e.get("ecosystem", "")).lower()
        eco = "pypi" if eco == "pypi" else eco
        bad.setdefault((eco, P.norm_name(eco, str(e["name"]))), []).append(
            (e.get("version") or None, re.sub(r"[^A-Za-z0-9._-]", "", str(e.get("id", "")))[:40]))
    for d in sc.deps:
        for ver, mid in bad.get((d.eco, P.norm_name(d.eco, d.name)), []):
            cur = re.sub(r"^[\^~<>=!v\s]+", "", d.spec.strip()).split(" ")[0].split(",")[0]
            if ver is None or cur == ver:
                line = d.line
                if line is None and d.file in file_lines:
                    line = _find_line(file_lines[d.file], d.name)
                sc.add("osv-malware", "high", d.file, line,
                       f"Phụ thuộc bị cơ sở dữ liệu công khai báo là gói độc hại ({mid or 'OSV'})",
                       key=(d.name, ver))


# ---------------------------------------------------------------- per-file logic

_SETUP_RUN_RE = re.compile(r"os\.system|os\.popen|subprocess|(?<![.\w])(exec|eval)\s*\(")
_SETUP_NET_RE = re.compile(
    r"urlopen|urllib\.request|urlretrieve|requests\.(get|post)|\bcurl\b|\bwget\b|socket\.|http\.client", re.I)
_PR_HEAD_RE = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref")


def _scan_setup_py(sc: _Scan, rel: str, text: str) -> None:
    if "cmdclass" not in text and "setup(" not in text:
        return
    run = None
    net = False
    for i, ln in enumerate(text.splitlines(), 1):
        ln = ln[:MAX_LINE]
        if run is None and _SETUP_RUN_RE.search(ln):
            run = i
        if _SETUP_NET_RE.search(ln) or any(r.search(ln) for r in P.PIPE_RES):
            net = True
    if run is not None:
        sc.add("autorun-python-build", "high" if net else "medium", rel, run,
               "setup.py chạy lệnh/mã khi cài gói" + (" và có tải mã từ mạng" if net else ""))


def _scan_workflow(sc: _Scan, rel: str, text: str) -> None:
    prt = risky = None
    for i, ln in enumerate(text.splitlines(), 1):
        ln = ln[:MAX_LINE]
        if prt is None and re.search(r"\bpull_request_target\b", ln):
            prt = i
        if risky is None and (_PR_HEAD_RE.search(ln) or any(r.search(ln) for r in P.PIPE_RES)):
            risky = i
    if prt is not None:
        sc.add("autorun-workflow", "medium" if risky else "low", rel, prt,
               "Workflow pull_request_target" + (" lấy mã của PR hoặc tải-rồi-chạy từ mạng (có đặc quyền ghi/secret)" if risky else ""))


def _scan_special(sc: _Scan, rel: str, name: str, text: str) -> None:
    low = rel.lower()
    lines = text.splitlines()
    if name == "package.json":
        _scan_package_json(sc, rel, text)
    elif name == "package-lock.json":
        _scan_package_lock(sc, rel, text)
    elif re.match(r"^requirements.*\.txt$", name.lower()) or "/requirements/" in "/" + low:
        if low.endswith(".txt"):
            _scan_requirements(sc, rel, text)
    elif name == "pyproject.toml":
        _scan_pyproject(sc, rel, text)
    if low.endswith(".vscode/tasks.json"):
        m = re.search(r'"runOn"\s*:\s*"folderOpen"', text)
        if m:
            net = P.NET_CMD_RE.search(text) or any(
                '"command"' in ln and "http" in ln.lower() for ln in lines)
            sc.add("autorun-editor-task", "high" if net else "medium", rel, text.count("\n", 0, m.start()) + 1,
                   "Tác vụ VS Code tự chạy khi mở thư mục" + (" và có tải/chạy mã từ mạng" if net else ""))
    if name == "setup.py":
        _scan_setup_py(sc, rel, text)
    if low.endswith((".yml", ".yaml")) and ".github/workflows/" in "/" + low:
        _scan_workflow(sc, rel, text)
    if name == ".devcontainer.json" or (".devcontainer/" in "/" + low and name.endswith(".json")):
        keys = "|".join(P.DEVCONTAINER_KEYS)
        for m in re.finditer(r'"(%s)"\s*:\s*(\[[^\]]{0,2000}\]|\{[^}]{0,2000}\}|"(?:[^"\\\n]|\\.){0,2000}")' % keys, text):
            if P.NET_RE.search(m.group(2)):
                sc.add("autorun-devcontainer", "high", rel, text.count("\n", 0, m.start()) + 1,
                       f"Devcontainer '{m.group(1)}' tự chạy khi mở và có tải mã từ mạng", key=m.group(1))


def _is_exe_header(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:2] == b"MZ" and b"\x00" in head[:64]:
        return "MZ"
    return None


def _scan_file(sc: _Scan, root: Path, full: str, rel: str, max_bytes: int) -> None:
    name = os.path.basename(full)
    ext = os.path.splitext(name)[1].lower()
    try:
        st = os.lstat(full)
    except OSError:
        sc.note(f"Không đọc được file: {_safe(rel)}")
        return
    if not stat.S_ISREG(st.st_mode):
        sc.note(f"Bỏ qua file đặc biệt (không phải file thường): {_safe(rel)}")
        return
    if ext in P.EXE_MEDIUM_EXTS:
        sc.add("executable-binary", "medium", rel, None, f"File thực thi ({ext}) trong repo")
    elif ext in P.EXE_LOW_EXTS:
        sc.add("executable-binary", "low", rel, None, f"File thực thi/script đóng gói ({ext}) trong repo")
    try:
        with open(full, "rb") as fh:
            head = fh.read(4096)
            kind = _is_exe_header(head)
            if kind and ext not in P.EXE_MEDIUM_EXTS:
                sc.add("executable-binary", "medium", rel, None, f"File nhị phân thực thi (header {kind}) trong repo")
            if st.st_size > max_bytes:
                sc.note(f"File quá lớn, không phân tích nội dung: {_safe(rel)} ({st.st_size} byte)")
                return
            if b"\x00" in head:
                return
            data = head + fh.read(max_bytes - len(head) + 1)
    except OSError:
        sc.note(f"Không đọc được file: {_safe(rel)}")
        return
    text = data.decode("utf-8", errors="ignore")
    if "/" not in rel and ext in (".cmd", ".ps1", ".sh", ".vbs", ".wsf"):
        sc.add("root-script", "info", rel, None, f"Script ({ext}) ở thư mục gốc repo")
    if (name in ("package.json", "package-lock.json", "pyproject.toml", "setup.py") or ext in (".txt", ".json")
            or (ext in (".yml", ".yaml") and ".github/workflows/" in "/" + rel)):
        _scan_special(sc, rel, name, text)
        sc.file_lines[rel] = text.splitlines() if name == "package-lock.json" else []
    if ext not in P.DOC_EXTS:
        _scan_text(sc, rel, name, ext, text)


def _scan_git_hooks(sc: _Scan, git_dir: str, rel_git: str) -> None:
    hooks = os.path.join(git_dir, "hooks")
    if os.path.islink(hooks):
        sc.note(f"Thư mục hooks là symlink, không theo: {_safe(rel_git)}/hooks")
        return
    try:
        entries = sorted(os.scandir(hooks), key=lambda e: e.name)
    except OSError:
        return
    for e in entries:
        if e.name.endswith(".sample"):
            continue
        try:
            if e.is_file(follow_symlinks=False):
                sc.add("autorun-git-hook", "medium", f"{rel_git}/hooks/{e.name}", None,
                       "Git hook đi kèm repo (chạy khi dùng git, có thể chạy mã tuỳ ý)")
        except OSError:
            continue


def analyze_tree(root: Path, osv: dict | None = None, max_file_bytes: int = 2_000_000,
                 deadline: float = 300, clock=time.monotonic) -> ScanResult:
    root = Path(root)
    sc = _Scan(osv)
    start = clock()
    root_real = os.path.realpath(root)
    expired = False

    def onerror(e):  # noqa: ANN001
        sc.note(f"Không đọc được thư mục: {_safe(getattr(e, 'filename', ''))}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        if clock() - start > deadline:
            expired = True
            break
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir

        def rel_of(n: str) -> str:
            return f"{rel_dir}/{n}" if rel_dir else n

        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                if not _inside(root_real, full):
                    sc.sym_notes += 1
                    if sc.sym_notes <= MAX_NOTES:
                        sc.note(f"Symlink trỏ ra ngoài repo, không theo: {_safe(rel_of(d))}")
                continue
            if d == ".git":
                _scan_git_hooks(sc, full, rel_of(d))
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            if clock() - start > deadline:
                expired = True
                break
            full = os.path.join(dirpath, f)
            if os.path.islink(full):
                if not _inside(root_real, full):
                    sc.sym_notes += 1
                    if sc.sym_notes <= MAX_NOTES:
                        sc.note(f"Symlink trỏ ra ngoài repo, không theo: {_safe(rel_of(f))}")
                continue
            _scan_file(sc, root, full, rel_of(f), max_file_bytes)
        if expired:
            break
    if sc.sym_notes > MAX_NOTES:
        sc.note(f"... và {sc.sym_notes - MAX_NOTES} symlink khác trỏ ra ngoài repo")
    if expired:
        sc.note(f"Hết thời gian phân tích (deadline {deadline:g}s), chưa quét hết repo")
    if not expired and clock() - start > deadline:
        sc.note(f"Hết thời gian phân tích (deadline {deadline:g}s) trước bước kiểm tra phụ thuộc/OSV")
        return sc.res
    _check_deps(sc)
    _check_osv(sc, sc.file_lines)
    return sc.res


def _inside(root_real: str, path: str) -> bool:
    try:
        target = os.path.realpath(path)
        return os.path.commonpath([root_real, target]) == root_real
    except ValueError:
        return False

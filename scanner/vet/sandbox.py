"""Sandbox Docker cho "kiểm tra repo lạ" (spec 8b.3–8b.5).

Repo lạ KHÔNG bao giờ nằm trên hệ thống file Windows: nó chỉ sống trong một volume Docker
có tên, kiểu tmpfs (giới hạn dung lượng ngay ở tầng mount), bị xoá trong `finally`.

Các bước (mỗi bước một container `--rm`, cap-drop ALL, no-new-privileges, user 10001,
rootfs chỉ đọc, giới hạn RAM/PID, đặt `--name` để `docker kill` khi quá giờ):
  1. fetch    (có mạng)  git clone --depth 1 với hook/filter/LFS/submodule/symlink tắt,
              chỉ https, không theo redirect, IP máy chủ GHIM bằng --add-host (chống DNS rebinding).
  2. size     (không mạng) du -sk để phát hiện vượt giới hạn.
  3. packages (không mạng) liệt kê gói từ package-lock.json -> tra OSV ở tiến trình điều khiển.
  4. osv-write(không mạng) ghi osv.json vào volume kết quả.
  5. analyze  (không mạng, repo :ro) python -m scanner.vet.
  6. read     (không mạng, chỉ đọc) cat vet.json -> stdout. Không bao giờ chép repo ra.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..docker_desktop import DockerUnavailable
from . import source as S
from .osv import Http, default_http, lookup_osv, valid_packages
from .signals import ScanResult, Signal
from .verdict import Verdict, decide

GIT_IMAGE = "alpine/git:v2.47.2"
VET_IMAGE = "scan-vet:local"
VET_USER = "10001:10001"
MAX_BYTES = 500_000_000
FETCH_TIMEOUT = 300
ANALYZE_TIMEOUT = 300
ANALYZE_DEADLINE = 270  # bộ phân tích tự dừng sớm hơn lệnh kill để còn ghi vet.json
STEP_TIMEOUT = 120
OUT_BYTES = 32_000_000
MAX_RESULT_BYTES = 5_000_000
MAX_OSV_ARG = 20_000  # argv Windows tối đa ~32K ký tự; chừa chỗ cho phần còn lại của lệnh
_LEVELS = frozenset({"high", "medium", "low", "info"})
_MAX_SIGNALS = 2000
_LEVEL_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_VOLUME = re.compile(r"scanvet-[0-9a-f]{8,32}(-out)?")
_PKG_DIR = Path(__file__).resolve().parent

Fetch = Callable[[Callable, str], int]


@dataclass
class VetOutcome:
    verdict: Optional[Verdict]
    result: Optional[ScanResult]
    fetch_error: Optional[str]
    truncated: bool
    tool_errors: list[str] = field(default_factory=list)
    source: Optional[S.Source] = None


# ------------------------------------------------------------------ helpers

_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")


def clean(text, limit: int = 300) -> str:
    """Bỏ ký tự điều khiển/bidi khỏi chuỗi do repo kiểm soát trước khi in hoặc báo cáo."""
    return _CTRL.sub("", str(text))[:limit]


def new_volume_name() -> str:
    return f"scanvet-{uuid.uuid4().hex}"


def _check_volume(volume: str) -> None:
    if not isinstance(volume, str) or not _VOLUME.fullmatch(volume):
        raise S.InvalidSource("Tên volume không hợp lệ (chỉ chấp nhận volume scanvet-*).")


def _revalidate(src: S.Source) -> None:
    """Kiểm tra lại Source (có thể được tạo trực tiếp, không qua parse_source)."""
    S._check_host(src.host)
    segs = src.path.split("/") if isinstance(src.path, str) else []
    if not 2 <= len(segs) <= S._MAX_SEGMENTS or not all(
            S._SEGMENT.fullmatch(s) and s not in (".", "..") and not s.endswith(".git") for s in segs):
        raise S.InvalidSource("Đường dẫn repo không hợp lệ.")
    if src.clone_url != f"https://{src.host}/{src.path}.git":
        raise S.InvalidSource("URL tải repo không khớp máy chủ/đường dẫn.")
    b = src.branch
    if b is not None and (not isinstance(b, str) or not S._BRANCH.fullmatch(b) or ".." in b or "//" in b
                          or b.endswith(("/", ".", ".lock")) or "@" in b or "/." in b or "/-" in b):
        raise S.InvalidSource("Tên nhánh không hợp lệ.")


def _pin_ip(host: str, resolver=None) -> str:
    addrs = S.resolve_public(host, resolver)
    v4 = [a for a in addrs if ":" not in a]
    if not v4:
        raise S.InvalidSource(f"Máy chủ {host} không có địa chỉ IPv4 công khai để ghim.")
    return v4[0]


def _base(step: str, name: str, memory: str = "256m", pids: str = "64", network: bool = False) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", name, "--label", "scanvet=1", "--label", f"scanvet.step={step}",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", memory,
           "--memory-swap", memory, "--pids-limit", pids, "--user", VET_USER, "--read-only",
           "--tmpfs", "/tmp:rw,size=64m,noexec,nosuid,nodev"]
    if not network:
        cmd += ["--network", "none"]
    return cmd


def _name(step: str) -> str:
    return f"scanvet-{step}-{uuid.uuid4().hex[:12]}"


# ------------------------------------------------------------------ command builders

def build_volume_create(volume: str, size_bytes: int) -> list[str]:
    _check_volume(volume)
    return ["docker", "volume", "create", "--label", "scanvet=1", "--driver", "local",
            "--opt", "type=tmpfs", "--opt", "device=tmpfs",
            "--opt", f"o=size={int(size_bytes)},uid=10001,gid=10001,mode=0700", volume]


def build_fetch_command(src: S.Source, volume: str, max_bytes: int = MAX_BYTES, *,
                        pinned_ip: Optional[str] = None, resolver=None, name: Optional[str] = None) -> list[str]:
    """Lệnh git clone trong container. Giới hạn dung lượng do volume tmpfs size=max_bytes."""
    _revalidate(src)
    _check_volume(volume)
    ip = pinned_ip or _pin_ip(src.host, resolver)
    cmd = _base("fetch", name or _name("fetch"), memory="1g", pids="256", network=True) + [
        "--add-host", f"{src.host}:{ip}",
        "-e", "HOME=/tmp", "-e", "GIT_TERMINAL_PROMPT=0", "-e", "GIT_CONFIG_NOSYSTEM=1",
        "-e", "GIT_CONFIG_GLOBAL=/dev/null", "-e", "GIT_LFS_SKIP_SMUDGE=1", "-e", "GIT_ASKPASS=",
        "-v", f"{volume}:/work", "--entrypoint", "git", GIT_IMAGE]
    for c in ("core.hooksPath=/dev/null", "core.symlinks=false", "core.fsmonitor=false",
              "protocol.allow=never", "protocol.https.allow=always", "protocol.file.allow=never",
              "http.followRedirects=false", "credential.helper=", "transfer.fsckObjects=true",
              "filter.lfs.smudge=", "filter.lfs.process=", "filter.lfs.required=false",
              "submodule.recurse=false"):
        cmd += ["-c", c]
    cmd += ["clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if src.branch:
        cmd += ["--branch", src.branch]
    return cmd + ["--", src.clone_url, "/work/repo"]


def build_size_command(volume: str, name: Optional[str] = None) -> list[str]:
    _check_volume(volume)
    return _base("size", name or _name("size")) + ["-v", f"{volume}:/work:ro", "--entrypoint", "du",
                                           GIT_IMAGE, "-sk", "/work"]


def build_packages_command(volume: str, name: Optional[str] = None) -> list[str]:
    _check_volume(volume)
    return _base("packages", name or _name("packages"), memory="512m") + [
        "-v", f"{volume}:/work:ro", "--entrypoint", "python", VET_IMAGE,
        "-m", "scanner.vet.osv", "list", "/work/repo"]


def build_osv_write_command(out_volume: str, osv: dict, name: Optional[str] = None) -> list[str]:
    _check_volume(out_volume)
    return _base("osv-write", name or _name("osvw")) + [
        "-v", f"{out_volume}:/out", "--entrypoint", "python", VET_IMAGE,
        "-m", "scanner.vet.osv", "write", "/out/osv.json", json.dumps(osv, ensure_ascii=True)]


def build_analyze_command(volume: str, out_volume: str, *, memory: str = "1g", pids: str = "128",
                          name: Optional[str] = None) -> list[str]:
    _check_volume(volume)
    _check_volume(out_volume)
    return _base("analyze", name or _name("analyze"), memory=memory, pids=pids) + [
        "-v", f"{volume}:/work:ro", "-v", f"{out_volume}:/out", VET_IMAGE,
        "/work/repo", "--osv", "/out/osv.json", "--out", "/out/vet.json", "--deadline", str(ANALYZE_DEADLINE)]


def build_read_command(out_volume: str, name: Optional[str] = None) -> list[str]:
    _check_volume(out_volume)
    return _base("read", name or _name("read")) + ["-v", f"{out_volume}:/in:ro", "--entrypoint", "cat",
                                           GIT_IMAGE, "/in/vet.json"]


# ------------------------------------------------------------------ image

IMAGE_FILES = ("scanner/__init__.py", "scanner/vet/__init__.py", "scanner/vet/__main__.py",
               "scanner/vet/signals.py", "scanner/vet/patterns.py", "scanner/vet/osv.py")


def ensure_vet_image(executor) -> bool:
    """docker build với context tạm chỉ gồm các file cần thiết (không phải cả repo)."""
    root = _PKG_DIR.parent.parent
    with tempfile.TemporaryDirectory(prefix="scanvet-build-") as tmp:
        ctx = Path(tmp)
        for rel in IMAGE_FILES:
            dst = ctx / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / rel, dst)
        shutil.copyfile(_PKG_DIR / "Dockerfile", ctx / "Dockerfile")
        return executor(["docker", "build", "--label", "scanvet=1", "-t", VET_IMAGE, str(ctx)],
                        None, 600) == 0


# ------------------------------------------------------------------ result parsing

def _read_text(path: Path) -> str:
    try:
        if not path.is_file():
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_RESULT_BYTES)
    except OSError:
        return ""


def _encodable(v: str) -> bool:
    try:
        v.encode("utf-8")  # lone surrogate (U+D800-U+DFFF) -> UnicodeEncodeError
        return True
    except UnicodeEncodeError:
        return False


def _str_field(v, limit: int) -> Optional[str]:
    return v if isinstance(v, str) and len(v) <= limit and _encodable(v) else None


def parse_result(text: str) -> Optional[ScanResult]:
    """vet.json do container (không tin cậy) -> ScanResult, hoặc None nếu hỏng/sai schema.
    None luôn dẫn tới SUSPICIOUS + tool_error ở vet_repo, không bao giờ ném ngoại lệ."""
    if not isinstance(text, str) or len(text) > MAX_RESULT_BYTES:
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list) \
            or not isinstance(data.get("incomplete"), list):
        return None
    sigs = []
    for s in data["signals"]:
        if not isinstance(s, dict):
            return None
        sid, level = _str_field(s.get("id"), 200), s.get("level")
        file, why = _str_field(s.get("file"), 1000), _str_field(s.get("why"), 1000)
        line = s.get("line")
        if sid is None or file is None or why is None or not isinstance(level, str) or level not in _LEVELS:
            return None
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or not 0 <= line < 10**9):
            return None
        sigs.append(Signal(clean(sid, 80), level, clean(file, 300), line, clean(why, 300)))
    inc = data["incomplete"][:200]
    if not all(isinstance(i, str) and _encodable(i) for i in inc):
        return None
    incomplete = [clean(i, 300) for i in inc]
    if len(sigs) > _MAX_SIGNALS:
        dropped = len(sigs) - _MAX_SIGNALS
        sigs = sorted(sigs, key=lambda x: _LEVEL_RANK[x.level])[:_MAX_SIGNALS]  # sort ổn định
        incomplete.append(f"Đã cắt bớt {dropped} tín hiệu (giữ {_MAX_SIGNALS} tín hiệu mức cao nhất)")
    return ScanResult(sigs, incomplete)

def _parse_kb(text: str) -> Optional[int]:
    m = re.match(r"\s*(\d+)", text or "")
    return int(m.group(1)) if m else None


# ------------------------------------------------------------------ orchestration

def _fail(src, msg, truncated=False) -> VetOutcome:
    return VetOutcome(None, None, msg, truncated, [], src)


def _cleanup(executor, names: list[str], created: list[str]) -> None:
    """Kill container trước, rồi xoá volume (thử lại 1 lần). Lỗi dọn dẹp không che ngoại lệ gốc."""
    def attempt(cmd: list[str]) -> int:
        try:
            return executor(cmd, None, STEP_TIMEOUT)
        except Exception:  # noqa: BLE001 - dọn dẹp là best-effort
            return 1
    if names:
        attempt(["docker", "rm", "-f", *names])
    if created and attempt(["docker", "volume", "rm", "-f", *created]) != 0:
        if names:
            attempt(["docker", "rm", "-f", *names])
        attempt(["docker", "volume", "rm", "-f", *created])


def vet_repo(src: S.Source, executor, docker, now=None, fetch: Optional[Fetch] = None,
             http: Http = default_http, resolver=None, max_bytes: int = MAX_BYTES) -> VetOutcome:
    """Tải + phân tích repo trong sandbox. `fetch(executor, volume) -> exit code` thay git clone
    (cho test/e2e nạp fixture). `now` để dành cho lớp báo cáo (không dùng ở đây)."""
    try:
        _revalidate(src)
        ip = None if fetch is not None else _pin_ip(src.host, resolver)
    except S.InvalidSource as e:
        return _fail(src, f"Nguồn repo bị từ chối: {clean(e)}")
    try:
        docker.ensure()
    except DockerUnavailable as e:
        return _fail(src, f"Không dùng được Docker: {clean(e)}")
    if not ensure_vet_image(executor):
        return _fail(src, "Không tạo được image phân tích (docker build lỗi).")

    vol, out_vol = new_volume_name(), None
    out_vol = vol + "-out"
    created: list[str] = []
    names: list[str] = []

    def nm(step_name: str) -> str:
        n = _name(step_name)
        names.append(n)  # mọi container đều có tên đã biết để `docker rm -f` khi dọn
        return n
    tool_errors: list[str] = []
    truncated = False
    tmp = tempfile.TemporaryDirectory(prefix="scanvet-")
    tdir = Path(tmp.name)
    try:
        for v, size in ((vol, max_bytes), (out_vol, OUT_BYTES)):
            if executor(build_volume_create(v, size), None, STEP_TIMEOUT) != 0:
                return _fail(src, "Không tạo được volume Docker cho repo.")
            created.append(v)

        if fetch is not None:
            code = fetch(executor, vol)
        else:
            code = executor(build_fetch_command(src, vol, max_bytes, pinned_ip=ip, name=nm("fetch")),
                       None, FETCH_TIMEOUT)

        executor(build_size_command(vol, nm("size")), tdir / "size.txt", STEP_TIMEOUT)
        kb = _parse_kb(_read_text(tdir / "size.txt"))
        if kb is not None and kb * 1024 >= max_bytes * 0.95:
            truncated = True
        if code != 0:
            why = ("quá thời gian tải" if code == 124 else f"git thoát mã {code}")
            msg = (f"Tải repo thất bại ({why}): có thể do mạng, repo không tồn tại/không công khai, "
                   f"hoặc nhánh không có.")
            if truncated:
                msg = f"Repo vượt giới hạn {max_bytes // 1_000_000} MB nên không tải trọn được; không kiểm tra."
            return _fail(src, msg, truncated)
        if kb is None:
            tool_errors.append("Không đo được dung lượng repo")

        executor(build_packages_command(vol, nm("packages")), tdir / "packages.json", STEP_TIMEOUT)
        try:
            raw = json.loads(_read_text(tdir / "packages.json"))
            if not isinstance(raw, list):
                raise ValueError("danh sách gói không phải list")
            pk = valid_packages(raw)
            osv = lookup_osv(pk, http)
        except (ValueError, RecursionError, MemoryError):
            osv = {"malicious": [], "error": "không liệt kê được gói từ package-lock.json"}
        if osv.get("error"):
            tool_errors.append("Tra cứu OSV (gói độc hại) không đầy đủ: " + clean(osv["error"], 150))
        if len(json.dumps(osv, ensure_ascii=True)) > MAX_OSV_ARG:
            # Không có stdin trong executor: giới hạn kích thước argv, ghi nhận là chưa đầy đủ.
            mal = list(osv.get("malicious") or [])
            while mal and len(json.dumps({"malicious": mal, "error": "x"}, ensure_ascii=True)) > MAX_OSV_ARG:
                mal = mal[:len(mal) // 2]
            osv = {"malicious": mal, "error": "kết quả OSV quá lớn, đã cắt bớt"}
            tool_errors.append("Tra cứu OSV (gói độc hại) không đầy đủ: kết quả quá lớn, đã cắt bớt")
        if executor(build_osv_write_command(out_vol, osv, nm("osvw")), None, STEP_TIMEOUT) != 0:
            tool_errors.append("Không chuyển được kết quả OSV vào bước phân tích")

        acode = executor(build_analyze_command(vol, out_vol, name=nm("analyze")), None, ANALYZE_TIMEOUT)
        if acode == 124:
            tool_errors.append("Phân tích quá 5 phút, đã dừng")
        elif acode == 137:
            tool_errors.append("Bộ phân tích bị dừng (có thể hết bộ nhớ)")
        elif acode != 0:
            tool_errors.append(f"Bộ phân tích thoát mã {acode}")

        executor(build_read_command(out_vol, nm("read")), tdir / "vet.json", STEP_TIMEOUT)
        result = parse_result(_read_text(tdir / "vet.json"))
        if result is None:
            result = ScanResult([], ["Không đọc được kết quả phân tích (vet.json thiếu hoặc hỏng)"])
            if not tool_errors:
                tool_errors.append("Kết quả phân tích thiếu hoặc hỏng")
        if truncated:
            result.incomplete.append(f"Repo vượt giới hạn {max_bytes // 1_000_000} MB, kết quả có thể thiếu")
        verdict = decide(result, None, truncated, tool_errors)
        return VetOutcome(verdict, result, None, truncated, tool_errors, src)
    finally:
        try:
            _cleanup(executor, names, created)
        finally:
            tmp.cleanup()
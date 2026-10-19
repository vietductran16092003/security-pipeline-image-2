"""Chạy các công cụ quét (qua Docker) và xác định trạng thái từng phần quét."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

from .detect import SKIP_DIRS, detect_project, plan_sections
from .models import SECTION_IDS, Section
from .parsers import parse_conftest, parse_gitleaks, parse_semgrep, parse_trivy

# (lệnh, file ghi stdout hoặc None, timeout giây) -> exit code
Executor = Callable[[list[str], Optional[Path], Optional[float]], int]

TOOL_IMAGES: dict[str, str] = {
    "gitleaks": "zricethezav/gitleaks:v8.21.2",
    "semgrep": "semgrep/semgrep:1.97.0",
    "trivy": "aquasec/trivy:0.57.1",
    "conftest": "openpolicyagent/conftest:v0.56.0",
}
TRIVY_CACHE_VOLUME = "scanner-trivy-cache:/root/.cache"
TARGET_IMAGE = "scan-target:local"
TOOL_TIMEOUT = 600
# Tổng thời gian cho mọi công cụ, nhỏ hơn timeout 20 phút của job để còn kịp ghi báo cáo và gửi mail.
SCAN_DEADLINE = 900
EXCLUDED_DIRS = (".scanner", "scan-out")

# phần quét -> (file output, parser, các exit code chấp nhận)
OUTPUTS = {
    "secrets": ("gitleaks.json", parse_gitleaks, (0,)),
    "code": ("semgrep.json", parse_semgrep, (0, 1)),
    "deps": ("trivy-fs.json", parse_trivy, (0,)),
    "image": ("trivy-image.json", parse_trivy, (0,)),
    "dockerfile_policy": ("conftest.json", parse_conftest, (0, 1)),
    "iac": ("trivy-config.json", parse_trivy, (0,)),
}


def default_executor(cmd: list[str], stdout_path: Optional[Path] = None,
                     timeout: Optional[float] = TOOL_TIMEOUT) -> int:
    print("$ " + " ".join(cmd), flush=True)
    try:
        if stdout_path is not None:
            with open(stdout_path, "w", encoding="utf-8") as fh:
                return subprocess.run(cmd, stdout=fh, timeout=timeout).returncode
        return subprocess.run(cmd, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        print(f"Hết thời gian chờ ({timeout:.0f}s)", flush=True)
        if "--name" in cmd:  # timeout chỉ giết docker client, phải dừng cả container
            subprocess.run(["docker", "kill", cmd[cmd.index("--name") + 1]], capture_output=True)
        return 124
    except FileNotFoundError as exc:
        print(f"Không tìm thấy lệnh: {exc}", flush=True)
        return 127


def _docker(image: str, mounts: list[str], extra: Optional[list[str]] = None) -> list[str]:
    cmd = ["docker", "run", "--rm", "--name", f"scanner-{uuid.uuid4().hex[:12]}"]
    for m in mounts:
        cmd += ["-v", m]
    return cmd + (extra or []) + [image]


def _trivy_skip() -> list[str]:
    return ["--skip-dirs", ",".join(f"/repo/{d}" for d in EXCLUDED_DIRS)]


# Repo trên runner thuộc user khác với user trong container: báo git tin tưởng /repo.
GIT_SAFE_DIR = ["-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory", "-e", "GIT_CONFIG_VALUE_0=/repo"]


def _trivy_ignore(root: Path) -> list[str]:
    return ["--ignorefile", "/repo/.trivyignore"] if (root / ".trivyignore").is_file() else []


def build_commands(section_id: str, root: Path, out: Path, scanner_dir: Path) -> list[list[str]]:
    root, out, scanner_dir = Path(root).resolve(), Path(out).resolve(), Path(scanner_dir).resolve()
    repo, outm = f"{root}:/repo", f"{out}:/out"
    if section_id == "secrets":
        return [_docker(TOOL_IMAGES["gitleaks"], [repo, outm], GIT_SAFE_DIR) + [
            "detect", "--source", "/repo", "--redact", "--report-format", "json",
            "--report-path", "/out/gitleaks.json", "--exit-code", "0"]]
    if section_id == "code":
        excludes = [a for d in EXCLUDED_DIRS for a in ("--exclude", d)]
        return [_docker(TOOL_IMAGES["semgrep"], [repo, outm], ["-w", "/repo", *GIT_SAFE_DIR]) + [
            "semgrep", "scan", "--config", "p/default", "--json", "--output", "/out/semgrep.json",
            "--metrics=off", *excludes, "/repo"]]
    if section_id == "deps":
        return [_docker(TOOL_IMAGES["trivy"], [repo, outm, TRIVY_CACHE_VOLUME]) + [
            "fs", "--scanners", "vuln", *_trivy_skip(), *_trivy_ignore(root), "--format", "json",
            "--output", "/out/trivy-fs.json", "/repo"]]
    if section_id == "image":
        return [
            ["docker", "build", "-t", TARGET_IMAGE, str(root)],
            _docker(TOOL_IMAGES["trivy"], ["/var/run/docker.sock:/var/run/docker.sock", f"{root}:/repo:ro",
                                           outm, TRIVY_CACHE_VOLUME]) + [
                "image", "--scanners", "vuln", *_trivy_ignore(root), "--format", "json",
                "--output", "/out/trivy-image.json", TARGET_IMAGE],
        ]
    if section_id == "dockerfile_policy":
        return [_docker(TOOL_IMAGES["conftest"], [repo, f"{scanner_dir / 'policy'}:/policy"]) + [
            "test", "/repo/Dockerfile", "--policy", "/policy", "--parser", "dockerfile",
            "--all-namespaces", "--output", "json"]]
    if section_id == "iac":
        return [_docker(TOOL_IMAGES["trivy"], [repo, outm, TRIVY_CACHE_VOLUME]) + [
            "config", *_trivy_skip(), *_trivy_ignore(root), "--format", "json", "--output", "/out/trivy-config.json", "/repo"]]
    raise ValueError(f"Phần quét không tồn tại: {section_id}")


def _tool_name(cmd: list[str]) -> str:
    if cmd[:2] == ["docker", "build"]:
        return "docker build"
    for name, image in TOOL_IMAGES.items():
        if image in cmd:
            return name
    return cmd[0]


def _timeout_section(section_id: str, deadline: float) -> Section:
    return Section(section_id, "error", f"Hết thời gian quét (giới hạn {deadline / 60:.0f} phút cho toàn bộ công cụ)")


def _run_section(section_id: str, root: Path, out: Path, scanner_dir: Path, executor: Executor,
                 remaining: Callable[[], float], deadline: float) -> Section:
    filename, parser, accepted = OUTPUTS[section_id]
    target = out / filename
    if target.exists():
        target.unlink()
    for cmd in build_commands(section_id, root, out, scanner_dir):
        stdout_path = target if section_id == "dockerfile_policy" else None
        left = remaining()
        if left <= 0:
            return _timeout_section(section_id, deadline)
        code = executor(cmd, stdout_path, min(TOOL_TIMEOUT, left))
        if code == 124:
            return _timeout_section(section_id, deadline) if remaining() <= 0 else \
                Section(section_id, "error", f"{_tool_name(cmd)} chạy quá {TOOL_TIMEOUT // 60} phút")
        ok = (0,) if cmd[:2] == ["docker", "build"] else accepted
        if code not in ok:
            return Section(section_id, "error", f"{_tool_name(cmd)} thất bại (exit {code})")
    if not target.exists() or target.stat().st_size == 0:
        return Section(section_id, "error", "Công cụ không tạo ra file output")
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
        findings = parser(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError, TypeError):
        return Section(section_id, "error", "Output JSON không hợp lệ")
    for f in findings:  # đường dẫn trong container -> đường dẫn tương đối trong dự án
        if f.file and f.file.startswith("/repo/"):
            f.file = f.file[len("/repo/"):]
    return Section(section_id, "findings" if findings else "clean", findings=findings)


def run_scan(root: Path, out: Path, scanner_dir: Path, executor: Executor = default_executor,
             deadline: float = SCAN_DEADLINE, clock: Callable[[], float] = time.monotonic) -> list[Section]:
    root, out = Path(root), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    plan = plan_sections(detect_project(root))
    start = clock()

    def remaining() -> float:
        return deadline - (clock() - start)

    sections = []
    for sid in SECTION_IDS:
        if plan[sid] is not None:
            sections.append(Section(sid, "skipped", plan[sid]))
        else:
            sections.append(_run_section(sid, root, out, Path(scanner_dir), executor, remaining, deadline))
    return sections


def count_ignore_rules(root: Path) -> int:
    root = Path(root)
    total = 0
    for name in (".gitleaksignore", ".trivyignore"):
        f = root / name
        if f.is_file():
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            total += sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d not in EXCLUDED_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                total += path.read_text(encoding="utf-8", errors="ignore").count("nosemgrep")
            except OSError:
                continue
    return total

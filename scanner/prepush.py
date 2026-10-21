"""Hook pre-push: chỉ chặn secret trong các commit sắp push và lỗi P1; lỗi của bộ quét không khoá push."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .detect import detect_project, plan_sections
from .docker_desktop import DockerUnavailable
from .rules import apply_rules, load_rules
from .runner import _run_section, Executor
from .models import Finding

HOW_TO_BYPASS = "Bỏ qua kiểm tra: git push --no-verify  (hoặc đặt biến môi trường SCAN_SKIP=1)"


@dataclass
class RefUpdate:
    local_sha: str
    remote_sha: str


def _is_zero(sha: str) -> bool:
    return bool(sha) and set(sha) == {"0"}


def parse_ref_lines(text: str) -> list[RefUpdate]:
    ups = []
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) == 4:
            ups.append(RefUpdate(local_sha=parts[1], remote_sha=parts[3]))
    return ups


def commit_range(u: RefUpdate) -> Optional[str]:
    if _is_zero(u.local_sha):
        return None  # xoá nhánh: không có commit nào để quét
    if _is_zero(u.remote_sha):
        return f"{u.local_sha} --not --remotes"  # nhánh mới: chỉ commit chưa có trên remote nào
    return f"{u.remote_sha}..{u.local_sha}"


def _combined_log_opts(ups: list[RefUpdate]) -> Optional[str]:
    ranges = [r for r in (commit_range(u) for u in ups) if r]
    if not ranges:
        return None
    plain = [r for r in ranges if " --not " not in r]
    new = [r.split(" --not ")[0] for r in ranges if " --not " in r]
    parts = plain + ([*new, "--not", "--remotes"] if new else [])
    return " ".join(parts)


def _warn(msg: str) -> int:
    print(f"CẢNH BÁO (kiểm tra trước khi push): {msg}\nPush vẫn được tiếp tục.")
    return 0


def _where(f: Finding) -> str:
    # Không bao giờ in nội dung secret: chỉ file, dòng, tên rule.
    loc = f.file or f.package or "?"
    return f"{loc}:{f.line}" if f.line else loc


def prepush(root: Path, stdin_text: str, scanner_dir: Path, executor: Executor, docker) -> int:
    if os.environ.get("SCAN_SKIP") == "1":
        print("SCAN_SKIP=1: bỏ qua kiểm tra trước khi push.")
        return 0
    log_opts = _combined_log_opts(parse_ref_lines(stdin_text))
    if log_opts is None:
        return 0
    root, scanner_dir = Path(root).resolve(), Path(scanner_dir).resolve()
    try:
        started = docker.ensure()
    except DockerUnavailable as exc:
        return _warn(f"không kiểm tra được vì Docker không chạy ({exc}). Hãy quét lại sau.")
    except Exception as exc:  # noqa: BLE001
        return _warn(f"lỗi khi mở Docker: {exc}")
    try:
        findings = _scan(root, scanner_dir, executor, log_opts)
    except Exception as exc:  # noqa: BLE001 - lỗi của chính bộ quét không được khoá push
        return _warn(f"bộ quét gặp lỗi ({type(exc).__name__}: {exc}).")
    finally:
        if started:
            try:
                docker.stop()
            except Exception:  # noqa: BLE001
                pass
    if findings is None:
        return 0
    blocking = [f for f in findings if f.kind == "secret" or f.priority == "P1"]
    if not blocking:
        print("Kiểm tra trước khi push: không có secret hay lỗi P1. Cho phép push.")
        return 0
    print(f"Chặn push: phát hiện {len(blocking)} vấn đề nghiêm trọng.")
    for f in blocking:
        label = "Secret" if f.kind == "secret" else "P1"
        print(f"  - [{label}] {_where(f)} ({f.rule_id}) {f.title if f.kind != 'secret' else ''}".rstrip())
    print("Hãy thu hồi/sửa rồi push lại. " + HOW_TO_BYPASS)
    return 1


def _scan(root: Path, scanner_dir: Path, executor, log_opts: str):
    plan = plan_sections(detect_project(root))
    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="scan-prepush-") as tmp:
        out = Path(tmp)
        for sid in ("secrets", "deps"):
            if plan[sid] is not None:
                continue
            sec = _run_section(sid, root, out, scanner_dir, executor, lambda: 600.0, 600.0,
                               "ci", log_opts if sid == "secrets" else None)
            if sec.status == "error":
                raise RuntimeError(f"phần '{sid}' lỗi: {sec.detail}")
            findings += sec.findings
    apply_rules(findings, load_rules(scanner_dir / "rules.yaml"))
    return findings

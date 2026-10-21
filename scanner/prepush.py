"""Hook pre-push: chỉ chặn secret trong các commit sắp push và lỗi P1; lỗi của bộ quét không khoá push."""

from __future__ import annotations

import os
import sys
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
    bad = 0
    for ln in text.splitlines():
        parts = ln.split()
        if len(parts) == 4:
            ups.append(RefUpdate(local_sha=parts[1], remote_sha=parts[3]))
        elif ln.strip():
            bad += 1
            print("CẢNH BÁO - KHÔNG ĐƯỢC KIỂM TRA: bỏ qua dòng ref không đúng định dạng của hook pre-push.",
                  file=sys.stderr)
    if bad and not ups:
        print("CẢNH BÁO - KHÔNG ĐƯỢC KIỂM TRA: không dòng ref nào hợp lệ, chưa kiểm tra gì cả.", file=sys.stderr)
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
    print(f"CẢNH BÁO - KHÔNG ĐƯỢC KIỂM TRA (kiểm tra trước khi push): {msg}\nPush vẫn được tiếp tục.",
          file=sys.stderr)
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
    findings: list[Finding] = []
    errors: list[str] = []
    try:
        _scan(root, scanner_dir, executor, log_opts, findings, errors)
    except Exception as exc:  # noqa: BLE001 - lỗi của chính bộ quét không được khoá push
        errors.append(f"bộ quét gặp lỗi ({type(exc).__name__}: {exc})")
    finally:
        if started:
            try:
                docker.stop()
            except Exception:  # noqa: BLE001
                pass
    # Nếu rules.yaml hỏng thì chưa có priority: coi CRITICAL là P1 để không bỏ lọt.
    blocking = [f for f in findings
                if f.kind == "secret" or f.priority == "P1" or (f.priority is None and f.severity == "CRITICAL")]
    if errors:
        print("CẢNH BÁO - KHÔNG ĐƯỢC KIỂM TRA, chưa kiểm tra được: " + "; ".join(errors), file=sys.stderr)
    if not blocking:
        if not errors:
            print("Kiểm tra trước khi push: không có secret hay lỗi P1. Cho phép push.")
        else:
            print("Không thấy secret/P1 ở phần đã kiểm tra. Push vẫn được tiếp tục.", file=sys.stderr)
        return 0
    print(f"Chặn push: phát hiện {len(blocking)} vấn đề nghiêm trọng.", file=sys.stderr)
    for f in blocking:
        label = "Secret" if f.kind == "secret" else "P1"
        print(f"  - [{label}] {_where(f)} ({f.rule_id}) {f.title if f.kind != 'secret' else ''}".rstrip(),
              file=sys.stderr)
    print("Hãy thu hồi/sửa rồi push lại. " + HOW_TO_BYPASS, file=sys.stderr)
    return 1


def _scan(root: Path, scanner_dir: Path, executor, log_opts: str,
          findings: list[Finding], errors: list[str]) -> None:
    """Ghi kết quả vào findings/errors được truyền vào để lỗi muộn không làm mất phần đã thu thập."""
    plan = plan_sections(detect_project(root))
    with tempfile.TemporaryDirectory(prefix="scan-prepush-") as tmp:
        out = Path(tmp)
        for sid in ("secrets", "deps"):
            if plan[sid] is not None:
                continue
            sec = _run_section(sid, root, out, scanner_dir, executor, lambda: 600.0, 600.0,
                               "ci", log_opts if sid == "secrets" else None)
            if sec.status == "error":
                errors.append(f"{sid} ({sec.detail})")
                continue
            findings += sec.findings
    try:
        apply_rules(findings, load_rules(scanner_dir / "rules.yaml"))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"rules.yaml không đọc được ({type(exc).__name__}); chỉ chặn secret và CRITICAL")

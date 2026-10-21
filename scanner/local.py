"""Lệnh `check`: quét dự án trên máy, lưu lịch sử, so với lần trước, mở báo cáo."""

from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Callable

from . import store
from .docker_desktop import DockerUnavailable
from .grade import compute_grade
from .reporting import build_and_write_report, load_previous


def check_project(root: Path, scanner_dir: Path, executor, docker,
                  open_report: Callable[[Path], object] = webbrowser.open) -> int:
    """0 = quét xong (bất kể có lỗi); 2 = không quét được."""
    root = Path(root).resolve()
    if not root.is_dir():
        print(f"Không tìm thấy thư mục: {root}")
        return 2
    try:
        started = docker.ensure()
    except DockerUnavailable as exc:
        print(f"Không quét được: {exc}")
        return 2
    try:
        slug = store.slug_for(root)
        previous_path = store.latest_report(slug)
        out = store.new_run_dir(slug)
        report = build_and_write_report(
            root, out, Path(scanner_dir).resolve(), executor, mode="local", rules_path=None,
            meta=dict(project=root.name, branch="local", commit="local", run_id="local", run_url=""),
            get_previous=lambda: load_previous(previous_path) if previous_path else None,
        )
    finally:
        if started:
            docker.stop()
    if report is None:
        return 2
    store.prune(slug)
    c = report.counts()
    print(f"Xong: điểm {compute_grade(report)} · P1={c['P1']} P2={c['P2']} Backlog={c['Backlog']}")
    print(f"Báo cáo: {out / 'email.html'}")
    report_file = out / "email.html"
    try:
        opened = open_report(report_file)
    except Exception:  # noqa: BLE001 - không mở được trình duyệt không làm hỏng kết quả quét
        opened = False
    if not opened:
        print(f"Không mở được trình duyệt, hãy mở file: {report_file}")
    return 0

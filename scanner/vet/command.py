"""Lệnh `vet`: link repo -> kiểm tra trong sandbox -> vet.html (+ vet.json) -> mở trình duyệt."""
from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Callable

from .. import store
from ..docker_desktop import DockerUnavailable
from .render import render_vet_html
from .sandbox import clean, vet_repo
from .source import InvalidSource, parse_source

MAX_SOURCE_FILE = 4096


def read_source_file(path: Path) -> str:
    """Đọc link từ file tạm (do ask-repo.ps1 ghi), UTF-8, tối đa vài KB."""
    with open(path, "rb") as fh:
        raw = fh.read(MAX_SOURCE_FILE)
    return raw.decode("utf-8-sig", errors="replace").strip()


def _vet_json(outcome) -> dict:
    sigs = outcome.result.signals if outcome.result else []
    return {
        "verdict": outcome.verdict.value if outcome.verdict else None,
        "source": clean(outcome.source.display, 400) if outcome.source else None,
        "fetch_error": clean(outcome.fetch_error, 600) if outcome.fetch_error else None,
        "truncated": outcome.truncated,
        "tool_errors": [clean(e) for e in outcome.tool_errors],
        "incomplete": [clean(i) for i in (outcome.result.incomplete if outcome.result else [])],
        "signals": [dict(id=clean(s.id, 80), level=s.level, file=clean(s.file), line=s.line,
                         why=clean(s.why)) for s in sigs],
    }


def vet_command(text: str, executor, docker, open_report: Callable[[str], object] = webbrowser.open,
                parse=parse_source, vet=vet_repo) -> int:
    """0 = có mức hoặc "không kiểm tra được" rõ ràng; 2 = link sai / không dùng được Docker."""
    try:
        src = parse(text)
    except InvalidSource as exc:
        print(clean(exc, 500))
        return 2
    try:
        started = docker.ensure()
    except DockerUnavailable as exc:
        print(f"Không kiểm tra được: {clean(exc, 500)}")
        return 2
    try:
        outcome = vet(src, executor, docker)
    finally:
        if started:
            docker.stop()
    slug = "vet/" + store.slug_for_text(src.display)
    try:
        out = store.new_run_dir(slug)
        report_file = out / "vet.html"
        report_file.write_text(render_vet_html(outcome), encoding="utf-8")
        (out / "vet.json").write_text(json.dumps(_vet_json(outcome), ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    except OSError as exc:
        print(f"Không lưu được báo cáo: {clean(exc, 300)}")
        return 2
    store.prune(slug, keep=20)
    shown = clean(src.display, 200)
    if outcome.verdict is None:
        print(f"Không kiểm tra được {shown}: {clean(outcome.fetch_error or 'không rõ nguyên nhân', 300)}")
    else:
        print(f"Kết quả cho {shown}: {outcome.verdict.value}")
    print(f"Báo cáo: {report_file}")
    try:
        opened = open_report(str(report_file))
    except Exception:  # noqa: BLE001 - không mở được trình duyệt không làm hỏng kết quả
        opened = False
    if not opened:
        print(f"Không mở được trình duyệt, hãy mở file: {report_file}")
    return 0

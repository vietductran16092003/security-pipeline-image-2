"""Dựng báo cáo từ kết quả công cụ và ghi 4 file; dùng chung cho `run` và `check`."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .diff import diff_reports
from .models import Report
from .render import render_email, render_subject, render_summary
from .rules import apply_rules, load_rules
from .runner import count_ignore_rules, run_scan


def load_previous(path: Path) -> Optional[Report]:
    try:
        return Report.from_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def build_and_write_report(
    root: Path, out: Path, scanner_dir: Path, executor, *, mode: str, rules_path: Optional[Path],
    meta: dict, get_previous: Callable[[], Optional[Report]],
) -> Optional[Report]:
    """Quét, áp luật, dựng Report, so với lần trước, ghi 4 file. Trả None nếu không ghi được."""
    sections = run_scan(root, out, scanner_dir, executor, mode=mode)
    findings = [f for s in sections for f in s.findings]
    apply_rules(findings, load_rules(rules_path or scanner_dir / "rules.yaml"))
    report = Report(
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sections=sections,
        ignore_rules=count_ignore_rules(root),
        **meta,
    )
    diff = diff_reports(report, get_previous())
    try:
        (out / "report.json").write_text(report.to_json(), encoding="utf-8")
        (out / "email.html").write_text(render_email(report, diff), encoding="utf-8")
        (out / "subject.txt").write_text(render_subject(report, diff), encoding="utf-8")
        (out / "summary.md").write_text(render_summary(report, diff), encoding="utf-8")
    except OSError as exc:
        print(f"Không ghi được báo cáo: {exc}")
        return None
    return report

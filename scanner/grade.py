"""Chấm điểm A–F cho một lần quét."""

from __future__ import annotations

from .models import Report

GRADE_COLORS: dict[str, str] = {
    "A": "#16a34a", "B": "#16a34a",
    "C": "#ca8a04",
    "D": "#ef4444", "F": "#ef4444",
}


def compute_grade(report: Report) -> str:
    counts = report.counts()
    p1, p2 = counts["P1"], counts["P2"]
    has_secret = any(f.kind == "secret" for f in report.all_findings())
    if p1 > 3 or has_secret:
        return "F"
    if p1 >= 1:
        return "D"
    if p2 > 5:
        return "C"
    if p2 >= 1:
        return "B"
    return "A"

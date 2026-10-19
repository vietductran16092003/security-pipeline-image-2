"""So sánh báo cáo hiện tại với lần quét trước."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import PRIORITIES, Finding, Report, SECTION_IDS

COMPARABLE = {"clean", "findings"}


@dataclass
class Diff:
    first_scan: bool
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    deltas: dict[str, int] = field(default_factory=dict)
    not_compared: list[str] = field(default_factory=list)


def _status(report: Report, sid: str) -> Optional[str]:
    s = report.section(sid)
    return s.status if s else None


def _counts(findings: list[Finding]) -> dict[str, int]:
    out = {p: sum(1 for f in findings if f.priority == p) for p in PRIORITIES}
    out["total"] = len(findings)
    return out


def diff_reports(current: Report, previous: Optional[Report]) -> Diff:
    if previous is None:
        return Diff(first_scan=True)
    compared, not_compared = [], []
    for sid in SECTION_IDS:
        if _status(current, sid) in COMPARABLE and _status(previous, sid) in COMPARABLE:
            compared.append(sid)
        elif _status(current, sid) == _status(previous, sid) == "skipped":
            continue  # không áp dụng ở cả hai lần: không có gì để so sánh, không cần báo
        else:
            not_compared.append(sid)
    cur = [f for sid in compared for f in current.section(sid).findings]
    prev = [f for sid in compared for f in previous.section(sid).findings]
    cur_keys = {f.key() for f in cur}
    prev_keys = {f.key() for f in prev}
    c, p = _counts(cur), _counts(prev)
    return Diff(
        first_scan=False,
        new=[f for f in cur if f.key() not in prev_keys],
        fixed=[f for f in prev if f.key() not in cur_keys],
        deltas={k: c[k] - p[k] for k in c},
        not_compared=not_compared,
    )

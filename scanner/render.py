"""Render email HTML (mẫu Hướng 1) và Job Summary markdown."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .diff import Diff
from .grade import GRADE_COLORS, compute_grade
from .models import PRIORITIES, SECTION_IDS, SECTION_LABELS, Finding, Report

PRIORITY_ORDER = {p: i for i, p in enumerate(PRIORITIES)}
SEVERITY_ORDER = {s: i for i, s in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))}
PRIORITY_COLORS = {"P1": "#dc2626", "P2": "#d97706", "Backlog": "#64748b"}
VN_TZ = timezone(timedelta(hours=7))
SUMMARY_LIMIT = 200

# autoescape=True: mọi giá trị từ finding đều được escape (có test_html_escaped).
_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=True)  # nosemgrep


def top_findings(report: Report, n: int = 5) -> list[Finding]:
    return sorted(
        report.all_findings(),
        key=lambda f: (PRIORITY_ORDER.get(f.priority, 9), SEVERITY_ORDER.get(f.severity, 9), f.rule_id),
    )[:n]


def errored_sections(report: Report) -> list[str]:
    return [s.id for s in report.sections if s.status == "error"]


def render_subject(report: Report, diff: Diff) -> str:
    p1 = report.counts()["P1"]
    head = f"[{report.project}] {p1} lỗi P1" if p1 else f"[{report.project}] Không có lỗi P1"
    if diff.first_scan:
        subject = f"{head} · Lần quét đầu tiên"
    else:
        subject = f"{head} · +{len(diff.new)} mới, {len(diff.fixed)} đã sửa"
    errors = errored_sections(report)
    if errors:
        subject += f" · {len(errors)} phần quét lỗi"
    return subject


def _location(f: Finding) -> str:
    if f.kind == "vuln":
        return " · ".join(x for x in (f.package, f.installed_version) if x)
    if f.file and f.line is not None:
        return f"{f.file}:{f.line}"
    return f.file or ""


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone(VN_TZ).strftime("%H:%M, %d/%m/%Y")
    except ValueError:
        return iso


def _delta(d: int | None) -> tuple[str, str]:
    if d is None:
        return "", ""
    if d > 0:
        return f"▲ {d}", "#fca5a5"
    if d < 0:
        return f"▼ {-d}", "#86efac"
    return "không đổi", "#94a3b8"


def _section_rows(report: Report) -> list[dict]:
    rows = []
    for sid in SECTION_IDS:
        s = report.section(sid)
        status = s.status if s else "error"
        detail = (s.detail if s else "Không có kết quả") or ""
        if status == "clean":
            icon, color, text = "✔", "#047857", "Sạch"
        elif status == "findings":
            icon, color, text = "✖", "#dc2626", f"{len(s.findings)} finding"
        elif status == "skipped":
            icon, color, text = "–", "#64748b", "Không quét"
        else:
            icon, color, text = "!", "#b45309", "Lỗi"
        rows.append(dict(label=SECTION_LABELS[sid], icon=icon, color=color, text=text, detail=detail))
    return rows


def _context(report: Report, diff: Diff) -> dict:
    counts = report.counts()
    grade = compute_grade(report)
    new_keys = {f.key() for f in diff.new}
    p1 = counts["P1"]
    total = counts["total"]

    stats = []
    for key, label, color in (("P1", "P1", "#f87171"), ("P2", "P2", "#fbbf24"),
                              ("Backlog", "Backlog", "#ffffff"), ("total", "Tổng", "#ffffff")):
        text, dcolor = _delta(None if diff.first_scan else diff.deltas.get(key, 0))
        stats.append(dict(label=label, value=counts[key], color=color, delta=text, delta_color=dcolor))

    bar = []
    if total:
        for key, color in (("P1", "#dc2626"), ("P2", "#f59e0b"), ("Backlog", "#cbd5e1")):
            pct = round(counts[key] * 100 / total)
            if pct:
                bar.append(dict(pct=pct, color=color))

    urgent_new = sorted((f for f in diff.new if f.priority in ("P1", "P2")),
                        key=lambda f: (PRIORITY_ORDER[f.priority], SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
    if urgent_new:
        f = urgent_new[0]
        alert = dict(good=False, title="Lỗi mới nghiêm trọng nhất",
                     code=f.rule_id, text=_alert_text(f))
    elif diff.first_scan and p1:
        f = top_findings(report, 1)[0]
        alert = dict(good=False, title="Lỗi nghiêm trọng nhất", code=f.rule_id, text=_alert_text(f))
    elif errored_sections(report):
        names = ", ".join(SECTION_LABELS[s] for s in errored_sections(report))
        alert = dict(good=False, warn=True, title="Không quét được một số phần", code="",
                     text=f"Không quét được: {names}. Kết quả chưa đầy đủ, xem chi tiết ở cuối email.")
    elif diff.first_scan:
        alert = dict(good=True, title="Không có lỗi P1", code="", text="Chưa phát hiện lỗi cần xử lý ngay.")
    else:
        alert = dict(good=True, title="Không có lỗi mới mức P1/P2", code="",
                     text="Lần push này không thêm lỗi nghiêm trọng nào.")

    new_p = {p: sum(1 for f in diff.new if f.priority == p) for p in PRIORITIES}
    fixed_names = []
    for f in diff.fixed:
        name = f.package or f.file or f.rule_id
        if name not in fixed_names:
            fixed_names.append(name)
    fixed_text = ", ".join(fixed_names[:3])
    if len(diff.fixed) > 3:
        fixed_text += f" và {len(diff.fixed) - 3} lỗi khác"

    top = []
    for f in top_findings(report, 5):
        top.append(dict(
            priority=f.priority, color=PRIORITY_COLORS.get(f.priority, "#64748b"),
            rule_id=f.rule_id, is_new=f.key() in new_keys, meta=_location(f),
            is_vuln=f.kind == "vuln", fix=f.fixed_version or "chưa có bản vá", has_fix=bool(f.fixed_version),
        ))

    if p1:
        headline_em, headline_rest = f"{p1} lỗi P1", " cần xử lý ngay"
    else:
        headline_em, headline_rest = "", "Không có lỗi P1"
    new_p1 = new_p["P1"]
    lead = f"Commit {report.commit[:7]} · quét lúc {_when(report.scanned_at)}."
    if not diff.first_scan and new_p1:
        lead = f"Có {new_p1} lỗi P1 mới. " + lead
    errors = errored_sections(report)
    if errors:
        lead = f"Không quét được {len(errors)} phần, điểm chỉ là tạm tính. " + lead

    return dict(
        r=report, grade=grade, grade_color=GRADE_COLORS[grade], provisional=bool(errors), stats=stats, bar=bar, alert=alert,
        diff=diff, new_count=len(diff.new), fixed_count=len(diff.fixed),
        new_breakdown=" · ".join(f"{n} {p}" for p, n in new_p.items() if n) or "Không có",
        fixed_text=fixed_text or "Không có", top=top, total=total,
        sections=_section_rows(report), headline_em=headline_em, headline_rest=headline_rest, lead=lead,
        not_compared=", ".join(SECTION_LABELS[s] for s in diff.not_compared),
    )


def _alert_text(f: Finding) -> str:
    where = _location(f)
    text = f"{f.title} ({where})" if where and f.title != f.rule_id else (where or f.title)
    if f.kind == "vuln":
        text += f". Nâng lên {f.fixed_version}." if f.fixed_version else ". Chưa có bản vá."
    elif f.recommendation:
        text += f". {f.recommendation}."
    return text


def render_email(report: Report, diff: Diff) -> str:
    return _env.get_template("email.html.j2").render(**_context(report, diff))


def _md(text) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def render_summary(report: Report, diff: Diff) -> str:
    c = report.counts()
    grade = compute_grade(report)
    grade_label = f"Điểm tạm {grade}" if errored_sections(report) else f"Điểm {grade}"
    lines = [f"## Báo cáo bảo mật: {report.project}", "",
             f"**{grade_label}** · nhánh `{report.branch}` · commit `{report.commit[:7]}` · {_when(report.scanned_at)}", ""]
    if diff.first_scan:
        lines.append("Lần quét đầu tiên, chưa có dữ liệu để so sánh.")
    else:
        lines.append(f"So với lần trước: **+{len(diff.new)} mới**, **{len(diff.fixed)} đã sửa**.")
        if diff.not_compared:
            lines.append(f"Không so sánh được: {', '.join(SECTION_LABELS[s] for s in diff.not_compared)}.")
    lines += ["", "| P1 | P2 | Backlog | Tổng |", "|---|---|---|---|",
              f"| {c['P1']} | {c['P2']} | {c['Backlog']} | {c['total']} |", "",
              "### Các phần quét", "", "| Phần | Trạng thái | Ghi chú |", "|---|---|---|"]
    for row in _section_rows(report):
        lines.append(f"| {row['label']} | {row['icon']} {row['text']} | {_md(row['detail'])} |")
    if report.ignore_rules:
        lines += ["", f"Đang áp dụng {report.ignore_rules} quy tắc bỏ qua từ file ignore của dự án."]
    ordered = top_findings(report, len(report.all_findings()))
    if ordered:
        lines += ["", "### Finding", "", "| Mức | Mã | Vị trí | Bản vá | Khuyến nghị |", "|---|---|---|---|---|"]
        for f in ordered[:SUMMARY_LIMIT]:
            fix = (f.fixed_version or "chưa có bản vá") if f.kind == "vuln" else ""
            lines.append(f"| {f.priority} | {_md(f.rule_id)} | {_md(_location(f))} | {_md(fix)} | {_md(f.recommendation)} |")
        if len(ordered) > SUMMARY_LIMIT:
            lines += ["", f"… và {len(ordered) - SUMMARY_LIMIT} finding khác, xem `report.json` trong artifact `security-report`."]
    return "\n".join(lines) + "\n"

"""Báo cáo HTML cho "kiểm tra repo lạ": một file tự chứa (CSS nội tuyến, không script, không tài nguyên ngoài).

Mọi chuỗi đến từ repo hoặc từ kết quả (tên file, why, id, nguồn, lỗi) đều đi qua `clean()` (bỏ ký tự
điều khiển/bidi) rồi `html.escape`; repo lạ có thể đặt tên file là `<script>...</script>`.
"""
from __future__ import annotations

from html import escape

from .sandbox import VetOutcome, clean
from .verdict import Verdict

MAX_SIGNALS = 200

_LEVEL_ORDER = ("high", "medium", "low", "info")
_GROUP_TITLE = {
    "high": "Dấu hiệu nghiêm trọng",
    "medium": "Dấu hiệu đáng chú ý",
    "low": "Dấu hiệu nhẹ",
    "info": "Ghi chú",
}
_LEVEL_LABEL = {"high": "cao", "medium": "trung bình", "low": "thấp", "info": "ghi chú"}

_VERDICT_STYLE = {
    Verdict.NOT_SAFE: ("#b42318", "#fee4e2",
                       "Đừng tải hoặc mở repo này. Đã thấy dấu hiệu rất đáng lo, xem lý do bên dưới."),
    Verdict.SUSPICIOUS: ("#b54708", "#fef0c7",
                         "Chỉ mở nếu bạn hiểu rõ repo này. Có dấu hiệu cần xem kỹ hoặc kiểm tra chưa đầy đủ."),
    Verdict.SAFER: ("#067647", "#dcfae6",
                    "Chưa thấy dấu hiệu xấu, nhưng đây KHÔNG phải bảo đảm repo sạch."),
}

LIMITS_NOTE = ("Lưu ý về giới hạn: kiểm tra này chỉ giúp giảm rủi ro, không chứng minh repo sạch. "
               "Công cụ chỉ đọc file tĩnh trong môi trường cô lập, không chạy mã của repo, "
               "nên có thể bỏ sót mã độc được che giấu kỹ.")

_CSS = """
body{margin:0;background:#f4f5f7;color:#1d2939;font:16px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:16px}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:16px;margin:0 0 16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 8px}
.src{color:#475467;word-break:break-all;margin:0 0 12px}
.badge{display:block;border-radius:10px;padding:14px 16px;font-size:24px;font-weight:700}
.badge small{display:block;font-size:15px;font-weight:400;margin-top:4px}
ul{margin:0;padding-left:20px}li{margin:0 0 8px;word-break:break-word}
code{background:#f2f4f7;border-radius:4px;padding:0 4px;word-break:break-all}
.lv{font-size:12px;color:#475467}.note{color:#475467;font-size:14px}
"""


def _t(value, limit: int = 300) -> str:
    return escape(clean(value, limit), quote=True)


def _page(body: str) -> str:
    return ("<!DOCTYPE html>\n<html lang=\"vi\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Kiểm tra repo lạ</title>"
            f"<style>{_CSS}</style></head><body><div class=\"wrap\">{body}</div></body></html>\n")


def _limits() -> str:
    return f"<div class=\"card note\"><p style=\"margin:0\">{escape(LIMITS_NOTE)}</p></div>"


def _source_line(outcome: VetOutcome) -> str:
    src = outcome.source
    return f"<p class=\"src\">Repo: <code>{_t(src.display, 400)}</code></p>" if src is not None else ""


def _render_no_verdict(outcome: VetOutcome) -> str:
    reason = outcome.fetch_error or "Không rõ nguyên nhân."
    errors = "".join(f"<li>{_t(e)}</li>" for e in outcome.tool_errors)
    body = (
        "<div class=\"card\"><h1>Kiểm tra repo lạ</h1>" + _source_line(outcome) +
        "<div class=\"badge\" style=\"background:#eaecf0;color:#344054\">Không kiểm tra được"
        "<small>Chưa có kết luận nào về repo này. Đừng xem việc không có kết quả là dấu hiệu tốt.</small></div></div>"
        f"<div class=\"card\"><h2>Lý do</h2><p style=\"margin:0\">{_t(reason, 600)}</p>"
        + (f"<ul>{errors}</ul>" if errors else "") + "</div>"
        + _limits())
    return _page(body)


def _signal_li(s) -> str:
    level = str(getattr(s, "level", "")).strip().lower()
    where = _t(s.file, 300)
    if s.line is not None:
        where += f":{int(s.line)}"
    return (f"<li><code>{_t(s.id, 80)}</code> <span class=\"lv\">mức {escape(_LEVEL_LABEL.get(level, 'khác'))}</span>"
            f"<br><code>{where}</code><br>{_t(s.why, 300)}</li>")


def _render_signals(outcome: VetOutcome) -> str:
    sigs = list(outcome.result.signals) if outcome.result else []
    groups: dict[str, list] = {lv: [] for lv in _LEVEL_ORDER}
    for s in sigs:
        lv = str(s.level).strip().lower()
        groups[lv if lv in groups else "medium"].append(s)
    ordered = [(lv, s) for lv in _LEVEL_ORDER for s in groups[lv]]
    shown, extra = ordered[:MAX_SIGNALS], max(0, len(ordered) - MAX_SIGNALS)
    out = []
    for lv in _LEVEL_ORDER:
        items = [_signal_li(s) for l, s in shown if l == lv]
        if items:
            out.append(f"<div class=\"card\"><h2>{escape(_GROUP_TITLE[lv])} ({len(groups[lv])})</h2>"
                       f"<ul>{''.join(items)}</ul></div>")
    if extra:
        out.append(f"<div class=\"card note\">… còn {extra} tín hiệu nữa (không hiển thị hết).</div>")
    if not sigs:
        out.append("<div class=\"card note\">Không có tín hiệu nào được ghi nhận.</div>")
    return "".join(out)


def _render_incomplete(outcome: VetOutcome) -> str:
    notes = []
    if outcome.result:
        notes += [clean(i, 300) for i in outcome.result.incomplete]
    notes += [clean(e, 300) for e in outcome.tool_errors]
    if outcome.truncated:
        notes.append("Repo quá lớn, chỉ kiểm tra được một phần.")
    if not notes:
        return ""
    lis = "".join(f"<li>{escape(n)}</li>" for n in notes)
    return f"<div class=\"card\"><h2>Kiểm tra chưa đầy đủ vì…</h2><ul>{lis}</ul></div>"


def render_vet_html(outcome: VetOutcome) -> str:
    if outcome.verdict is None:
        return _render_no_verdict(outcome)
    color, bg, sentence = _VERDICT_STYLE[Verdict(outcome.verdict)]
    head = (f"<div class=\"card\"><h1>Kiểm tra repo lạ</h1>{_source_line(outcome)}"
            f"<div class=\"badge\" style=\"background:{bg};color:{color}\">{escape(Verdict(outcome.verdict).value)}"
            f"<small>{escape(sentence)}</small></div></div>")
    return _page(head + _render_incomplete(outcome) + _render_signals(outcome) + _limits())

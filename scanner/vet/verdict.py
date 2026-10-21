"""Quy tắc ba mức (spec 8b.2). Chỉ stdlib, không import nặng."""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    NOT_SAFE = "Không nên mở"
    SUSPICIOUS = "Đáng ngờ"
    SAFER = "An toàn hơn"


def decide(result, fetch_error: str | None = None, truncated: bool = False,
           tool_errors: list[str] | None = None) -> Verdict | None:
    """None khi không kiểm tra được gì. `info` không ảnh hưởng mức.
    SAFER chỉ khi có kết quả, sạch và đầy đủ."""
    if result is None:
        return None
    # "HIGH" == "high"; mức lạ (None, "", "critical") không phải info -> SUSPICIOUS.
    levels = {str(s.level).strip().lower() for s in result.signals}
    if "high" in levels:
        return Verdict.NOT_SAFE
    degraded = bool(fetch_error or truncated or tool_errors or result.incomplete)
    if degraded or levels - {"info"}:
        return Verdict.SUSPICIOUS
    return Verdict.SAFER

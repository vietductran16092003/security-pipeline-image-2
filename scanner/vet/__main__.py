"""Điểm vào chạy trong container: python -m scanner.vet <root> --osv <path> --out <vet.json>.

Chỉ import stdlib + scanner.vet.signals (image không có pip deps). Luôn ghi JSON hợp lệ;
lỗi nội bộ được ghi vào `incomplete` (không bao giờ tạo vẻ "sạch" khi phân tích hỏng).
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .signals import ScanResult, analyze_tree


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanner.vet")
    ap.add_argument("root")
    ap.add_argument("--osv")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-file-bytes", type=int, default=2_000_000)
    ap.add_argument("--deadline", type=float, default=300)
    a = ap.parse_args(argv)

    osv = None
    if a.osv:
        try:
            osv = json.loads(Path(a.osv).read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(osv, dict):
                osv = {"error": "định dạng OSV không hợp lệ"}
        except (OSError, ValueError):
            osv = {"error": "không đọc được kết quả tra cứu OSV"}

    code = 0
    root = Path(a.root)
    if not root.is_dir():
        result = ScanResult([], ["Không tìm thấy thư mục repo để phân tích"])
        code = 2
    else:
        try:
            result = analyze_tree(root, osv=osv, max_file_bytes=a.max_file_bytes, deadline=a.deadline)
        except Exception as e:  # noqa: BLE001
            result = ScanResult([], [f"Bộ phân tích gặp lỗi nội bộ ({type(e).__name__})"])
            code = 3
    return _write(Path(a.out), result, code)


def _write(out: Path, result: ScanResult, code: int) -> int:
    """Luôn để lại vet.json hợp lệ: nếu ghi/serialize lỗi, ghi bản tối giản kèm ghi chú incomplete."""
    try:
        text = json.dumps(dataclasses.asdict(result), ensure_ascii=False, indent=2)
        out.write_text(text, encoding="utf-8")
        return code
    except Exception as e:  # noqa: BLE001
        note = f"lỗi ghi kết quả ({type(e).__name__}), một phần kết quả có thể thiếu"
    sigs = []
    for s in result.signals:
        try:
            d = dataclasses.asdict(s)
            json.dumps(d, ensure_ascii=False).encode("utf-8")
            sigs.append(d)
        except Exception:  # noqa: BLE001
            continue
    for payload in ({"signals": sigs, "incomplete": [note]}, {"signals": [], "incomplete": [note]}):
        try:
            out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            return code or 4
        except Exception:  # noqa: BLE001
            continue
    out.write_text('{"signals": [], "incomplete": ["lỗi ghi kết quả"]}', encoding="utf-8")
    return code or 4


if __name__ == "__main__":
    sys.exit(main())

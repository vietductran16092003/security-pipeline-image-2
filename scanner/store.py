"""Kho lịch sử quét trên máy: mỗi dự án một thư mục, mỗi lần quét một thư mục con theo giờ."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import unicodedata
from datetime import datetime
from pathlib import Path

_STAMP = "%Y%m%d-%H%M%S"


def slug_for(path: Path) -> str:
    """Tên thư mục an toàn từ đường dẫn; thêm 8 ký tự băm để hai đường dẫn khác nhau không trùng."""
    norm = os.path.normcase(os.path.normpath(str(path)))
    digest = hashlib.sha256(norm.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    name = Path(norm).name or "root"
    name = name.replace("đ", "d").replace("Đ", "d")
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c)).lower()
    name = re.sub(r"[^a-z0-9]+", "-", name).strip("-") or "project"
    return f"{name[:40].strip('-') or 'project'}-{digest}"


def store_root() -> Path:
    override = os.environ.get("SCAN_STORE")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "security-scan"


def new_run_dir(slug: str, now: datetime | None = None) -> Path:
    stamp = (now or datetime.now()).strftime(_STAMP)
    d = store_root() / slug / stamp
    d.mkdir(parents=True, exist_ok=True)
    return d


def _runs(slug: str) -> list[Path]:
    base = store_root() / slug
    if not base.is_dir():
        return []
    return sorted((d for d in base.iterdir() if d.is_dir()), key=lambda d: d.name)


def latest_report(slug: str) -> Path | None:
    for d in reversed(_runs(slug)):
        f = d / "report.json"
        if f.is_file():
            return f
    return None


def prune(slug: str, keep: int = 20) -> None:
    runs = _runs(slug)
    for d in runs[: max(0, len(runs) - keep)]:
        shutil.rmtree(d, ignore_errors=True)

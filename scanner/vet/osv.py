"""Tra cứu gói độc hại trên OSV (chỉ giữ id `MAL-`).

Hai nửa, chạy ở hai nơi khác nhau:
- `extract_packages` / `main(["list", root])`: chạy TRONG container không mạng, đọc
  package-lock.json của repo lạ và in danh sách (ecosystem, tên, phiên bản) ra stdout.
- `lookup_osv`: chạy ở tiến trình điều khiển (có mạng), chỉ nhận bộ ba đã kiểm tra regex,
  gọi https://api.osv.dev/v1/querybatch qua `http` được tiêm vào (test dùng bản giả).
- `main(["write", path, json])`: chạy trong container để ghi osv.json vào volume kết quả.

Chỉ stdlib + scanner.vet.signals (image phân tích không cài thêm gì).
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Callable

OSV_URL = "https://api.osv.dev/v1/querybatch"
BATCH = 1000
MAX_PACKAGES = 5000
MAX_LOCKFILES = 50
MAX_LOCK_BYTES = 20_000_000
HTTP_TIMEOUT = 30

_NPM_NAME = re.compile(r"(@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9._~-][a-z0-9._~-]{0,213}", re.I)
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
_ID = re.compile(r"[^A-Za-z0-9._-]")

Http = Callable[[str, bytes], bytes]


def default_http(url: str, body: bytes) -> bytes:
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310 (URL cố định https)
        return resp.read(50_000_000)


def valid_packages_counted(packages) -> tuple[list[tuple[str, str, str]], int]:
    """Như valid_packages nhưng đếm số mục bị bỏ (sai định dạng/regex/phiên bản lạ; trùng thì không tính).
    Lockfile của hệ sinh thái khác npm không bao giờ được liệt kê (ngoài phạm vi), nên không nằm ở đây."""
    out, seen, dropped = [], set(), 0
    for item in packages or []:
        ok = isinstance(item, (list, tuple)) and len(item) == 3
        if ok:
            eco, name, ver = item
            ok = (eco == "npm" and isinstance(name, str) and isinstance(ver, str)
                  and _NPM_NAME.fullmatch(name) is not None and _VERSION.fullmatch(ver) is not None)
        if not ok:
            dropped += 1
            continue
        key = (eco, name, ver)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out, dropped


def valid_packages(packages) -> list[tuple[str, str, str]]:
    """Giữ bộ ba hợp lệ (chỉ npm), bỏ trùng, giới hạn số lượng."""
    out, seen = [], set()
    for item in packages or []:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            continue
        eco, name, ver = item
        if eco != "npm" or not isinstance(name, str) or not isinstance(ver, str):
            continue
        if not _NPM_NAME.fullmatch(name) or not _VERSION.fullmatch(ver):
            continue
        key = (eco, name, ver)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def lookup_osv(packages: list[tuple[str, str, str]], http: Http = default_http) -> dict:
    """-> {"malicious": [{ecosystem,name,version,id}], "error"?: str}. Lỗi mạng KHÔNG im lặng."""
    pk = valid_packages(packages)
    result: dict = {"malicious": []}
    errors: list[str] = []
    if len(pk) > MAX_PACKAGES:
        errors.append(f"chỉ tra cứu {MAX_PACKAGES}/{len(pk)} gói")
        pk = pk[:MAX_PACKAGES]
    for start in range(0, len(pk), BATCH):
        chunk = pk[start:start + BATCH]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                       for e, n, v in chunk]}).encode()
        try:
            data = json.loads(http(OSV_URL, body))
            results = data["results"]
            if not isinstance(results, list) or len(results) != len(chunk):
                raise ValueError("số kết quả không khớp")
        except Exception as e:  # noqa: BLE001 - mọi lỗi đều thành "không đầy đủ"
            errors.append(f"không tra cứu được OSV ({type(e).__name__})")
            break
        for (eco, name, ver), r in zip(chunk, results):
            vulns = r.get("vulns") if isinstance(r, dict) else None
            for v in vulns if isinstance(vulns, list) else []:
                vid = _ID.sub("", str(v.get("id", "")) if isinstance(v, dict) else "")[:40]
                if vid.startswith("MAL-"):
                    result["malicious"].append({"ecosystem": eco, "name": name, "version": ver, "id": vid})
    if errors:
        result["error"] = "; ".join(errors)
    return result


def extract_packages(root: Path) -> list[tuple[str, str, str]]:
    """Đọc mọi package-lock.json (không theo symlink, bỏ .git/node_modules)."""
    from .signals import _Scan, _scan_package_lock

    sc = _Scan(None)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
        if "package-lock.json" not in filenames:
            continue
        full = os.path.join(dirpath, "package-lock.json")
        if os.path.islink(full) or not os.path.isfile(full) or os.path.getsize(full) > MAX_LOCK_BYTES:
            continue
        count += 1
        if count > MAX_LOCKFILES:
            break
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        _scan_package_lock(sc, os.path.relpath(full, root), text)
    return valid_packages([(d.eco, d.name, d.spec) for d in sc.deps])


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "list":
        print(json.dumps([list(t) for t in extract_packages(Path(argv[1]))]))
        return 0
    if len(argv) == 3 and argv[0] == "write":
        data = json.loads(argv[2])
        Path(argv[1]).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return 0
    print("cách dùng: python -m scanner.vet.osv list <root> | write <path> <json>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

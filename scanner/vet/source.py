"""Cổng kiểm tra nguồn repo: chỉ chấp nhận danh sách trắng nghiêm ngặt.

LƯU Ý: kiểm tra DNS ở đây chỉ mang tính THAM KHẢO (advisory): `git clone` sẽ phân
giải lại tên miền (DNS rebinding/TOCTOU). Biện pháp thật là chặn mạng tới dải
riêng ở tầng sandbox (Task 10). Host IDN phải được nhập dạng punycode (xn--).

Kết quả (`Source.clone_url`) sẽ được đưa cho `git clone` trong container, nên
không bao giờ ghép chuỗi người dùng nhập vào shell; mọi thành phần đều được
kiểm bằng regex chặt và host được kiểm tra không trỏ về IP nội bộ.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit


class InvalidSource(ValueError):
    """Nguồn repo không hợp lệ hoặc không an toàn."""


@dataclass(frozen=True)
class Source:
    host: str
    path: str
    branch: str | None
    clone_url: str
    display: str


_ALLOWED_CHARS = re.compile(r"[A-Za-z0-9._/:@~-]+")
_SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}")
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
_MAX_SEGMENTS = 10
_V6_OK = [ipaddress.ip_network("2000::/3")]
_V6_BAD = [ipaddress.ip_network(n) for n in (
    "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:db8::/32")]


def _default_resolver(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)]


def _bad(msg: str) -> InvalidSource:
    return InvalidSource(msg)


def _check_host(host: str) -> None:
    if not host or len(host) > 253 or host != host.lower():
        raise _bad("Tên máy chủ không hợp lệ.")
    labels = host.split(".")
    if len(labels) < 2 or host == "localhost" or host.endswith(".localhost"):
        raise _bad("Không chấp nhận máy chủ nội bộ hoặc không có tên miền đầy đủ.")
    if not all(_LABEL.fullmatch(lb) for lb in labels):
        raise _bad("Tên máy chủ chứa ký tự không hợp lệ.")
    # Phần cuối phải là TLD chữ cái: loại 127.1, 2130706433, 0x7f.1, 0177.0.0.1...
    if not _TLD.fullmatch(labels[-1]):
        raise _bad("Không chấp nhận địa chỉ IP hoặc dạng số làm máy chủ.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise _bad("Không chấp nhận địa chỉ IP làm máy chủ.")


def _check_resolution(host: str, resolver: Callable[[str], list[str]]) -> None:
    # Advisory only (xem docstring): git clone sẽ phân giải lại.
    try:
        addrs = list(resolver(host))
    except Exception:
        raise _bad(f"Không phân giải được máy chủ {host}.") from None
    if not addrs:
        raise _bad(f"Không phân giải được máy chủ {host}.")
    for raw in addrs:
        try:
            ip = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError:
            raise _bad(f"Máy chủ {host} trả về địa chỉ không hợp lệ.") from None
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            elif not any(ip in n for n in _V6_OK) or any(ip in n for n in _V6_BAD):
                raise _bad(f"Máy chủ {host} trỏ về địa chỉ IPv6 không được phép.")
        if not ip.is_global or ip.is_multicast:
            raise _bad(f"Máy chủ {host} trỏ về địa chỉ nội bộ, không được phép.")


def parse_source(text: str, resolver: Callable[[str], list[str]] | None = None) -> Source:
    if not isinstance(text, str) or not text:
        raise _bad("Nguồn repo đang trống.")
    if not _ALLOWED_CHARS.fullmatch(text):
        raise _bad("Nguồn repo chứa khoảng trắng, ký tự điều khiển hoặc ký tự không được phép.")
    if text.startswith("-"):
        raise _bad("Nguồn repo không được bắt đầu bằng dấu '-'.")
    resolver = resolver or _default_resolver

    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme.lower() != "https":
            raise _bad("Chỉ chấp nhận https.")
        if parts.query or parts.fragment or "?" in text or "#" in text:
            raise _bad("URL không được chứa query hoặc fragment.")
        netloc = parts.netloc
        if "@" in netloc:
            raise _bad("URL không được chứa tên người dùng/mật khẩu.")
        if ":" in netloc or "[" in netloc:
            raise _bad("Không chấp nhận cổng tuỳ chỉnh hoặc địa chỉ IPv6.")
        host, rest = netloc.lower(), parts.path
        if not rest.startswith("/"):
            raise _bad("URL thiếu đường dẫn repo.")
        rest = rest[1:]
    else:
        if ":" in text:
            raise _bad("Dạng nguồn không được hỗ trợ (không dùng scp/ssh).")
        first = text.split("/", 1)[0]
        if "." in first:
            host, _, rest = text.partition("/")
            host = host.lower()
        else:
            host, rest = "github.com", text

    path_part, sep, branch = rest.partition("@")
    branch_val: str | None = None
    if sep:
        if not _BRANCH.fullmatch(branch) or ".." in branch or "//" in branch \
                or branch.endswith(("/", ".", ".lock")) or "@" in branch \
                or "/." in branch or "/-" in branch:
            raise _bad("Tên nhánh không hợp lệ.")
        branch_val = branch
    path_part = path_part.removesuffix("/")
    if path_part.endswith(".git"):
        path_part = path_part[:-4]
    segs = path_part.split("/")
    if len(segs) < 2 or len(segs) > _MAX_SEGMENTS:
        raise _bad("Đường dẫn repo phải có dạng chủ-sở-hữu/repo.")
    if host == "github.com" and len(segs) != 2:
        raise _bad("Repo GitHub phải có dạng owner/repo.")
    for s in segs:
        if s in (".", "..") or not _SEGMENT.fullmatch(s) or s.endswith(".git"):
            raise _bad("Đường dẫn repo chứa phần không hợp lệ.")

    _check_host(host)
    _check_resolution(host, resolver)

    path = "/".join(segs)
    display = f"{host}/{path}" + (f"@{branch_val}" if branch_val else "")
    return Source(host=host, path=path, branch=branch_val,
                  clone_url=f"https://{host}/{path}.git", display=display)

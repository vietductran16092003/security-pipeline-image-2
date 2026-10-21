"""Mẫu nhận diện cho bộ phát hiện dấu hiệu (chỉ stdlib, không import gì của repo lạ).

Mọi regex ở đây tránh lặp lồng nhau (chống ReDoS) và được áp lên dòng đã cắt độ dài.
"""
from __future__ import annotations

import re

I = re.IGNORECASE

DOC_EXTS = {".md", ".markdown", ".rst", ".txt", ".adoc"}
CODE_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh", ".ps1",
    ".psm1", ".bat", ".cmd", ".rb", ".go", ".php", ".pl", ".java", ".cs", ".vbs", ".lua",
    ".rs", ".swift", ".kt", "",
}
SOFT_NAMES = {"dockerfile", "makefile", "gnumakefile"}  # curl|sh ở đây hay gặp hơn: chỉ medium
SOFT_EXTS = {".yml", ".yaml", ".dockerfile", ".mk", ".toml", ".json", ".cfg", ".ini", ".gradle"}

EXE_MEDIUM_EXTS = {".exe", ".dll", ".scr"}
EXE_LOW_EXTS = {".jar", ".bat"}

# Mạng: tải/gửi dữ liệu.
NET_CMD_RE = re.compile(
    r"\b(curl|wget|iwr|irm|certutil|bitsadmin|powershell|pwsh)\b|invoke-webrequest"
    r"|invoke-restmethod|node\s+(-e|--eval)\b|/dev/tcp/|\bnc\s+-", I)
NET_RE = re.compile(NET_CMD_RE.pattern + r"|https?://", I)

PIPE_RES = [
    re.compile(
        r"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,400}\|\s*"
        r"(sudo\s+)?(sh|bash|zsh|dash|python3?|node|perl|ruby|iex|invoke-expression|powershell|pwsh)\b", I),
    re.compile(
        r"\b(iex|invoke-expression)\b[^\n]{0,120}(downloadstring|net\.webclient|\biwr\b|\birm\b"
        r"|invoke-webrequest|invoke-restmethod)", I),
    re.compile(r"\b(sh|bash)\s+-c\s+[\"']?\$\(\s*(curl|wget)\b", I),
    re.compile(r"\b(sh|bash)\s+<\(\s*(curl|wget)\b", I),
]

PS_ENC_RE = re.compile(
    r"\b(powershell|pwsh)(\.exe)?\b[^\n]{0,200}?\s-(e|ec|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", I)
DECODE_RE = re.compile(
    r"b64decode|\batob\s*\(|base64|fromhex|unhexlify|FromBase64String"
    r"|(\\x[0-9a-fA-F]{2}){8,}|codecs\.decode|String\.fromCharCode", I)
EXEC_RE = re.compile(r"(?<![.\w])(eval|exec|execfile|Function)\s*\(")
IEX_RE = re.compile(r"\b(iex|invoke-expression)\b", I)

CRED_RES = [
    re.compile(
        r"(~|\$HOME|\$\{HOME\}|%USERPROFILE%|%APPDATA%|%LOCALAPPDATA%|expanduser|homedir|Path\.home"
        r"|USERPROFILE|user_home)[^\n]{0,120}?(\.ssh|\.aws|\.gnupg|\.npmrc|\.pypirc|\.netrc"
        r"|\.git-credentials|\.docker[/\\]config|\.kube[/\\]config|\.env\b|Login Data|Cookies"
        r"|Local State|wallet|keychain)", I),
    re.compile(
        r"id_rsa|id_ed25519|id_ecdsa|\.ssh[/\\]|\.aws[/\\]credentials|Login Data|wallet\.dat"
        r"|Local Storage[/\\]leveldb|google-chrome|User Data[/\\]Default|MetaMask"
        r"|nkbihfbeogaeaoehlefnkodbefgpgknn", I),
    re.compile(r"json\.dumps\(\s*(dict\()?os\.environ|JSON\.stringify\(\s*process\.env|dict\(os\.environ\)"),
]
EXFIL_RE = re.compile(
    r"requests\.(post|put|patch|request)\b|urlopen\s*\(|http\.client|\bfetch\s*\(|axios\.(post|put)"
    r"|XMLHttpRequest|https?\.request\s*\(|\bcurl\b|\bwget\b|invoke-webrequest|invoke-restmethod"
    r"|\biwr\b|net\.webclient|socket\.(connect|create_connection)|net\.connect|Net::HTTP", I)
WEBHOOK_RE = re.compile(
    r"discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot|webhook\.site/|canary\.discord\.com/api/webhooks/", I)

DEVCONTAINER_KEYS = ("initializeCommand", "onCreateCommand", "updateContentCommand",
                     "postCreateCommand", "postStartCommand", "postAttachCommand")
INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall", "prepare")

# ~50 gói phổ biến (chỉ tên >= 5 ký tự dùng để so; tên ngắn gây báo nhầm).
POPULAR = {
    "npm": [
        "express", "react", "lodash", "axios", "webpack", "typescript", "moment", "chalk",
        "commander", "request", "async", "underscore", "jquery", "bluebird", "debug", "colors",
        "eslint", "prettier", "mongoose", "passport", "nodemon", "dotenv", "jsonwebtoken",
        "bcrypt", "react-dom", "cross-env", "socket.io", "babel-core", "angular", "vue",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "django", "flask", "urllib3", "setuptools", "boto3",
        "pytest", "pyyaml", "cryptography", "beautifulsoup4", "scipy", "matplotlib",
        "tensorflow", "pillow", "sqlalchemy", "jinja2", "colorama", "certifi", "selenium",
        "paramiko", "tqdm", "click", "psycopg2", "python-dateutil", "protobuf", "cffi",
        "pydantic", "fastapi",
    ],
}
KNOWN_LEGIT_NEIGHBORS = {"scapy", "panda", "reactor", "colour"}


def within_one(a: str, b: str) -> bool:
    """Khoảng cách sửa (chèn/xoá/thay) bằng đúng 1."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    if la == lb:
        return a[i + 1:] == b[i + 1:]
    return a[i:] == b[i + 1:]


def norm_name(eco: str, name: str) -> str:
    n = name.strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def typosquat_target(eco: str, name: str) -> str | None:
    n = norm_name(eco, name)
    if len(n) < 4 or n.startswith("@"):
        return None
    popular = {norm_name(eco, p) for p in POPULAR.get(eco, [])}
    if n in popular or n in KNOWN_LEGIT_NEIGHBORS:
        return None
    for p in sorted(popular):
        if len(p) >= 5 and within_one(n, p):
            return p
    return None

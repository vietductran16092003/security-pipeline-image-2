"""Nhận biết dự án có gì để quyết định chạy phần quét nào."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import SECTION_IDS

MANIFEST_PATTERNS = (
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "go.mod", "pom.xml", "build.gradle", "*.csproj", "packages.lock.json",
    "Gemfile.lock", "Cargo.lock", "composer.lock",
)
SKIP_DIRS = {".git", "node_modules", ".venv", "vendor", ".scanner"}

SKIP_REASONS = {
    "deps": "Không tìm thấy file khai báo thư viện",
    "image": "Không có Dockerfile ở thư mục gốc",
    "dockerfile_policy": "Không có Dockerfile ở thư mục gốc",
    "iac": "Không có file Terraform/Kubernetes/Helm",
}


@dataclass
class Profile:
    deps_files: list[str] = field(default_factory=list)
    dockerfile: Optional[str] = None
    iac_files: list[str] = field(default_factory=list)


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            yield full.relative_to(root).as_posix(), name, full


def _is_k8s_yaml(path: Path) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return "apiVersion:" in head and "kind:" in head


def detect_project(root: Path) -> Profile:
    root = Path(root)
    profile = Profile()
    if (root / "Dockerfile").is_file():
        profile.dockerfile = "Dockerfile"
    for rel, name, full in _walk(root):
        if any(fnmatch.fnmatch(name, pat) for pat in MANIFEST_PATTERNS):
            profile.deps_files.append(rel)
        if name.endswith(".tf") or name == "Chart.yaml":
            profile.iac_files.append(rel)
        elif name.endswith((".yaml", ".yml")) and _is_k8s_yaml(full):
            profile.iac_files.append(rel)
    return profile


def plan_sections(p: Profile) -> dict[str, Optional[str]]:
    run = {
        "secrets": True,
        "code": True,
        "deps": bool(p.deps_files),
        "image": p.dockerfile is not None,
        "dockerfile_policy": p.dockerfile is not None,
        "iac": bool(p.iac_files),
    }
    return {sid: (None if run[sid] else SKIP_REASONS[sid]) for sid in SECTION_IDS}

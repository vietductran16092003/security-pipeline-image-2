"""Mô hình dữ liệu chung: Finding, Section, Report."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

SCHEMA_VERSION = 1

SECTION_IDS: tuple[str, ...] = ("secrets", "code", "deps", "image", "dockerfile_policy", "iac")

SECTION_LABELS: dict[str, str] = {
    "secrets": "Secret (Gitleaks)",
    "code": "Code (Semgrep)",
    "deps": "Thư viện (Trivy)",
    "image": "Docker image (Trivy)",
    "dockerfile_policy": "Dockerfile policy (Conftest)",
    "iac": "Cấu hình IaC (Trivy)",
}

PRIORITIES: tuple[str, ...] = ("P1", "P2", "Backlog")


@dataclass
class Finding:
    tool: str
    kind: str  # vuln | secret | code | policy | config
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    title: str
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    base_os_eol: bool = False
    priority: Optional[str] = None
    reason: Optional[str] = None
    recommendation: Optional[str] = None

    def key(self) -> str:
        return f"{self.tool}:{self.rule_id}:{self.package or self.file or ''}"


@dataclass
class Section:
    id: str
    status: str  # clean | findings | skipped | error
    detail: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Report:
    project: str
    branch: str
    commit: str
    run_id: str
    run_url: str
    scanned_at: str
    sections: list[Section]
    ignore_rules: int = 0
    schema_version: int = SCHEMA_VERSION

    def all_findings(self) -> list[Finding]:
        return [f for s in self.sections for f in s.findings]

    def counts(self) -> dict[str, int]:
        found = self.all_findings()
        out = {p: sum(1 for f in found if f.priority == p) for p in PRIORITIES}
        out["total"] = len(found)
        return out

    def section(self, section_id: str) -> Optional[Section]:
        return next((s for s in self.sections if s.id == section_id), None)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Report":
        try:
            data = json.loads(text)
            if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
                raise ValueError("schema_version không hợp lệ")
            sections = [
                Section(id=s["id"], status=s["status"], detail=s.get("detail"),
                        findings=[Finding(**f) for f in s.get("findings", [])])
                for s in data["sections"]
            ]
            fields = {k: v for k, v in data.items() if k != "sections"}
            return cls(sections=sections, **fields)
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"Báo cáo không đọc được: {exc}") from exc

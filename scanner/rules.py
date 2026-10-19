"""Rule Engine: gán priority/reason/recommendation cho từng finding theo rules.yaml."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import yaml

from .models import PRIORITIES, Finding


def load_rules(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def apply_rules(findings: list[Finding], rules: list[dict]) -> None:
    """Rule khớp đầu tiên thắng. `when` được eval với namespace không có builtins;
    rules.yaml nằm trong repo bộ quét nên không phải input từ dự án bị quét."""
    for rule in rules:
        if rule.get("priority") not in PRIORITIES:
            raise ValueError(f"Rule {rule.get('name')!r} có priority không hợp lệ: {rule.get('priority')!r}")
    safe_globals = {"__builtins__": {}}
    for f in findings:
        for rule in rules:
            try:
                matched = eval(rule["when"], safe_globals, asdict(f))  # noqa: S307
            except Exception:
                matched = False
            if matched:
                f.priority = rule["priority"]
                f.reason = rule["reason"]
                f.recommendation = rule["recommendation"]
                break
        else:
            raise ValueError(f"Không rule nào khớp finding {f.key()}")

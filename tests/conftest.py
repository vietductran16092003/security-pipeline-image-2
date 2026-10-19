import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.models import Finding, Report, Section, SECTION_IDS  # noqa: E402


def make_report(findings, sections=None, project="my-api", **kw):
    """Report với Section `deps` chứa `findings`; các phần khác là clean."""
    if sections is None:
        sections = [
            Section(sid, "findings" if (sid == "deps" and findings) else "clean",
                    findings=list(findings) if sid == "deps" else [])
            for sid in SECTION_IDS
        ]
    base = dict(project=project, branch="main", commit="a1b2c3d4e5", run_id="128",
                run_url="https://github.com/o/r/actions/runs/128",
                scanned_at="2026-10-19T09:42:00+00:00", sections=sections)
    base.update(kw)
    return Report(**base)


def vuln(rule_id="CVE-1", priority="P1", severity="HIGH", package="openssl", fixed="1.2", **kw):
    return Finding("trivy", "vuln", rule_id, severity, rule_id, package=package,
                   installed_version="1.0", fixed_version=fixed, priority=priority, **kw)

"""Chuyển output JSON của từng công cụ thành danh sách Finding."""

from __future__ import annotations

from .models import Finding

SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _severity(value) -> str:
    value = (value or "").upper()
    return value if value in KNOWN_SEVERITIES else "UNKNOWN"


def parse_trivy(raw: dict) -> list[Finding]:
    raw = raw or {}
    os_info = (raw.get("Metadata") or {}).get("OS") or {}
    eol = bool(os_info.get("EOSL"))
    found: list[Finding] = []
    for result in raw.get("Results") or []:
        target = result.get("Target") or ""
        for v in result.get("Vulnerabilities") or []:
            found.append(Finding(
                tool="trivy", kind="vuln",
                rule_id=v.get("VulnerabilityID") or "UNKNOWN",
                severity=_severity(v.get("Severity")),
                title=v.get("Title") or v.get("VulnerabilityID") or "",
                package=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion") or None,
                file=v.get("PkgPath") or target or None,
                base_os_eol=eol,
            ))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") and m.get("Status") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            found.append(Finding(
                tool="trivy", kind="config",
                rule_id=m.get("ID") or m.get("AVDID") or "UNKNOWN",
                severity=_severity(m.get("Severity")),
                title=m.get("Title") or m.get("Message") or "",
                file=target or None,
                line=cause.get("StartLine"),
            ))
    return found


def parse_semgrep(raw: dict) -> list[Finding]:
    found: list[Finding] = []
    for r in (raw or {}).get("results") or []:
        extra = r.get("extra") or {}
        found.append(Finding(
            tool="semgrep", kind="code",
            rule_id=r.get("check_id") or "UNKNOWN",
            severity=SEMGREP_SEVERITY.get((extra.get("severity") or "").upper(), "UNKNOWN"),
            title=(extra.get("message") or "").strip(),
            file=r.get("path"),
            line=(r.get("start") or {}).get("line"),
        ))
    return found


def parse_gitleaks(raw: list) -> list[Finding]:
    # Cố ý không đọc các trường Secret/Match: giá trị secret không bao giờ rời khỏi máy quét.
    return [
        Finding(
            tool="gitleaks", kind="secret",
            rule_id=item.get("RuleID") or "UNKNOWN",
            severity="CRITICAL",
            title=item.get("Description") or item.get("RuleID") or "",
            file=item.get("File"),
            line=item.get("StartLine"),
        )
        for item in raw or []
    ]


def parse_conftest(raw: list) -> list[Finding]:
    found: list[Finding] = []
    for result in raw or []:
        filename = result.get("filename")
        for level, items, severity in (("deny", result.get("failures"), "HIGH"),
                                       ("warn", result.get("warnings"), "LOW")):
            for item in items or []:
                msg = item.get("msg") or ""
                found.append(Finding(
                    tool="conftest", kind="policy",
                    rule_id=f"{level}:{msg[:60]}",
                    severity=severity, title=msg, file=filename,
                ))
    return found

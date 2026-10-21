"""CLI: `python -m scanner run ...` và `python -m scanner send ...`."""

from __future__ import annotations

import argparse
import os
import smtplib
import sys
from datetime import datetime, timezone
from pathlib import Path

from .diff import diff_reports
from .docker_desktop import DockerDesktop, DockerUnavailable
from .mailer import send_email
from .models import Report
from .previous import fetch_previous_report
from .render import render_email, render_subject, render_summary
from .rules import apply_rules, load_rules
from .runner import count_ignore_rules, default_executor, run_scan


def _run(args, executor, docker) -> int:
    root, out, scanner_dir = Path(args.root).resolve(), Path(args.out), Path(args.scanner_dir).resolve()
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Không tạo được thư mục output: {exc}")
        return 2
    try:
        started = docker.ensure()
    except DockerUnavailable as exc:
        print(f"Không quét được: {exc}")
        return 2
    try:
        return _scan(root, out, scanner_dir, args, executor)
    finally:
        if started:
            docker.stop()


def _load_previous(path: Path):
    try:
        return Report.from_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _scan(root: Path, out: Path, scanner_dir: Path, args, executor) -> int:
    env = os.environ
    repo = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "local")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    branch = "local" if args.mode == "local" else env.get("GITHUB_REF_NAME", "local")

    sections = run_scan(root, out, scanner_dir, executor, mode=args.mode)
    findings = [f for s in sections for f in s.findings]
    apply_rules(findings, load_rules(Path(args.rules) if args.rules else scanner_dir / "rules.yaml"))
    report = Report(
        project=repo.split("/")[-1] if repo else root.name,
        branch=branch,
        commit=env.get("GITHUB_SHA", "local"),
        run_id=run_id,
        run_url=f"{server}/{repo}/actions/runs/{run_id}" if repo else "",
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        sections=sections,
        ignore_rules=count_ignore_rules(root),
    )
    if args.previous:
        previous = _load_previous(Path(args.previous))
    else:
        previous = fetch_previous_report(repo, branch, run_id, env.get("GITHUB_TOKEN", ""))
    diff = diff_reports(report, previous)
    try:
        (out / "report.json").write_text(report.to_json(), encoding="utf-8")
        (out / "email.html").write_text(render_email(report, diff), encoding="utf-8")
        (out / "subject.txt").write_text(render_subject(report, diff), encoding="utf-8")
        (out / "summary.md").write_text(render_summary(report, diff), encoding="utf-8")
    except OSError as exc:
        print(f"Không ghi được báo cáo: {exc}")
        return 2
    c = report.counts()
    print(f"Xong: P1={c['P1']} P2={c['P2']} Backlog={c['Backlog']} Tổng={c['total']}")
    return 0


def _send(args, smtp_factory) -> int:
    user, password, to = (os.environ.get(k, "") for k in ("SMTP_USERNAME", "SMTP_PASSWORD", "REPORT_EMAIL_TO"))
    if not (user and password and to):
        print("Bỏ qua gửi email: thiếu secret SMTP (SMTP_USERNAME, SMTP_PASSWORD, REPORT_EMAIL_TO).")
        return 0
    out = Path(args.out)
    try:
        subject = (out / "subject.txt").read_text(encoding="utf-8").strip()
        html = (out / "email.html").read_text(encoding="utf-8")
        send_email(subject, html, user, password, to, smtp_factory=smtp_factory)
    except Exception as exc:  # noqa: BLE001 - lỗi gửi mail không được làm đỏ workflow
        print(f"Gửi email thất bại: {exc}")
        return 0
    print(f"Đã gửi email tới {to}")
    return 0


def main(argv, executor=default_executor, smtp_factory=smtplib.SMTP_SSL, docker=None) -> int:
    parser = argparse.ArgumentParser(prog="scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="Quét dự án và ghi báo cáo")
    run.add_argument("--root", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--scanner-dir", required=True)
    run.add_argument("--rules", default=None)
    run.add_argument("--mode", choices=("ci", "local"), default="ci")
    run.add_argument("--previous", default=None)
    send = sub.add_parser("send", help="Gửi email báo cáo")
    send.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return _run(args, executor, docker or DockerDesktop())
    return _send(args, smtp_factory)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

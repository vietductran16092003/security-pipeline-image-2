"""Lấy báo cáo của lần quét trước từ artifact `security-report` trên GitHub."""

from __future__ import annotations

import io
import json
import urllib.request
import zipfile
from typing import Optional

from .models import Report

API = "https://api.github.com"
ARTIFACT_NAME = "security-report"


def select_previous_artifact(artifacts: list[dict], branch: str, current_run_id: str,
                             name: str = ARTIFACT_NAME) -> Optional[int]:
    candidates = [
        a for a in artifacts
        if a.get("name") == name and not a.get("expired")
        and (a.get("workflow_run") or {}).get("head_branch") == branch
        and str((a.get("workflow_run") or {}).get("id")) != str(current_run_id)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda a: a.get("created_at") or "")["id"]


def _get(url: str, token: str) -> bytes:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    # URL luôn bắt đầu bằng hằng API (https://api.github.com), không lấy từ input người dùng.
    with urllib.request.urlopen(req, timeout=60) as resp:  # nosemgrep
        return resp.read()


def fetch_previous_report(repo: str, branch: str, run_id: str, token: str) -> Optional[Report]:
    """Mọi lỗi (mạng, quyền, zip hỏng, schema khác) đều trả None: coi như lần quét đầu."""
    if not token or not repo:
        return None
    try:
        listing = json.loads(_get(f"{API}/repos/{repo}/actions/artifacts?name={ARTIFACT_NAME}&per_page=100", token))
        art_id = select_previous_artifact(listing.get("artifacts") or [], branch, run_id)
        if art_id is None:
            return None
        data = _get(f"{API}/repos/{repo}/actions/artifacts/{art_id}/zip", token)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            text = z.read("report.json").decode("utf-8")
        return Report.from_json(text)
    except Exception as exc:  # noqa: BLE001 - lỗi nào cũng không được làm hỏng lượt quét
        print(f"Không lấy được báo cáo lần trước, coi như lần quét đầu: {exc}", flush=True)
        return None

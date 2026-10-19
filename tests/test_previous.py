import io
import json
import urllib.error
import urllib.request
import zipfile

from scanner import previous
from scanner.previous import fetch_previous_report, select_previous_artifact
from conftest import make_report, vuln


def a(art_id, branch, created, expired=False, run_id=None, name="security-report"):
    return {"id": art_id, "name": name, "expired": expired, "created_at": f"{created}T00:00:00Z",
            "workflow_run": {"id": run_id if run_id is not None else art_id * 100, "head_branch": branch}}


def test_select_newest_same_branch():
    arts = [a(1, "main", "2026-10-01"), a(2, "main", "2026-10-03"),
            a(3, "dev", "2026-10-04"), a(4, "main", "2026-10-05", expired=True)]
    assert select_previous_artifact(arts, "main", "999") == 2


def test_select_excludes_current_run():
    assert select_previous_artifact([a(5, "main", "2026-10-06", run_id=999)], "main", "999") is None


def test_select_ignores_other_names():
    assert select_previous_artifact([a(6, "main", "2026-10-06", name="other")], "main", "1") is None


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _zip(text):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", text)
    return buf.getvalue()


def _fake_urlopen(zip_bytes):
    def fake(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        if "/zip" in url:
            return FakeResp(zip_bytes)
        return FakeResp(json.dumps({"artifacts": [a(7, "main", "2026-10-10")]}).encode())
    return fake


def test_fetch_ok(monkeypatch):
    rep = make_report([vuln("A")])
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(_zip(rep.to_json())))
    assert fetch_previous_report("o/r", "main", "1", "t") == rep


def test_fetch_returns_none_on_http_error(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert fetch_previous_report("o/r", "main", "1", "t") is None


def test_fetch_returns_none_on_old_schema(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(_zip('{"schema_version": 0}')))
    assert fetch_previous_report("o/r", "main", "1", "t") is None


def test_fetch_returns_none_on_bad_zip(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(b"not a zip"))
    assert fetch_previous_report("o/r", "main", "1", "t") is None


def test_fetch_without_token_skips_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("không được gọi mạng")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert previous.fetch_previous_report("o/r", "main", "1", "") is None

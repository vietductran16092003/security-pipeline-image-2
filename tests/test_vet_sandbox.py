import json

import pytest

from scanner.vet import sandbox as sb
from scanner.vet.source import InvalidSource, Source
from scanner.vet.verdict import Verdict

PUBLIC_IP = "140.82.112.3"


def src(branch=None, host="github.com", path="o/r"):
    return Source(host=host, path=path, branch=branch, clone_url=f"https://{host}/{path}.git",
                  display=f"{host}/{path}")


def pub(host):
    return [PUBLIC_IP]


def step(cmd):
    for i, a in enumerate(cmd):
        if a == "--label" and cmd[i + 1].startswith("scanvet.step="):
            return cmd[i + 1].split("=", 1)[1]
    return cmd[1]


class FakeDocker:
    def __init__(self):
        self.ensured = 0

    def ensure(self):
        self.ensured += 1
        return False


VET_CLEAN = {"signals": [], "incomplete": []}


class FakeExec:
    """Executor giả: ghi lại mọi lệnh, trả code/stdout theo bước."""

    def __init__(self, codes=None, outputs=None, raises=None):
        self.cmds, self.codes, self.raises = [], codes or {}, raises or {}
        self.outputs = {"size": "1000\t/work/repo\n", "packages": "[]", "read": json.dumps(VET_CLEAN),
                        "inspect": "true\n"}
        self.outputs.update(outputs or {})

    def __call__(self, cmd, stdout_path, timeout):
        assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
        self.cmds.append((cmd, timeout))
        s = step(cmd)
        if s == "ps" and stdout_path is not None and "ps" not in self.outputs:
            # container còn tồn tại = mọi container đã `docker run` (giả lập: không tự xoá)
            stdout_path.write_text("\n".join(c[c.index("--name") + 1] for c, _ in self.cmds
                                             if c[:2] == ["docker", "run"]), encoding="utf-8")
            return 0
        if s in self.raises:
            raise self.raises[s]
        if stdout_path is not None and s in self.outputs:
            stdout_path.write_text(self.outputs[s], encoding="utf-8")
        return self.codes.get(s, 0)

    def steps(self):
        return [step(c) for c, _ in self.cmds]

    def find(self, s):
        return [c for c, _ in self.cmds if step(c) == s]


def no_http(url, body):
    raise AssertionError("không mong gọi mạng")


def run(ex, **kw):
    kw.setdefault("resolver", pub)
    kw.setdefault("http", no_http)
    return sb.vet_repo(src(kw.pop("branch", None)), ex, FakeDocker(), **kw)


# ------------------------------------------------------------------ fetch command

def test_fetch_command_has_no_host_bind_mount_and_disables_hooks():
    cmd = sb.build_fetch_command(src("main"), "scanvet-0123abcd", resolver=pub)
    vols = [cmd[i + 1] for i, a in enumerate(cmd) if a in ("-v", "--volume", "--mount")]
    assert vols == ["scanvet-0123abcd:/work"]
    for v in vols:
        assert not v.startswith(("/", ".", "~")) and ":\\" not in v and v.split(":")[0].startswith("scanvet-")
    joined = " ".join(cmd)
    for flag in ("core.hooksPath=/dev/null", "protocol.file.allow=never", "protocol.allow=never",
                 "protocol.https.allow=always", "filter.lfs.smudge=", "filter.lfs.process=",
                 "filter.lfs.required=false", "http.followRedirects=false", "core.symlinks=false"):
        assert flag in cmd, flag
    for flag in ("--depth", "--no-tags", "--single-branch", "--no-recurse-submodules"):
        assert flag in cmd
    assert cmd[cmd.index("--depth") + 1] == "1"
    for flag in ("--cap-drop", "--security-opt", "--memory", "--pids-limit", "--user", "--name"):
        assert flag in cmd
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in cmd and "--network" not in joined.replace("--network-alias", "")
    assert sb.GIT_IMAGE in cmd and ":" in sb.GIT_IMAGE and not sb.GIT_IMAGE.endswith(":latest")


def test_fetch_pins_validated_ip_with_add_host():
    cmd = sb.build_fetch_command(src(), "scanvet-0123abcd", resolver=lambda h: ["2606:50c0::1", PUBLIC_IP])
    assert cmd[cmd.index("--add-host") + 1] == f"github.com:{PUBLIC_IP}"


def test_fetch_refused_for_private_ip_before_any_docker_call():
    ex = FakeExec()
    with pytest.raises(InvalidSource):
        sb.build_fetch_command(src(), "scanvet-0123abcd", resolver=lambda h: ["10.0.0.5"])
    out = run(ex, resolver=lambda h: [PUBLIC_IP, "192.168.1.1"])
    assert out.verdict is None and out.fetch_error
    assert ex.cmds == []  # từ chối trước mọi lệnh docker


def test_branch_and_url_are_separate_argv_after_double_dash():
    cmd = sb.build_fetch_command(src("feat/x"), "scanvet-0123abcd", resolver=pub)
    i = cmd.index("--branch")
    assert cmd[i + 1] == "feat/x"
    dd = cmd.index("--")
    assert dd > i and cmd[dd + 1:] == ["https://github.com/o/r.git", "/work/repo"]


@pytest.mark.parametrize("branch", ["x --upload-pack=evil", "--upload-pack=evil", "-x", "a b", "a\nb"])
def test_hostile_branch_rejected(branch):
    with pytest.raises(InvalidSource):
        sb.build_fetch_command(src(branch), "scanvet-0123abcd", resolver=pub)


def test_hostile_source_fields_rejected():
    bad = Source(host="github.com", path="o/r", branch=None, clone_url="https://evil.example/o/r.git",
                 display="x")
    with pytest.raises(InvalidSource):
        sb.build_fetch_command(bad, "scanvet-0123abcd", resolver=pub)
    with pytest.raises(InvalidSource):
        sb.build_fetch_command(src(), "/etc", resolver=pub)


# ------------------------------------------------------------------ analyze command

def test_analyze_command_is_offline_readonly_and_dropped_caps():
    cmd = sb.build_analyze_command("scanvet-0123abcd", "scanvet-0123abcd-out")
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--read-only" in cmd
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"
    assert "--memory" in cmd and "--pids-limit" in cmd
    user = cmd[cmd.index("--user") + 1]
    assert not user.startswith("0") and user != "root"
    vols = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert "scanvet-0123abcd:/work:ro" in vols and "scanvet-0123abcd-out:/out" in vols and len(vols) == 2
    tail = cmd[cmd.index(sb.VET_IMAGE) + 1:]
    assert tail == ["/work/repo", "--osv", "/out/osv.json", "--out", "/out/vet.json", "--deadline", "270"]


def test_every_command_is_argv_list_without_shell():
    ex = FakeExec()
    run(ex)
    for cmd, _ in ex.cmds:
        assert cmd[0] == "docker"
        assert not {"sh", "bash", "/bin/sh", "cmd", "python -c", "powershell"} & set(cmd)
        for i, a in enumerate(cmd):
            if a == "-v":
                assert cmd[i + 1].split(":")[0].startswith("scanvet-")


# ------------------------------------------------------------------ vet_repo flow

def test_happy_path_gives_safer_and_cleans_up():
    ex = FakeExec()
    out = run(ex)
    assert out.verdict == Verdict.SAFER and out.fetch_error is None and not out.truncated
    steps = ex.steps()
    assert steps.index("fetch") < steps.index("analyze") < steps.index("read")
    rm = [c for c, _ in ex.cmds if c[:3] == ["docker", "volume", "rm"]]
    assert rm and all(v.startswith("scanvet-") for v in rm[-1][4:])
    assert len(rm[-1][4:]) == 2


def test_volume_removed_even_when_analysis_raises():
    ex = FakeExec(raises={"analyze": RuntimeError("boom")})
    with pytest.raises(RuntimeError):
        run(ex)
    assert ex.cmds[-1][0][:3] == ["docker", "volume", "rm"]
    created = [c[-1] for c, _ in ex.cmds if c[:3] == ["docker", "volume", "create"]]
    assert set(created) <= set(ex.cmds[-1][0])


def test_clone_failure_gives_none_verdict_and_fetch_error():
    ex = FakeExec(codes={"fetch": 128})
    out = run(ex)
    assert out.verdict is None and out.result is None and out.fetch_error
    assert "analyze" not in ex.steps()
    assert ex.cmds[-1][0][:3] == ["docker", "volume", "rm"]


def test_fetch_seam_used_instead_of_clone():
    ex = FakeExec()
    seen = []
    out = run(ex, fetch=lambda executor, volume: seen.append(volume) or 0)
    assert seen and seen[0].startswith("scanvet-") and "fetch" not in ex.steps()
    assert out.verdict == Verdict.SAFER


def test_oversize_marks_truncated():
    ex = FakeExec(outputs={"size": f"{600_000}\t/work/repo\n"})  # KB
    out = run(ex)
    assert out.truncated and out.verdict == Verdict.SUSPICIOUS


def test_oversize_fetch_failure_marks_truncated_no_verdict():
    ex = FakeExec(codes={"fetch": 128}, outputs={"size": f"{489_000}\t/work\n"})
    out = run(ex)
    assert out.truncated and out.verdict is None and out.fetch_error


def test_oversize_with_high_signal_still_not_safe():
    vet = {"signals": [{"id": "x", "level": "high", "file": "a", "line": 1, "why": "w"}], "incomplete": []}
    ex = FakeExec(outputs={"size": "600000\t/work/repo\n", "read": json.dumps(vet)})
    assert run(ex).verdict == Verdict.NOT_SAFE


def test_analysis_timeout_marks_incomplete_and_never_safer():
    ex = FakeExec(codes={"analyze": 124}, outputs={"read": ""})
    out = run(ex)
    assert out.verdict == Verdict.SUSPICIOUS
    assert out.result is not None and out.result.incomplete
    assert out.tool_errors
    timeout = [t for c, t in ex.cmds if step(c) == "analyze"][0]
    assert timeout == 300


@pytest.mark.parametrize("code,read", [(137, json.dumps(VET_CLEAN)), (0, "not json"), (0, "[]"),
                                       (3, json.dumps(VET_CLEAN))])
def test_analysis_failure_never_safer(code, read):
    out = run(FakeExec(codes={"analyze": code}, outputs={"read": read}))
    assert out.verdict != Verdict.SAFER


def test_osv_lookup_flows_into_analysis_and_errors_to_tool_errors():
    ex = FakeExec(outputs={"packages": json.dumps([["npm", "evil", "1.0.0"]])})

    def http(url, body):
        raise OSError("mạng lỗi")
    out = run(ex, http=http)
    assert out.tool_errors and any("OSV" in e for e in out.tool_errors)
    assert out.verdict == Verdict.SUSPICIOUS
    w = ex.find("osv-write")[0]
    payload = json.loads(w[-1])
    assert payload["malicious"] == [] and payload["error"]


def test_osv_hit_passed_to_analysis():
    ex = FakeExec(outputs={"packages": json.dumps([["npm", "evil", "1.0.0"]])})
    http = lambda u, b: json.dumps({"results": [{"vulns": [{"id": "MAL-2025-9"}]}]}).encode()  # noqa: E731
    run(ex, http=http)
    payload = json.loads(ex.find("osv-write")[0][-1])
    assert payload["malicious"][0]["id"] == "MAL-2025-9"


def test_result_strings_sanitized():
    vet = {"signals": [{"id": "x\x1b[2J", "level": "medium", "file": "a\x07\r\nb", "line": 7,
                        "why": "w\x1b]0;pwn\x07"}], "incomplete": ["i\x1b[1m"]}
    out = run(FakeExec(outputs={"read": json.dumps(vet)}))
    s = out.result.signals[0]
    for text in (s.id, s.file, s.why, out.result.incomplete[0]):
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in text)
    assert out.verdict == Verdict.SUSPICIOUS


def test_docker_unavailable_gives_no_verdict():
    from scanner.docker_desktop import DockerUnavailable

    class D:
        def ensure(self):
            raise DockerUnavailable("không có docker")
    ex = FakeExec()
    out = sb.vet_repo(src(), ex, D(), resolver=pub, http=no_http)
    assert out.verdict is None and out.fetch_error and ex.cmds == []


def test_volume_names_random_and_prefixed():
    a, b = sb.new_volume_name(), sb.new_volume_name()
    assert a != b and a.startswith("scanvet-") and len(a) > len("scanvet-") + 8


def test_ensure_vet_image_builds_from_minimal_context():
    seen = {}

    def ex(cmd, stdout_path, timeout):
        from pathlib import Path
        ctx = Path(cmd[-1])
        seen["files"] = sorted(p.relative_to(ctx).as_posix() for p in ctx.rglob("*") if p.is_file())
        seen["cmd"] = cmd
        return 0
    assert sb.ensure_vet_image(ex) is True
    assert seen["cmd"][:2] == ["docker", "build"] and sb.VET_IMAGE in seen["cmd"]
    assert "Dockerfile" in seen["files"]
    assert all(f == "Dockerfile" or f.startswith("scanner/") for f in seen["files"])
    assert "scanner/vet/signals.py" in seen["files"] and "scanner/vet/sandbox.py" not in seen["files"]
    assert not any("test" in f or f.startswith("scanner/runner") for f in seen["files"])


def test_dockerfile_pinned_nonroot_no_installs():
    from pathlib import Path
    text = (Path(sb.__file__).parent / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.12." in text and "-slim" in text
    assert "USER 10001" in text
    assert "pip" not in text and "apt" not in text


# ------------------------------------------------------------------ review fixes (Task 10)

def _val(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def test_parse_result_hostile_json_never_raises():
    assert sb.parse_result("[" * 200000) is None
    assert sb.parse_result("{" * 200000) is None
    assert sb.parse_result('{"signals": ' + "[" * 100000) is None


def test_parse_result_hostile_vet_json_gives_suspicious_not_traceback():
    out = run(FakeExec(outputs={"read": "[" * 200000}))
    assert out.verdict == Verdict.SUSPICIOUS and out.tool_errors


def test_parse_result_size_cap():
    big = json.dumps({"signals": [], "incomplete": ["x" * 100]}) + " " * (sb.MAX_RESULT_BYTES + 10)
    assert sb.parse_result(big) is None


def _sig(**kw):
    s = {"id": "x", "level": "low", "file": "a", "line": 1, "why": "w"}
    s.update(kw)
    return json.dumps({"signals": [s], "incomplete": []})


@pytest.mark.parametrize("bad", [
    {"level": "critical"}, {"level": "HIGH"}, {"level": ""}, {"level": None}, {"level": 5},
    {"id": 5}, {"file": ["a"]}, {"why": None}, {"line": "7"}, {"line": 1.5}, {"line": True},
    {"id": "x" * 500}, {"file": "f" * 5000}, {"why": "w" * 5000}, {"line": -1},
])
def test_parse_result_strict_schema_rejects(bad):
    assert sb.parse_result(_sig(**bad)) is None


def test_parse_result_non_dict_signal_and_non_str_incomplete_rejected():
    assert sb.parse_result(json.dumps({"signals": ["x"], "incomplete": []})) is None
    assert sb.parse_result(json.dumps({"signals": [], "incomplete": [5]})) is None
    assert sb.parse_result(json.dumps({"signals": [{"id": "x"}], "incomplete": []})) is None


@pytest.mark.parametrize("lv", ["high", "medium", "low", "info"])
def test_parse_result_accepts_whitelisted_levels(lv):
    assert sb.parse_result(_sig(level=lv)).signals[0].level == lv
    assert sb.parse_result(_sig(line=None)).signals[0].line is None


def test_unknown_level_never_safer_via_vet_repo():
    out = run(FakeExec(outputs={"read": _sig(level="critical")}))
    assert out.verdict == Verdict.SUSPICIOUS and out.tool_errors


def _removed_names(ex):
    out = []
    for c, _ in ex.cmds:
        if c[:3] == ["docker", "rm", "-f"]:
            out += c[3:]
    return out


def _run_names(ex):
    return [c[c.index("--name") + 1] for c, _ in ex.cmds if c[:2] == ["docker", "run"]]


def test_keyboard_interrupt_mid_analysis_kills_containers_before_volume_rm():
    ex = FakeExec(raises={"analyze": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        run(ex)
    names = _run_names(ex)
    analyze_name = [c[c.index("--name") + 1] for c in ex.find("analyze")][0]
    assert analyze_name in names
    cmds = [c for c, _ in ex.cmds]
    rm_idx = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "rm", "-f"]]
    vol_idx = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "volume", "rm"]]
    assert rm_idx and vol_idx and max(rm_idx) < min(vol_idx)
    assert set(names) <= set(_removed_names(ex))
    assert cmds[vol_idx[0]][:4] == ["docker", "volume", "rm", "-f"]
    created = [c[-1] for c in cmds if c[:3] == ["docker", "volume", "create"]]
    assert cmds[vol_idx[0]][4:] == created


def test_volume_rm_failure_retried_after_container_rm_and_exception_propagates():
    class Ex(FakeExec):
        vol_calls = 0

        def __call__(self, cmd, stdout_path, timeout):
            if cmd[:3] == ["docker", "volume", "rm"]:
                self.cmds.append((cmd, timeout))
                Ex.vol_calls += 1
                return 1 if Ex.vol_calls == 1 else 0
            return super().__call__(cmd, stdout_path, timeout)
    ex = Ex(raises={"analyze": RuntimeError("boom")})
    with pytest.raises(RuntimeError, match="boom"):
        run(ex)
    cmds = [c for c, _ in ex.cmds]
    seq = [c[:3] for c in cmds if c[:3] in (["docker", "rm", "-f"], ["docker", "volume", "rm"])]
    assert seq == [["docker", "rm", "-f"], ["docker", "volume", "rm"],
                   ["docker", "rm", "-f"], ["docker", "volume", "rm"]]
    assert Ex.vol_calls == 2


def test_cleanup_errors_do_not_mask_original_exception():
    class Ex(FakeExec):
        def __call__(self, cmd, stdout_path, timeout):
            if cmd[:2] == ["docker", "rm"] or cmd[:3] == ["docker", "volume", "rm"]:
                raise OSError("cleanup broke")
            return super().__call__(cmd, stdout_path, timeout)
    ex = Ex(raises={"analyze": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        run(ex)


def _all_run_cmds():
    ex = FakeExec(outputs={"packages": json.dumps([["npm", "evil", "1.0.0"]])})
    http = lambda u, b: json.dumps({"results": [{"vulns": [{"id": "MAL-2025-9"}]}]}).encode()  # noqa: E731
    run(ex, http=http)
    return ex, [c for c, _ in ex.cmds if c[:2] == ["docker", "run"]]


EXPECTED = {  # step -> (memory, pids, has_network, extra volume specs)
    "hold": ("64m", "16", False, ["{v}:/work", "{o}:/out"]),
    "fetch": ("1g", "256", True, ["{v}:/work"]),
    "size": ("256m", "64", False, ["{v}:/work:ro"]),
    "packages": ("512m", "64", False, ["{v}:/work:ro"]),
    "osv-write": ("256m", "64", False, ["{o}:/out"]),
    "analyze": ("1g", "128", False, ["{v}:/work:ro", "{o}:/out"]),
    "read": ("256m", "64", False, ["{o}:/in:ro"]),
}


def test_every_docker_run_has_full_isolation_with_exact_values():
    ex, runs = _all_run_cmds()
    assert sorted(step(c) for c in runs) == sorted(EXPECTED)
    created = [c[-1] for c, _ in ex.cmds if c[:3] == ["docker", "volume", "create"]]
    v, o = created
    for c in runs:
        s = step(c)
        mem, pids, net, vols = EXPECTED[s]
        assert _val(c, "--cap-drop") == "ALL", s
        assert _val(c, "--security-opt") == "no-new-privileges", s
        assert "--read-only" in c, s
        assert _val(c, "--user") == "10001:10001", s
        assert _val(c, "--memory") == mem and _val(c, "--memory-swap") == mem, s
        assert _val(c, "--pids-limit") == pids, s
        assert _val(c, "--tmpfs") == "/tmp:rw,size=64m,noexec,nosuid,nodev", s
        assert "--privileged" not in c and "--pid" not in c and "--ipc" not in c and "--device" not in c, s
        assert not any(a.startswith(("--cap-add", "--volumes-from", "--mount")) for a in c), s
        if net:
            assert "--network" not in c and _val(c, "--add-host") == f"github.com:{PUBLIC_IP}", s
        else:
            assert _val(c, "--network") == "none", s
        specs = [c[i + 1] for i, a in enumerate(c) if a in ("-v", "--volume")]
        assert specs == [x.format(v=v, o=o) for x in vols], s
        assert _val(c, "--name").startswith("scanvet-"), s
        assert "scanvet=1" in c, s
    assert len(set(_run_names(ex))) == len(runs)


def test_volume_create_is_size_capped_tmpfs():
    ex, _ = _all_run_cmds()
    creates = [c for c, _ in ex.cmds if c[:3] == ["docker", "volume", "create"]]
    assert len(creates) == 2
    for c in creates:
        assert "type=tmpfs" in c and any(a.startswith("o=size=") and "mode=0700" in a for a in c)


def test_base_helper_regression_would_fail():
    base = sb._base("x", "scanvet-x-1")
    assert base[:3] == ["docker", "run", "--rm"]
    for pair in (["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--user", "10001:10001"],
                 ["--network", "none"]):
        i = base.index(pair[0])
        assert base[i:i + 2] == pair


def test_osv_payload_capped_for_argv_and_recorded_as_tool_error():
    many = [["npm", f"pkg{i}", "1.0.0"] for i in range(3000)]
    ex = FakeExec(outputs={"packages": json.dumps(many)})
    http = lambda u, b: json.dumps({"results": [  # noqa: E731
        {"vulns": [{"id": f"MAL-2025-{i}"}]} for i in range(len(json.loads(b)["queries"]))]}).encode()
    out = run(ex, http=http)
    w = ex.find("osv-write")[0]
    assert len(w[-1]) <= sb.MAX_OSV_ARG
    assert sum(len(a) + 1 for a in w) < 30000
    payload = json.loads(w[-1])
    assert payload["error"] and payload["malicious"]
    assert out.verdict != Verdict.SAFER and any("OSV" in e for e in out.tool_errors)


# ------------------------------------------------------------------ fix round 2

def _many(n, level, extra=None):
    sigs = [{"id": f"s{i}", "level": level, "file": "a", "line": 1, "why": "w"} for i in range(n)]
    return json.dumps({"signals": sigs + (extra or []), "incomplete": []})


def _note(n):
    return f"Đã cắt bớt {n} tín hiệu (giữ {sb._MAX_SIGNALS} tín hiệu mức cao nhất)"


def test_truncation_keeps_high_signal_at_end_and_notes_it():
    high = {"id": "H", "level": "high", "file": "a", "line": 1, "why": "w"}
    out = run(FakeExec(outputs={"read": _many(2500, "info", [high])}))
    assert out.verdict == Verdict.NOT_SAFE
    assert any(s.id == "H" for s in out.result.signals) and len(out.result.signals) == 2000
    assert _note(501) in out.result.incomplete


def test_truncation_of_low_signals_never_safer():
    out = run(FakeExec(outputs={"read": _many(2500, "low")}))
    assert out.verdict != Verdict.SAFER
    assert _note(500) in out.result.incomplete


def test_exactly_max_signals_has_no_note():
    r = sb.parse_result(_many(2000, "info"))
    assert len(r.signals) == 2000 and r.incomplete == []


def test_truncation_sort_is_stable_by_level_rank():
    sigs = [{"id": f"i{k}", "level": "info", "file": "a", "line": 1, "why": "w"} for k in range(1000)]
    sigs += [{"id": f"m{k}", "level": "medium", "file": "a", "line": 1, "why": "w"} for k in range(1500)]
    r = sb.parse_result(json.dumps({"signals": sigs, "incomplete": []}))
    assert [s.id for s in r.signals[:1500]] == [f"m{k}" for k in range(1500)]
    assert r.signals[1500].id == "i0" and len(r.signals) == 2000


@pytest.mark.parametrize("bad", ['{"signals":[{"id":"\\ud800","level":"high","file":"a","line":1,"why":"w"}],"incomplete":[]}',
                                 '{"signals":[{"id":"x","level":"high","file":"\\udfff","line":1,"why":"w"}],"incomplete":[]}',
                                 '{"signals":[{"id":"x","level":"high","file":"a","line":1,"why":"\\udc00"}],"incomplete":[]}',
                                 '{"signals":[],"incomplete":["\\ud800"]}'])
def test_lone_surrogates_rejected(bad):
    assert sb.parse_result(bad) is None
    out = run(FakeExec(outputs={"read": bad}))
    assert out.verdict == Verdict.SUSPICIOUS and out.tool_errors


def test_keyboard_interrupt_during_fetch_removes_containers_before_volumes():
    ex = FakeExec(raises={"fetch": KeyboardInterrupt()})
    with pytest.raises(KeyboardInterrupt):
        run(ex)
    cmds = [c for c, _ in ex.cmds]
    fetch_name = _val(ex.find("fetch")[0], "--name")
    rm_idx = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "rm", "-f"]]
    vol_idx = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "volume", "rm"]]
    assert rm_idx and vol_idx and max(rm_idx) < min(vol_idx)
    assert fetch_name in cmds[rm_idx[0]]
    assert "analyze" not in ex.steps()


# ------------------------------------------------------------------ fix round 3 (hostile types)

@pytest.mark.parametrize("level", [[1], {}, {"a": 1}, 5, None, True, 1.5, [], "x"])
def test_unhashable_or_wrong_type_level_rejected(level):
    text = json.dumps({"signals": [{"id": "x", "level": level, "file": "a", "line": 1, "why": "w"}],
                       "incomplete": []})
    assert sb.parse_result(text) is None
    out = run(FakeExec(outputs={"read": text}))
    assert out.verdict == Verdict.SUSPICIOUS and out.tool_errors


@pytest.mark.parametrize("field", ["id", "file", "why", "line"])
@pytest.mark.parametrize("val", [[1], {}, {"a": 1}, 5.5, True])
def test_hostile_other_fields_never_raise(field, val):
    s = {"id": "x", "level": "low", "file": "a", "line": 1, "why": "w"}
    s[field] = val
    assert sb.parse_result(json.dumps({"signals": [s], "incomplete": []})) is None


@pytest.mark.parametrize("inc", [[[1]], [{}], [None], [5], "str", {"a": 1}])
def test_hostile_incomplete_never_raises(inc):
    assert sb.parse_result(json.dumps({"signals": [], "incomplete": inc})) is None


@pytest.mark.parametrize("pk", ["5", "{}", '"str"', "null", "[[1,2,3]]", '[[[1],"a","1"]]', '[["npm",[1],"1"]]',
                                '[["npm","a",[1]]]', pytest.param("[" * 200000, id="deep"), "x"])
def test_hostile_packages_output_never_raises(pk):
    out = run(FakeExec(outputs={"packages": pk}))
    assert out.verdict is not None  # khong nem ngoai le


@pytest.mark.parametrize("resp", [b"[]", b"5", b"null", b'{"results": 5}', b'{"results": [[1]]}',
                                  b'{"results": [{"vulns": 5}]}', b'{"results": [{"vulns": [5, null, [1], {"id": [1]}, {"id": {}}]}]}',
                                  b'{"results": [{"vulns": {"id": "MAL-1"}}]}', b"\xff\xfe", pytest.param(b"[" * 200000, id="deep")])
def test_hostile_osv_response_never_raises(resp):
    from scanner.vet import osv
    r = osv.lookup_osv([("npm", "a", "1.0.0")], lambda u, b: resp)
    assert r["malicious"] == [] 
    out = run(FakeExec(outputs={"packages": json.dumps([["npm", "a", "1.0.0"]])}), http=lambda u, b: resp)
    assert out.verdict is not None


# ------------------------------------------------------------------ real-Docker fix: holder + quiet cleanup

def _idx(ex, pred):
    return [i for i, (c, _) in enumerate(ex.cmds) if pred(c)]


def test_holder_started_after_volumes_and_before_fetch_and_verified():
    ex = FakeExec()
    run(ex)
    cmds = [c for c, _ in ex.cmds]
    creates = _idx(ex, lambda c: c[:3] == ["docker", "volume", "create"])
    hold = _idx(ex, lambda c: c[:2] == ["docker", "run"] and step(c) == "hold")
    insp = _idx(ex, lambda c: c[:2] == ["docker", "inspect"])
    fetch = _idx(ex, lambda c: c[:2] == ["docker", "run"] and step(c) == "fetch")
    assert len(hold) == 1 and max(creates) < hold[0] < insp[0] < fetch[0]
    h = cmds[hold[0]]
    assert "-d" in h[:4] and h[h.index("--entrypoint") + 1] == "sleep" and h[-1] == str(sb.HOLD_SECONDS)
    name = _val(h, "--name")
    assert cmds[insp[0]] == ["docker", "inspect", "-f", "{{.State.Running}}", name]


def test_holder_started_before_fetch_seam():
    ex = FakeExec()
    seen = []
    run(ex, fetch=lambda executor, volume: seen.append(list(ex.steps())) or 0)
    assert "hold" in seen[0] and "inspect" in seen[0] and "fetch" not in seen[0]


def test_every_shared_volume_is_mounted_by_holder():
    # Volume tmpfs bị umount và MẤT dữ liệu khi không còn container nào dùng nó, nên mọi volume
    # được >= 2 bước dùng phải luôn được container "hold" giữ.
    ex, runs = _all_run_cmds()
    users = {}
    for c in runs:
        for i, a in enumerate(c):
            if a == "-v":
                users.setdefault(c[i + 1].split(":")[0], []).append(step(c))
    assert users
    for vol, steps_ in users.items():
        if len([x for x in steps_ if x != "hold"]) >= 2:
            assert "hold" in steps_, (vol, steps_)
    assert set(users) == {c[-1] for c, _ in ex.cmds if c[:3] == ["docker", "volume", "create"]}


def test_holder_not_running_is_fetch_failure_and_volumes_removed():
    ex = FakeExec(outputs={"inspect": "false\n"})
    out = run(ex)
    assert out.verdict is None and out.fetch_error and "fetch" not in ex.steps()
    cmds = [c for c, _ in ex.cmds]
    assert cmds[-1][:4] == ["docker", "volume", "rm", "-f"]


def test_holder_run_failure_is_fetch_failure():
    ex = FakeExec(codes={"hold": 125})
    out = run(ex)
    assert out.verdict is None and out.fetch_error
    assert "inspect" not in ex.steps() and "fetch" not in ex.steps()
    assert [c for c, _ in ex.cmds][-1][:3] == ["docker", "volume", "rm"]


def test_holder_removed_before_volumes_on_interrupt_and_normal():
    for raises in ({"analyze": KeyboardInterrupt()}, {}):
        ex = FakeExec(raises=raises)
        try:
            run(ex)
        except KeyboardInterrupt:
            pass
        hold_name = _val(ex.find("hold")[0], "--name")
        cmds = [c for c, _ in ex.cmds]
        rm = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "rm", "-f"] and hold_name in c]
        vol = [i for i, c in enumerate(cmds) if c[:3] == ["docker", "volume", "rm"]]
        assert rm and vol and rm[0] < vol[0]


def test_cleanup_lists_present_containers_and_skips_absent():
    ex = FakeExec(outputs={"ps": ""})  # mọi container đã tự xoá (--rm)
    run(ex)
    ps = [c for c, _ in ex.cmds if c[:2] == ["docker", "ps"]]
    assert ps and ps[0][:7] == ["docker", "ps", "-a", "--filter", "label=scanvet=1", "--format", "{{.Names}}"]
    assert not [c for c, _ in ex.cmds if c[:3] == ["docker", "rm", "-f"]]  # không rm container vắng mặt


def test_cleanup_removes_only_listed_present_names():
    holder = {}

    class Ex(FakeExec):
        def __call__(self, cmd, stdout_path, timeout):
            if cmd[:2] == ["docker", "ps"]:
                self.cmds.append((cmd, timeout))
                stdout_path.write_text(holder["name"] + "\nscanvet-other-container\nrandom\n", encoding="utf-8")
                return 0
            r = super().__call__(cmd, stdout_path, timeout)
            if step(cmd) == "hold":
                holder["name"] = _val(cmd, "--name")
            return r
    ex = Ex()
    run(ex)
    rm = [c for c, _ in ex.cmds if c[:3] == ["docker", "rm", "-f"]]
    assert rm == [["docker", "rm", "-f", holder["name"]]]  # chỉ tên của lần chạy này và còn tồn tại


def test_analyzer_failure_surfaces_incomplete_detail_in_tool_errors():
    vet = {"signals": [], "incomplete": ["Không tìm thấy thư mục repo\x1b[2J để phân tích"]}
    out = run(FakeExec(codes={"analyze": 2}, outputs={"read": json.dumps(vet)}))
    assert out.verdict == Verdict.SUSPICIOUS
    joined = " ".join(out.tool_errors)
    assert "thoát mã 2" in joined and "Không tìm thấy thư mục repo" in joined and "\x1b" not in joined

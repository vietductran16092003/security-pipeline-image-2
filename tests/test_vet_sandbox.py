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
        self.outputs = {"size": "1000\t/work/repo\n", "packages": "[]", "read": json.dumps(VET_CLEAN)}
        self.outputs.update(outputs or {})

    def __call__(self, cmd, stdout_path, timeout):
        assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
        self.cmds.append((cmd, timeout))
        s = step(cmd)
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
    vet = {"signals": [{"id": "x\x1b[2J", "level": "medium", "file": "a\x07\r\nb", "line": "7",
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

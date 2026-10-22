r"""Test đầu-cuối cho "kiểm tra repo lạ" với Docker THẬT (chạy tay, mặc định bị loại bởi pytest.ini).

Chạy:  .venv\Scripts\python -m pytest -m docker -q

Repo mẫu (tests/fixtures/vet/*) được chép vào volume sandbox qua tham số `fetch` của `vet_repo`
thay cho `git clone`; sau đó chạy container phân tích THẬT. Sau mỗi test không được còn volume
`scanvet-*` hoặc container gắn nhãn `scanvet=1`.
"""
import subprocess
from pathlib import Path

import pytest

from scanner.docker_desktop import DockerDesktop
from scanner.runner import default_executor
from scanner.vet import source as S
from scanner.vet.command import vet_command
from scanner.vet.render import LIMITS_NOTE, render_vet_html
from scanner.vet.sandbox import GIT_IMAGE, VET_USER, vet_repo
from scanner.vet.verdict import Verdict

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vet"


def _docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _fake_source(name: str) -> S.Source:
    return S.Source("github.com", f"fixture/{name}", None, f"https://github.com/fixture/{name}.git",
                    f"github.com/fixture/{name}")


def _fixture_fetch(name: str):
    """Chép tests/fixtures/vet/<name> vào /work/repo của volume (container tạm, không có mạng)."""
    src_dir = FIXTURES / name

    def fetch(executor, volume: str) -> int:
        cmd = ["docker", "run", "--rm", "--label", "scanvet=1", "--network", "none", "--cap-drop", "ALL",
               "--user", VET_USER, "-v", f"{volume}:/work", "-v", f"{src_dir}:/src:ro",
               "--entrypoint", "sh", GIT_IMAGE, "-c", "mkdir -p /work/repo && cp -R /src/. /work/repo/"]
        return executor(cmd, None, 120)
    return fetch


def _out(args: list[str]) -> str:
    return subprocess.run(args, capture_output=True, text=True, timeout=60).stdout.strip()


def _leftovers() -> tuple[str, str]:
    return (_out(["docker", "volume", "ls", "-q", "--filter", "name=scanvet-"]),
            _out(["docker", "ps", "-a", "-q", "--filter", "label=scanvet=1"]))


@pytest.fixture
def docker_env():
    if not _docker_ok():
        pytest.skip("Docker không chạy (docker info lỗi)")
    before = _leftovers()
    yield DockerDesktop()
    assert _leftovers() == before, "còn volume/container scanvet sót lại sau test"


def _vet(docker, name):
    return vet_repo(_fake_source(name), default_executor, docker, fetch=_fixture_fetch(name))


def _has(outcome, sid, file, line):
    return any(s.id == sid and s.file == file and s.line == line for s in outcome.result.signals)


@pytest.mark.docker
def test_evil_npm_is_not_safe(docker_env):
    o = _vet(docker_env, "evil_npm")
    assert o.verdict == Verdict.NOT_SAFE, (o.verdict, o.tool_errors, o.fetch_error)
    assert _has(o, "autorun-install-script", "package.json", 5)
    assert _has(o, "autorun-devcontainer", ".devcontainer/devcontainer.json", 4)
    assert _has(o, "autorun-editor-task", ".vscode/tasks.json", 8)


@pytest.mark.docker
def test_evil_py_is_not_safe(docker_env):
    o = _vet(docker_env, "evil_py")
    assert o.verdict == Verdict.NOT_SAFE, (o.verdict, o.tool_errors, o.fetch_error)
    assert _has(o, "obfuscated-exec", "loader.py", 4)
    assert _has(o, "credential-access", "steal.py", 4)
    assert _has(o, "autorun-python-build", "setup.py", 6)


@pytest.mark.docker
def test_clean_small_is_safer_with_limits_note(docker_env):
    o = _vet(docker_env, "clean_small")
    assert o.verdict == Verdict.SAFER, (o.verdict, o.result and o.result.signals, o.tool_errors)
    html = render_vet_html(o)
    assert Verdict.SAFER.value in html
    from html import escape
    assert escape(LIMITS_NOTE) in html


def test_invalid_url_is_rejected_before_docker():
    calls = []

    class NoDocker:
        def ensure(self):
            calls.append("ensure")
            return False

    code = vet_command("http://github.com@evil.example/x", lambda *a, **k: calls.append(a) or 0, NoDocker(),
                       open_report=lambda p: True)
    assert code == 2
    assert calls == []
    with pytest.raises(S.InvalidSource):
        S.parse_source("file:///etc/passwd")

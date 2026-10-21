import pytest

from scanner.docker_desktop import DockerDesktop, DockerUnavailable


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.now += s


def make(ready_after=None, start_rc=0, exe="C:/Docker Desktop.exe", platform="win32", stop_rc=0):
    """ready_after: số lần gọi `docker info` thất bại trước khi Docker sẵn sàng (None = không bao giờ)."""
    calls, launched, clock = [], [], FakeClock()
    state = {"info": 0}

    def run(cmd, timeout=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "info"]:
            state["info"] += 1
            return 0 if ready_after is not None and state["info"] > ready_after else 1
        if cmd[:3] == ["docker", "desktop", "start"]:
            return start_rc
        if cmd[:3] == ["docker", "desktop", "stop"]:
            return stop_rc
        return 1

    d = DockerDesktop(run=run, launch=launched.append, find_exe=lambda: exe, sleep=clock.sleep,
                      clock=clock, platform=platform, timeout=180)
    return d, calls, launched, clock


def test_already_running_is_left_alone():
    d, calls, launched, _ = make(ready_after=0)
    assert d.ensure() is False
    assert calls == [["docker", "info"]] and launched == []


def test_starts_desktop_when_stopped(capsys):
    d, calls, launched, _ = make(ready_after=1)
    assert d.ensure() is True
    assert any(c[:3] == ["docker", "desktop", "start"] for c in calls) and launched == []
    assert "Đang khởi động Docker Desktop" in capsys.readouterr().out


def test_waits_until_engine_ready():
    d, _, _, clock = make(ready_after=5)
    assert d.ensure() is True
    assert 0 < clock.now < 180


def test_falls_back_to_exe_when_cli_start_fails():
    d, _, launched, _ = make(ready_after=2, start_rc=1)
    assert d.ensure() is True
    assert launched == [["C:/Docker Desktop.exe"]]


def test_not_installed_gives_one_clear_error():
    d, _, launched, _ = make(ready_after=None, start_rc=1, exe=None)
    with pytest.raises(DockerUnavailable, match="Không tìm thấy Docker Desktop"):
        d.ensure()
    assert launched == []


def test_timeout_gives_one_clear_error():
    d, _, _, clock = make(ready_after=None)
    with pytest.raises(DockerUnavailable, match="180 giây"):
        d.ensure()
    assert clock.now <= 183


def test_non_windows_does_not_try_to_start():
    d, calls, launched, _ = make(ready_after=None, platform="linux")
    with pytest.raises(DockerUnavailable, match="Docker chưa chạy"):
        d.ensure()
    assert calls == [["docker", "info"]] and launched == []


def test_stop_uses_desktop_cli(capsys):
    d, calls, _, _ = make()
    d.stop()
    assert calls[-1][:3] == ["docker", "desktop", "stop"]
    assert "Đang tắt Docker Desktop" in capsys.readouterr().out


def test_stop_failure_is_reported_not_raised(capsys):
    d, _, _, _ = make(stop_rc=1)
    d.stop()
    assert "tắt tay" in capsys.readouterr().out

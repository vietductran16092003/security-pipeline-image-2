"""Tự mở Docker Desktop khi quét trên máy và tắt lại sau khi quét, nếu chính bộ quét đã mở nó."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional

START_TIMEOUT = 180  # lần đầu mở máy, Docker Desktop có thể mất 1-2 phút
POLL_SECONDS = 3


class DockerUnavailable(Exception):
    """Không có Docker để quét; thông báo dành cho người dùng."""


def _quiet(cmd: list[str], timeout: Optional[float] = None) -> int:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout).returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 1


def _desktop_exe() -> Optional[Path]:
    for base in (os.environ.get("ProgramFiles"), r"C:\Program Files"):
        if base:
            exe = Path(base) / "Docker" / "Docker" / "Docker Desktop.exe"
            if exe.is_file():
                return exe
    return None


class DockerDesktop:
    def __init__(self, run: Callable[..., int] = _quiet, launch: Callable = subprocess.Popen,
                 find_exe: Callable[[], Optional[Path]] = _desktop_exe, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, platform: str = sys.platform,
                 timeout: int = START_TIMEOUT):
        self.run, self.launch, self.find_exe = run, launch, find_exe
        self.sleep, self.clock, self.platform, self.timeout = sleep, clock, platform, timeout

    def ready(self) -> bool:
        return self.run(["docker", "info"], 30) == 0

    def ensure(self) -> bool:
        """Đảm bảo Docker chạy được. Trả về True nếu chính hàm này đã mở Docker Desktop."""
        if self.ready():
            return False
        if self.platform != "win32":
            raise DockerUnavailable("Docker chưa chạy. Hãy khởi động Docker rồi quét lại.")
        print("Đang khởi động Docker Desktop…", flush=True)
        deadline = self.clock() + self.timeout
        if self.run(["docker", "desktop", "start", "--timeout", str(self.timeout)], self.timeout + 30) != 0:
            exe = self.find_exe()
            if exe is None:
                raise DockerUnavailable("Không tìm thấy Docker Desktop trên máy. Hãy cài Docker Desktop rồi quét lại.")
            self.launch([str(exe)])
        while not self.ready():
            if self.clock() >= deadline:
                raise DockerUnavailable(f"Docker Desktop chưa sẵn sàng sau {self.timeout} giây. "
                                        "Hãy mở Docker Desktop xem có báo lỗi không rồi quét lại.")
            self.sleep(POLL_SECONDS)
        print("Docker Desktop đã sẵn sàng.", flush=True)
        return True

    def stop(self) -> None:
        print("Đang tắt Docker Desktop…", flush=True)
        if self.run(["docker", "desktop", "stop"], 120) != 0:
            print("Không tắt được Docker Desktop, bạn có thể tắt tay.", flush=True)

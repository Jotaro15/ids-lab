"""Tests for the packet capture wrapper."""

import subprocess
import time
from pathlib import Path

import pytest

from idslab.capture.capture import CaptureError, capture_packets


class _FakeStdout:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text


class _FakeProcess:
    """Stands in for a tcpdump subprocess.Popen handle.

    `exits_with` is None for a capture that runs until it is terminated
    (the expected case), or an exit code for one that stops on its own.
    """

    def __init__(self, exits_with: int | None, stdout_text: str = "") -> None:
        self._exits_with = exits_with
        self.returncode = exits_with
        self.terminated = False
        self.killed = False
        self.stdout = _FakeStdout(stdout_text)
        self._still_running = exits_with is None

    def wait(self, timeout: float = 0.0) -> int:
        if self._still_running:
            raise subprocess.TimeoutExpired(cmd="tcpdump", timeout=timeout)
        return self._exits_with or 0

    def terminate(self) -> None:
        self.terminated = True
        self._still_running = False

    def kill(self) -> None:
        self.killed = True
        self._still_running = False


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)


def test_capture_packets_returns_the_requested_output_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _FakeProcess(exits_with=None)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)

    output = tmp_path / "nested" / "out.pcap"
    result = capture_packets("eth0", duration=5, output=output)

    assert result == output
    assert output.parent.is_dir()
    assert fake.terminated is True


def test_capture_packets_raises_if_tcpdump_exits_early(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _FakeProcess(exits_with=1, stdout_text="tcpdump: eth0: No such device exists")
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)

    with pytest.raises(CaptureError, match="No such device"):
        capture_packets("eth0", duration=5, output=tmp_path / "out.pcap")


def test_capture_packets_kills_tcpdump_if_it_ignores_terminate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _StubbornProcess(_FakeProcess):
        def terminate(self) -> None:
            # Unlike the base class, stays "running" after a first terminate.
            self.terminated = True

    fake = _StubbornProcess(exits_with=None)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: fake)

    capture_packets("eth0", duration=5, output=tmp_path / "out.pcap")

    assert fake.killed is True

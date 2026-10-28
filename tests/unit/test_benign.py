"""Tests for the benign traffic generator."""

import random
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from idslab.lab import benign


def _config(**changes: Any) -> benign.Config:
    values: dict[str, Any] = {
        "target": "victim",
        "user": "labuser",
        "password": "secret",
        "mean_interval": 1.0,
        "duration": 10.0,
        "seed": 1,
    }
    values.update(changes)
    return benign.Config(**values)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802  # name required by the base class
        status = 404 if self.path == "/missing.html" else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Keep test output quiet."""


@pytest.fixture
def web_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311  # simulation, not cryptography


def test_next_action_is_reproducible_with_a_seed() -> None:
    first = [benign.next_action(_rng(7)) for _ in range(20)]
    second = [benign.next_action(_rng(7)) for _ in range(20)]
    assert first == second


def test_next_action_only_returns_known_actions() -> None:
    rng = _rng(0)
    assert {benign.next_action(rng) for _ in range(500)} == set(benign.ACTION_WEIGHTS)


def test_http_get_returns_the_status_code(web_server: str) -> None:
    assert benign.http_get(f"{web_server}/") == 200


def test_http_get_treats_an_error_status_as_an_answer(web_server: str) -> None:
    assert benign.http_get(f"{web_server}/missing.html") == 404


def test_perform_survives_a_network_failure(caplog: pytest.LogCaptureFixture) -> None:
    benign.perform(_config(target="127.0.0.1:1"), "web_index")
    assert "failed" in caplog.text


def test_perform_logs_the_result_of_a_ssh_login(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(benign, "ssh_login", lambda *args: True)
    with caplog.at_level("INFO", logger="benign"):
        benign.perform(_config(), "ssh_login")
    assert "ssh_login ok=True" in caplog.text


def test_ssh_login_passes_the_password_through_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class _Result:
        returncode = 0

    def fake_run(command: list[str], **kwargs: Any) -> _Result:
        seen["command"] = command
        seen["env"] = kwargs["env"]
        return _Result()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert benign.ssh_login("victim", "labuser", "secret") is True
    assert seen["env"]["SSHPASS"] == "secret"
    assert "secret" not in seen["command"]


def test_run_stops_when_the_duration_is_over() -> None:
    now = [0.0]
    performed: list[str] = []

    def sleep(seconds: float) -> None:
        now[0] += seconds

    count = benign.run(
        _config(duration=10.0),
        do=lambda _config, action: performed.append(action),
        sleep=sleep,
        clock=lambda: now[0],
    )
    assert count == len(performed) > 0
    assert now[0] >= 10.0


def test_parse_args_reads_the_password_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LAB_SSH_PASSWORD", "secret")
    config = benign.parse_args(["--target", "10.0.0.1", "--seed", "3"])
    assert (config.target, config.password, config.seed) == ("10.0.0.1", "secret", 3)


def test_parse_args_requires_the_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LAB_SSH_PASSWORD", raising=False)
    with pytest.raises(SystemExit):
        benign.parse_args([])


def test_parse_args_rejects_a_non_positive_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAB_SSH_PASSWORD", "secret")
    with pytest.raises(SystemExit):
        benign.parse_args(["--mean-interval", "0"])


def test_main_runs_and_returns_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAB_SSH_PASSWORD", "secret")
    monkeypatch.setattr(benign, "run", lambda config: 0)
    assert benign.main(["--duration", "1"]) == 0

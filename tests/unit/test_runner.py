"""Tests for the scenario runner."""

import ipaddress
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from idslab.lab import runner
from idslab.lab.scenario import Scenario

SUBNET = "172.30.0.0/24"


def _scenario(**changes: Any) -> Scenario:
    values: dict[str, Any] = {
        "name": "port_scan",
        "attack_type": "port_scan",
        "description": "A TCP SYN scan.",
        "target": "victim",
        "command": ["nmap", "-sS", "victim"],
        "timeout": 30.0,
    }
    values.update(changes)
    return Scenario(**values)


def test_run_scenario_rejects_an_empty_command(tmp_path: Path) -> None:

    with pytest.raises(runner.EmptyCommandError, match="no command configured"):
        runner.run_scenario(_scenario(command=[]), SUBNET, tmp_path)


def test_run_scenario_checks_the_target_before_running_anything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from idslab.lab.guard import TargetOutsideLabError

    calls: list[str] = []

    def fake_check_target(target: str, _subnet: str) -> ipaddress.IPv4Address:
        calls.append(target)
        raise TargetOutsideLabError("outside the lab")

    monkeypatch.setattr(runner, "check_target", fake_check_target)

    with pytest.raises(TargetOutsideLabError, match="outside the lab"):
        runner.run_scenario(_scenario(), SUBNET, tmp_path)
    assert calls == ["victim"]


def test_run_scenario_writes_a_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runner, "check_target", lambda *_args: ipaddress.ip_address("172.30.0.10"))

    class _Result:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _Result())

    manifest_path = runner.run_scenario(_scenario(), SUBNET, tmp_path)

    assert manifest_path == tmp_path / "port_scan.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["attack_type"] == "port_scan"
    assert manifest["target_ip"] == "172.30.0.10"
    assert manifest["exit_code"] == 0
    assert manifest["start_time"] <= manifest["end_time"]


def test_run_scenario_records_a_non_zero_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(runner, "check_target", lambda *_args: ipaddress.ip_address("172.30.0.10"))

    class _Result:
        returncode = 1
        stderr = "nmap: command not found"

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _Result())

    manifest_path = runner.run_scenario(_scenario(), SUBNET, tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["exit_code"] == 1

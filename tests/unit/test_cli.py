"""Tests for the idslab command-line entry point."""

from pathlib import Path
from typing import Any

import pytest

from idslab import cli


def test_parse_args_reads_a_scenario_run_command() -> None:
    args = cli.parse_args(["scenario", "run", "configs/scenarios/port_scan.yaml"])
    assert args.command == "scenario"
    assert args.scenario_command == "run"
    assert args.scenario_file == Path("configs/scenarios/port_scan.yaml")


def test_parse_args_requires_a_scenario_file() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["scenario", "run"])


def test_main_runs_the_scenario_and_prints_the_manifest_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_scenario", lambda _path: "a-scenario")

    def fake_run_scenario(scenario: Any, subnet: str, output: Path) -> Path:
        assert scenario == "a-scenario"
        return output / "port_scan.json"

    monkeypatch.setattr(cli, "run_scenario", fake_run_scenario)

    exit_code = cli.main(["scenario", "run", "configs/scenarios/port_scan.yaml"])

    assert exit_code == 0
    assert "port_scan.json" in capsys.readouterr().out

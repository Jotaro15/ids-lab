"""Tests for the idslab command-line entry point."""

import json
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

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


def test_parse_args_reads_a_capture_run_command() -> None:
    args = cli.parse_args(
        ["capture", "run", "--duration", "30", "--output", "data/raw/benign.pcap"]
    )
    assert args.command == "capture"
    assert args.capture_command == "run"
    assert args.interface == "eth0"
    assert args.duration == 30.0
    assert args.output == Path("data/raw/benign.pcap")


def test_main_runs_a_capture_and_prints_the_output_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run_capture(interface: str, duration: float, output: Path) -> Path:
        assert (interface, duration) == ("eth0", 10.0)
        return output

    monkeypatch.setattr(cli, "run_capture", fake_run_capture)

    exit_code = cli.main(["capture", "run", "--duration", "10", "--output", "data/raw/benign.pcap"])

    assert exit_code == 0
    assert "benign.pcap" in capsys.readouterr().out


def test_parse_args_reads_a_flows_build_command() -> None:
    args = cli.parse_args(["flows", "build", "data/raw/a.pcap", "--output", "data/flows/a.csv"])
    assert args.command == "flows"
    assert args.flows_command == "build"
    assert args.pcap_file == Path("data/raw/a.pcap")
    assert args.output == Path("data/flows/a.csv")
    assert args.idle_timeout == 60.0


def test_main_writes_flows_to_a_csv_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pcap = tmp_path / "in.pcap"
    frame = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    frame.time = 100.0
    wrpcap(str(pcap), [frame])
    output = tmp_path / "out" / "flows.csv"

    exit_code = cli.main(["flows", "build", str(pcap), "--output", str(output)])

    assert exit_code == 0
    assert "1 flows" in capsys.readouterr().out
    assert output.read_text(encoding="utf-8").splitlines()[0].startswith("src_ip,")


def test_main_writes_window_features_to_a_csv_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pcap = tmp_path / "in.pcap"
    frames = []
    for index, port in enumerate((22, 80, 443)):
        frame = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234 + index, dport=port)
        frame.time = 100.0 + index
        frames.append(frame)
    wrpcap(str(pcap), frames)
    output = tmp_path / "windows.csv"

    exit_code = cli.main(["windows", "build", str(pcap), "--output", str(output)])

    assert exit_code == 0
    assert "1 windows" in capsys.readouterr().out
    assert output.read_text(encoding="utf-8").splitlines()[1].startswith("10.0.0.1,100.0,3,3,")


def _write_tcp_pcap(path: Path, source: str) -> None:
    frames = []
    for index, port in enumerate((22, 80, 443)):
        frame = Ether() / IP(src=source, dst="10.0.0.2") / TCP(sport=1234 + index, dport=port)
        frame.time = 100.0 + index
        frames.append(frame)
    wrpcap(str(path), frames)


def _write_manifest(directory: Path, attacker_ip: str) -> None:
    directory.mkdir()
    manifest = {
        "name": "scan",
        "attack_type": "port_scan",
        "target": "victim",
        "attacker_ip": attacker_ip,
        "target_ip": "10.0.0.2",
        "start_time": 99.0,
        "end_time": 103.0,
        "exit_code": 0,
    }
    (directory / "scan.json").write_text(json.dumps(manifest), encoding="utf-8")


def _build_windows(tmp_path: Path, *extra: str) -> list[str]:
    pcap = tmp_path / "in.pcap"
    _write_tcp_pcap(pcap, "10.0.0.1")
    output = tmp_path / "windows.csv"
    cli.main(["windows", "build", str(pcap), "--output", str(output), *extra])
    return output.read_text(encoding="utf-8").splitlines()


def test_windows_are_labelled_from_the_manifests(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "manifests", attacker_ip="10.0.0.1")

    lines = _build_windows(tmp_path, "--manifests", str(tmp_path / "manifests"))

    assert lines[0].endswith(",label")
    assert lines[1].endswith(",port_scan")


def test_windows_from_another_source_are_labelled_benign(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "manifests", attacker_ip="10.0.0.99")

    lines = _build_windows(tmp_path, "--manifests", str(tmp_path / "manifests"))

    assert lines[1].endswith(",benign")


def test_windows_have_an_empty_label_without_manifests(tmp_path: Path) -> None:
    lines = _build_windows(tmp_path)

    assert lines[1].endswith(",")

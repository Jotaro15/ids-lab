"""Tests for the idslab command-line entry point."""

import json
import random
import shutil
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from idslab import cli
from idslab.features.windows import WindowFeatures, write_windows_csv


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


def test_detect_writes_one_alert_per_suspicious_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pcap = tmp_path / "scan.pcap"
    frames = []
    for port in range(1, 31):
        frame = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000 + port, dport=port)
        frame.time = 100.0 + port * 0.01
        frames.append(frame)
    wrpcap(str(pcap), frames)
    rules = Path(__file__).parents[2] / "configs" / "rules.yaml"
    output = tmp_path / "out" / "alerts.jsonl"

    exit_code = cli.main(["detect", str(pcap), "--rules", str(rules), "--output", str(output)])

    assert exit_code == 0
    assert "1 alerts" in capsys.readouterr().out
    [line] = output.read_text(encoding="utf-8").splitlines()
    alert = json.loads(line)
    assert (alert["src_ip"], alert["attack_type"]) == ("10.0.0.1", "port_scan")


def test_dataset_split_writes_train_and_test_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("a", "b", "c"):
        _write_tcp_pcap(tmp_path / f"{name}.pcap", "10.0.0.1")
        cli.main(
            [
                "windows",
                "build",
                str(tmp_path / f"{name}.pcap"),
                "--output",
                str(tmp_path / f"{name}.csv"),
                "--manifests",
                str(tmp_path),
            ]
        )
    output_dir = tmp_path / "dataset"

    exit_code = cli.main(
        [
            "dataset",
            "split",
            *(str(tmp_path / f"{name}.csv") for name in ("a", "b", "c")),
            "--output-dir",
            str(output_dir),
            "--test-fraction",
            "0.34",
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "train: 2 windows {'benign': 2}" in out
    assert "test: 1 windows {'benign': 1}" in out
    assert (output_dir / "train.csv").is_file()
    assert (output_dir / "test.csv").is_file()


def _synthetic_window(
    label: str, ports: int, flows: int, ratio: float, step: int
) -> WindowFeatures:
    return WindowFeatures(
        src_ip="10.0.0.1",
        window_start=100.0 + 5 * step,
        flow_count=flows,
        distinct_dst_ports=ports,
        distinct_dst_ips=1,
        max_flows_to_one_port=1,
        syn_packets=flows,
        rst_packets=0,
        incomplete_ratio=ratio,
        total_packets=flows * 3,
        total_bytes=flows * 180,
        mean_flow_duration=0.2,
        label=label,
    )


def test_train_saves_both_models_with_their_checksums(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    windows = [_synthetic_window("benign", 1 + n % 2, 3 + n % 3, 0.1, n) for n in range(20)] + [
        _synthetic_window("port_scan", 80 + n, 80 + n, 0.95, n) for n in range(10)
    ]
    train_file = tmp_path / "train.csv"
    with train_file.open("w", newline="", encoding="utf-8") as destination:
        write_windows_csv(windows, destination)
    models = tmp_path / "models"

    exit_code = cli.main(["train", str(train_file), "--output-dir", str(models)])

    assert exit_code == 0
    assert "random_forest.joblib" in capsys.readouterr().out
    for name in ("random_forest.joblib", "isolation_forest.joblib"):
        assert (models / name).is_file()
        assert (models / f"{name}.sha256").is_file()


@pytest.fixture(scope="module")
def trained_models(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Directory with both models, trained once for all the tests of this module."""
    directory = tmp_path_factory.mktemp("trained")
    rng = random.Random(0)  # noqa: S311  # test data, not cryptography
    windows = [
        _synthetic_window("benign", rng.randint(1, 3), rng.randint(2, 8), rng.uniform(0, 0.2), n)
        for n in range(100)
    ] + [_synthetic_window("port_scan", 80 + n, 80 + n, 0.95, n) for n in range(15)]
    train_file = directory / "train.csv"
    with train_file.open("w", newline="", encoding="utf-8") as destination:
        write_windows_csv(windows, destination)
    cli.main(["train", str(train_file), "--output-dir", str(directory / "models")])
    return directory / "models"


def _write_scan_pcap(path: Path) -> None:
    frames = []
    for port in range(1, 121):
        frame = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000 + port, dport=port)
        frame.time = 100.0 + port * 0.01
        frames.append(frame)
    wrpcap(str(path), frames)


@pytest.mark.parametrize("detector", ["random_forest", "isolation_forest"])
def test_predict_flags_a_scan_with_each_model(
    tmp_path: Path, trained_models: Path, detector: str
) -> None:
    models = trained_models
    pcap = tmp_path / "scan.pcap"
    _write_scan_pcap(pcap)
    output = tmp_path / "alerts.jsonl"

    exit_code = cli.main(
        [
            "predict",
            str(pcap),
            "--detector",
            detector,
            "--model-dir",
            str(models),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    [line] = output.read_text(encoding="utf-8").splitlines()
    alert = json.loads(line)
    assert (alert["src_ip"], alert["detector"]) == ("10.0.0.1", detector)


def test_predict_refuses_a_model_that_changed_since_training(
    tmp_path: Path, trained_models: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    models = tmp_path / "models"
    shutil.copytree(trained_models, models)
    model_file = models / "random_forest.joblib"
    model_file.write_bytes(model_file.read_bytes() + b"x")
    pcap = tmp_path / "scan.pcap"
    _write_scan_pcap(pcap)

    exit_code = cli.main(
        [
            "predict",
            str(pcap),
            "--detector",
            "random_forest",
            "--model-dir",
            str(models),
            "--output",
            str(tmp_path / "alerts.jsonl"),
        ]
    )

    assert exit_code == 1
    assert "checksum mismatch" in capsys.readouterr().err


def test_a_missing_input_file_is_reported_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(
        [
            "detect",
            str(tmp_path / "missing.pcap"),
            "--rules",
            str(tmp_path / "rules.yaml"),
            "--output",
            str(tmp_path / "alerts.jsonl"),
        ]
    )

    assert exit_code == 1
    assert capsys.readouterr().err.startswith("error: ")

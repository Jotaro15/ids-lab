"""Command-line entry point for idslab."""

import argparse
import logging
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from idslab.capture import capture_packets as run_capture
from idslab.capture import read_packets
from idslab.detection import detect, load_rules, write_alerts_jsonl
from idslab.features import (
    build_flows,
    build_windows,
    label_windows,
    write_flows_csv,
    write_windows_csv,
)
from idslab.features.flows import DEFAULT_IDLE_TIMEOUT
from idslab.features.windows import DEFAULT_WINDOW_SIZE, WindowFeatures
from idslab.lab.manifest import load_manifests
from idslab.lab.runner import DEFAULT_LAB_SUBNET, run_scenario
from idslab.lab.scenario import load_scenario


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="idslab", description="Network intrusion detection lab toolkit."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scenario_parser = subparsers.add_parser("scenario", help="work with attack scenarios")
    scenario_subparsers = scenario_parser.add_subparsers(dest="scenario_command", required=True)

    run_parser = scenario_subparsers.add_parser(
        "run", help="run a scenario and record its manifest"
    )
    run_parser.add_argument("scenario_file", type=Path, help="path to a scenario YAML file")
    run_parser.add_argument(
        "--output", type=Path, default=Path("data/raw"), help="directory for the manifest file"
    )
    run_parser.add_argument(
        "--lab-subnet", default=DEFAULT_LAB_SUBNET, help="CIDR of the lab network"
    )

    capture_parser = subparsers.add_parser("capture", help="capture lab traffic")
    capture_subparsers = capture_parser.add_subparsers(dest="capture_command", required=True)

    capture_run_parser = capture_subparsers.add_parser(
        "run", help="capture packets on an interface into a pcap file"
    )
    capture_run_parser.add_argument(
        "--interface", default="eth0", help="network interface to capture on"
    )
    capture_run_parser.add_argument(
        "--duration", type=float, required=True, help="how long to capture, in seconds"
    )
    capture_run_parser.add_argument("--output", type=Path, required=True, help="pcap file to write")

    flows_parser = subparsers.add_parser("flows", help="turn captured packets into flows")
    flows_subparsers = flows_parser.add_subparsers(dest="flows_command", required=True)

    flows_build_parser = flows_subparsers.add_parser(
        "build", help="group the packets of a pcap file into flows and write them as CSV"
    )
    flows_build_parser.add_argument("pcap_file", type=Path, help="pcap file to read")
    flows_build_parser.add_argument("--output", type=Path, required=True, help="CSV file to write")
    flows_build_parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT,
        help="seconds of silence after which a flow is considered over",
    )

    windows_parser = subparsers.add_parser("windows", help="compute per-source window features")
    windows_subparsers = windows_parser.add_subparsers(dest="windows_command", required=True)

    windows_build_parser = windows_subparsers.add_parser(
        "build", help="turn a pcap file into per-source window features, written as CSV"
    )
    windows_build_parser.add_argument("pcap_file", type=Path, help="pcap file to read")
    windows_build_parser.add_argument(
        "--output", type=Path, required=True, help="CSV file to write"
    )
    windows_build_parser.add_argument(
        "--window-size",
        type=float,
        default=DEFAULT_WINDOW_SIZE,
        help="length of a time window, in seconds",
    )
    windows_build_parser.add_argument(
        "--manifests",
        type=Path,
        help="directory of scenario manifests; when given, windows get a ground-truth label",
    )
    windows_build_parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT,
        help="seconds of silence after which a flow is considered over",
    )

    detect_parser = subparsers.add_parser("detect", help="flag attacks in a pcap file with rules")
    detect_parser.add_argument("pcap_file", type=Path, help="pcap file to read")
    detect_parser.add_argument("--rules", type=Path, required=True, help="rules YAML file")
    detect_parser.add_argument(
        "--output", type=Path, required=True, help="JSON Lines file to write the alerts to"
    )
    detect_parser.add_argument(
        "--window-size",
        type=float,
        default=DEFAULT_WINDOW_SIZE,
        help="length of a time window, in seconds",
    )
    detect_parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT,
        help="seconds of silence after which a flow is considered over",
    )
    return parser


def _write_text(path: Path, write: Callable[[TextIO], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        write(destination)


def _windows_from_pcap(args: argparse.Namespace) -> list[WindowFeatures]:
    flows = build_flows(read_packets(args.pcap_file), args.idle_timeout)
    return build_windows(flows, args.window_size)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    return _build_parser().parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point installed as the `idslab` console script."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args(argv)

    if args.command == "scenario" and args.scenario_command == "run":
        scenario = load_scenario(args.scenario_file)
        manifest_path = run_scenario(scenario, args.lab_subnet, args.output)
        print(f"wrote {manifest_path}")
        return 0

    if args.command == "capture" and args.capture_command == "run":
        output_path = run_capture(args.interface, args.duration, args.output)
        print(f"wrote {output_path}")
        return 0

    if args.command == "flows" and args.flows_command == "build":
        flows = build_flows(read_packets(args.pcap_file), args.idle_timeout)
        _write_text(args.output, lambda out: write_flows_csv(flows, out))
        print(f"wrote {len(flows)} flows to {args.output}")
        return 0

    if args.command == "windows" and args.windows_command == "build":
        windows = _windows_from_pcap(args)
        if args.manifests is not None:
            windows = label_windows(windows, load_manifests(args.manifests), args.window_size)
        _write_text(args.output, lambda out: write_windows_csv(windows, out))
        print(f"wrote {len(windows)} windows to {args.output}")
        return 0

    if args.command == "detect":
        rules = load_rules(args.rules)
        alerts = detect(_windows_from_pcap(args), rules)
        _write_text(args.output, lambda out: write_alerts_jsonl(alerts, out))
        print(f"wrote {len(alerts)} alerts to {args.output}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

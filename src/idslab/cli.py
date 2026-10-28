"""Command-line entry point for idslab."""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from idslab.capture import capture_packets as run_capture
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
    return parser


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

    return 1


if __name__ == "__main__":
    sys.exit(main())

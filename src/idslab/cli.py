"""Command-line entry point for idslab."""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

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

    return 1


if __name__ == "__main__":
    sys.exit(main())

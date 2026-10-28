"""Runs a scenario: validates its target, executes it, and records a manifest.

The manifest is what later turns raw capture time into labelled data: it says
which attack type ran, against which address, and when it started and ended.
"""

import json
import logging
import subprocess  # nosec B404  # only ever called with a reviewed command, never a shell
import time
from pathlib import Path

from idslab.lab.guard import check_target
from idslab.lab.scenario import Scenario

logger = logging.getLogger("runner")

DEFAULT_LAB_SUBNET = "172.30.0.0/24"


class EmptyCommandError(Exception):
    """Raised when a scenario has no command configured yet."""


def run_scenario(scenario: Scenario, lab_subnet: str, output_dir: Path) -> Path:
    """Validate the target, run the scenario's command, and write its manifest.

    Args:
        scenario: The scenario to run.
        lab_subnet: The lab network, in CIDR notation.
        output_dir: Directory the manifest file is written into.

    Returns:
        Path to the manifest file written.

    Raises:
        EmptyCommandError: If the scenario has no command configured.
        idslab.lab.guard.TargetOutsideLabError: If the target is not inside
            the lab subnet.
    """
    if not scenario.command:
        raise EmptyCommandError(
            f"scenario {scenario.name!r} has no command configured; see configs/scenarios/README.md"
        )

    target_ip = check_target(scenario.target, lab_subnet)
    logger.info("running %s against %s (%s)", scenario.name, scenario.target, target_ip)

    started_at = time.time()
    result = subprocess.run(  # noqa: S603  # nosec B603  # command comes from a reviewed scenario file, no shell
        scenario.command,
        capture_output=True,
        text=True,
        timeout=scenario.timeout,
        check=False,
    )
    ended_at = time.time()

    if result.returncode != 0:
        logger.warning(
            "%s exited with code %d: %s", scenario.name, result.returncode, result.stderr.strip()
        )

    manifest = {
        "name": scenario.name,
        "attack_type": scenario.attack_type,
        "target": scenario.target,
        "target_ip": str(target_ip),
        "start_time": started_at,
        "end_time": ended_at,
        "exit_code": result.returncode,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / f"{scenario.name}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", manifest_path)
    return manifest_path

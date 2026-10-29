"""Runs a scenario: validates its target, executes it, and records a manifest.

The manifest is what later turns raw capture time into labelled data: it says
which attack type ran, from which address, against which address, and when it
started and ended.
"""

import ipaddress
import json
import logging
import socket
import subprocess  # nosec B404  # only ever called with a reviewed command, never a shell
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from idslab.lab.guard import check_target
from idslab.lab.manifest import Manifest
from idslab.lab.scenario import Scenario

logger = logging.getLogger("runner")

DEFAULT_LAB_SUBNET = "172.30.0.0/24"


class EmptyCommandError(Exception):
    """Raised when a scenario has no command configured yet."""


def _local_address_towards(target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return the local address this host uses to reach `target_ip`.

    Connecting a UDP socket only selects a route; it sends no packet.
    """
    family = socket.AF_INET6 if target_ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((str(target_ip), 9))
        return str(sock.getsockname()[0])


def run_scenario(scenario: Scenario, lab_subnet: str, output_dir: Path) -> Path:
    """Validate the target, run the scenario's command, and write its manifest.

    Args:
        scenario: The scenario to run.
        lab_subnet: The lab network, in CIDR notation.
        output_dir: Directory the manifest file is written into. The file is
            named after the scenario and its start time.

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
    attacker_ip = _local_address_towards(target_ip)
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

    manifest = Manifest(
        name=scenario.name,
        attack_type=scenario.attack_type,
        target=scenario.target,
        attacker_ip=attacker_ip,
        target_ip=str(target_ip),
        start_time=started_at,
        end_time=ended_at,
        exit_code=result.returncode,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    # The start time in the name keeps a second run of the same scenario from
    # overwriting the manifest of the first one.
    stamp = datetime.fromtimestamp(started_at, UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = output_dir / f"{scenario.name}_{stamp}.json"
    manifest_path.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
    logger.info("wrote %s", manifest_path)
    return manifest_path

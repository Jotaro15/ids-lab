"""Loading and validating attack scenario files.

A scenario file only describes a scenario: a name, the kind of attack it
represents for labelling purposes, and which host in the lab it targets. The
command that actually carries it out is configured separately for the
scenarios that need an external tool (see `configs/scenarios/README.md`),
which keeps that configuration easy to review on its own.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_REQUIRED_FIELDS = {"name", "attack_type", "description", "target"}


@dataclass(frozen=True, slots=True)
class Scenario:
    """A single attack scenario, as described in a YAML file.

    Attributes:
        name: Short identifier, used as the manifest file name.
        attack_type: Label used by the evaluation step, e.g. "port_scan".
        description: One sentence describing the scenario, for humans.
        target: Host name or IP address inside the lab network to run against.
        command: The command line that carries out the scenario, as a list of
            arguments. Run as-is, with no shell, only after `guard` has
            confirmed the target resolves inside the lab subnet. Empty when
            the scenario file leaves it to be filled in locally.
        timeout: Maximum number of seconds the command may run.
    """

    name: str
    attack_type: str
    description: str
    target: str
    command: list[str]
    timeout: float


def load_scenario(path: Path) -> Scenario:
    """Load and validate a scenario from a YAML file.

    Raises:
        ValueError: If a required field is missing or malformed.
    """
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")

    missing = _REQUIRED_FIELDS - data.keys()
    if missing:
        raise ValueError(f"{path}: missing required field(s): {', '.join(sorted(missing))}")

    command = data.get("command", [])
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ValueError(f"{path}: 'command' must be a list of strings")

    return Scenario(
        name=str(data["name"]),
        attack_type=str(data["attack_type"]),
        description=str(data["description"]),
        target=str(data["target"]),
        command=command,
        timeout=float(data.get("timeout", 60)),
    )

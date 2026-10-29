"""Scenario manifests: the record of when and from where an attack ran.

The scenario runner writes one manifest per run. Labelling reads them back to
tell which captured traffic belongs to an attack.
"""

import json
from dataclasses import dataclass, fields
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Manifest:
    """What happened during one scenario run.

    Attributes:
        name: Name of the scenario that ran.
        attack_type: Label of the attack, e.g. "port_scan".
        target: Host name or address the scenario was aimed at.
        attacker_ip: Address the attack traffic came from.
        target_ip: Address the target resolved to.
        start_time: When the command started, in seconds since the epoch.
        end_time: When the command ended, in seconds since the epoch.
        exit_code: Exit code of the command.
    """

    name: str
    attack_type: str
    target: str
    attacker_ip: str
    target_ip: str
    start_time: float
    end_time: float
    exit_code: int


def load_manifest(path: Path) -> Manifest:
    """Load a manifest from a JSON file.

    Raises:
        ValueError: If the file is not valid JSON, or a field is missing or
            has the wrong type.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")

    missing = {field.name for field in fields(Manifest)} - data.keys()
    if missing:
        raise ValueError(f"{path}: missing field(s): {', '.join(sorted(missing))}")

    try:
        return Manifest(
            name=str(data["name"]),
            attack_type=str(data["attack_type"]),
            target=str(data["target"]),
            attacker_ip=str(data["attacker_ip"]),
            target_ip=str(data["target_ip"]),
            start_time=float(data["start_time"]),
            end_time=float(data["end_time"]),
            exit_code=int(data["exit_code"]),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{path}: invalid field value: {error}") from error


def load_manifests(directory: Path) -> list[Manifest]:
    """Load every `*.json` manifest of a directory, ordered by start time.

    Raises:
        FileNotFoundError: If `directory` does not exist. A mistyped path must
            not silently produce a capture with no attack in it.
        ValueError: If one of the manifests is invalid.
    """
    if not directory.is_dir():
        raise FileNotFoundError(f"manifest directory not found: {directory}")
    manifests = [load_manifest(path) for path in sorted(directory.glob("*.json"))]
    return sorted(manifests, key=lambda manifest: manifest.start_time)

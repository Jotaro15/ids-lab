"""Alerts raised by the detectors."""

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import TextIO


@dataclass(frozen=True, slots=True)
class Alert:
    """A window that a detector considers to be an attack.

    Attributes:
        src_ip: The source address of the suspicious traffic.
        window_start: Start of the window, in seconds since the epoch.
        attack_type: The kind of attack the detector believes it saw.
        detector: What raised the alert: the name of the rule that fired, or of
            the model that flagged the window.
        evidence: The feature values that made the rule fire.
    """

    src_ip: str
    window_start: float
    attack_type: str
    detector: str
    evidence: dict[str, float]


def write_alerts_jsonl(alerts: Iterable[Alert], destination: TextIO) -> None:
    """Write alerts as JSON Lines: one JSON object per line."""
    for alert in alerts:
        destination.write(json.dumps(asdict(alert)) + "\n")

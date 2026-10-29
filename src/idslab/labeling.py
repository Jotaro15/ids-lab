"""Labelling windows from the manifests that scenarios leave behind.

A manifest says who attacked, what kind of attack it was, and when. A window
is labelled as that attack if its source IP is the attacker's and the window
overlaps the attack period. Everything else is benign.
"""

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from idslab.features.windows import WindowFeatures

BENIGN_LABEL = "benign"

_REQUIRED_FIELDS = ("attack_type", "attacker_ip", "start_time", "end_time")


@dataclass(frozen=True, slots=True)
class Manifest:
    """What a scenario run recorded about the attack it carried out.

    Attributes:
        attack_type: The label given to the attack, e.g. "port_scan".
        attacker_ip: Address the attack traffic came from.
        start_time: When the attack started, in seconds since the epoch.
        end_time: When the attack ended, in seconds since the epoch.
    """

    attack_type: str
    attacker_ip: str
    start_time: float
    end_time: float


def load_manifest(path: Path) -> Manifest:
    """Load a manifest written by `idslab scenario run`.

    Raises:
        ValueError: If the file is not a manifest or a required field is missing.
    """
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")

    missing = [name for name in _REQUIRED_FIELDS if name not in data]
    if missing:
        raise ValueError(f"{path}: missing required field(s): {', '.join(missing)}")

    return Manifest(
        attack_type=str(data["attack_type"]),
        attacker_ip=str(data["attacker_ip"]),
        start_time=float(data["start_time"]),
        end_time=float(data["end_time"]),
    )


def label_windows(
    windows: Iterable[WindowFeatures], manifests: Sequence[Manifest], window_size: float
) -> list[str]:
    """Return one label per window, in the same order.

    A window gets the attack type of the first manifest whose attacker sent
    traffic from the window's source IP while the window overlapped the
    attack. Windows matching no manifest are labelled "benign". Windows at
    the edges of an attack are labelled as attack, so labels are slightly
    generous there.

    Args:
        windows: The windows to label.
        manifests: The attacks that took place in the capture.
        window_size: Length of the windows, in seconds.
    """
    return [_label(window, manifests, window_size) for window in windows]


def _label(window: WindowFeatures, manifests: Sequence[Manifest], window_size: float) -> str:
    window_end = window.window_start + window_size
    for manifest in manifests:
        if (
            window.src_ip == manifest.attacker_ip
            and window.window_start < manifest.end_time
            and window_end > manifest.start_time
        ):
            return manifest.attack_type
    return BENIGN_LABEL

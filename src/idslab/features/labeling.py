"""Attaching ground-truth labels to window features.

A window is labelled with an attack type when it comes from the attacking
address and overlaps the time span recorded in a scenario manifest. Everything
else is benign, including traffic from other hosts during an attack.
"""

from collections.abc import Iterable
from dataclasses import replace

from idslab.features.windows import WindowFeatures
from idslab.lab.manifest import Manifest

BENIGN_LABEL = "benign"


def label_windows(
    windows: Iterable[WindowFeatures], manifests: Iterable[Manifest], window_size: float
) -> list[WindowFeatures]:
    """Return copies of `windows` with their `label` filled in.

    A window covers `window_size` seconds from its start. It takes the attack
    type of the first manifest, by start time, whose attacker address matches
    the window's source and whose time span overlaps the window. Labels are
    therefore slightly generous at the edges of an attack: a window that
    overlaps only its first or last moments is still labelled as the attack.

    Args:
        windows: The windows to label.
        manifests: The scenario manifests of the capture.
        window_size: Length of the windows, in seconds.

    Returns:
        The labelled windows, in the same order.
    """
    ordered = sorted(manifests, key=lambda manifest: manifest.start_time)
    return [replace(window, label=_label_of(window, ordered, window_size)) for window in windows]


def _label_of(window: WindowFeatures, manifests: list[Manifest], window_size: float) -> str:
    window_end = window.window_start + window_size
    for manifest in manifests:
        overlaps = window.window_start < manifest.end_time and window_end > manifest.start_time
        if overlaps and window.src_ip == manifest.attacker_ip:
            return manifest.attack_type
    return BENIGN_LABEL

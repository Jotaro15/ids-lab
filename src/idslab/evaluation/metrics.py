"""Scoring a detector's alerts against the ground-truth labels.

Everything is counted per window: a window is positive if it is labelled as
an attack, and a detector scores a hit when it raises an alert for it.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from idslab.detection.alerts import Alert
from idslab.features.labeling import BENIGN_LABEL
from idslab.features.windows import WindowFeatures

_SECONDS_PER_HOUR = 3600.0


@dataclass(frozen=True, slots=True)
class Metrics:
    """How well one detector did on a set of labelled windows.

    Attributes:
        detector: Name of the detector that was scored.
        true_positives: Attack windows that raised an alert.
        false_positives: Benign windows that raised an alert.
        false_negatives: Attack windows that raised no alert.
        true_negatives: Benign windows that raised no alert.
        precision: Share of alerts that were real attacks.
        recall: Share of attack windows that were caught.
        f1: Harmonic mean of precision and recall.
        false_alarms_per_hour: False alarms per hour of normal traffic, where
            each benign window counts as one window length of traffic.
        recall_by_attack: Recall of each attack type taken on its own.
    """

    detector: str
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    false_alarms_per_hour: float
    recall_by_attack: dict[str, float]


def evaluate(
    detector: str,
    windows: Sequence[WindowFeatures],
    alerts: Iterable[Alert],
    window_size: float,
) -> Metrics:
    """Score the alerts of a detector against the labels of the windows.

    Args:
        detector: Name to report the results under.
        windows: The labelled windows the detector looked at.
        alerts: The alerts it raised for them.
        window_size: Length of a window, in seconds.

    Raises:
        ValueError: If a window is unlabelled, the windows hold no benign or
            no attack window (the rates would be meaningless), or an alert
            does not belong to any of the windows.
    """
    alerted = {(alert.src_ip, alert.window_start) for alert in alerts}
    known = {(window.src_ip, window.window_start) for window in windows}
    if alerted - known:
        raise ValueError(f"{detector}: {len(alerted - known)} alert(s) match no window")

    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    attack_totals: dict[str, int] = {}
    attack_hits: dict[str, int] = {}
    for window in windows:
        if window.label is None:
            raise ValueError("cannot evaluate unlabelled windows")
        flagged = (window.src_ip, window.window_start) in alerted
        if window.label == BENIGN_LABEL:
            counts["fp" if flagged else "tn"] += 1
        else:
            counts["tp" if flagged else "fn"] += 1
            attack_totals[window.label] = attack_totals.get(window.label, 0) + 1
            attack_hits[window.label] = attack_hits.get(window.label, 0) + flagged

    benign = counts["fp"] + counts["tn"]
    attacks = counts["tp"] + counts["fn"]
    if benign == 0 or attacks == 0:
        raise ValueError("evaluation needs both benign and attack windows")

    precision = _ratio(counts["tp"], counts["tp"] + counts["fp"])
    recall = _ratio(counts["tp"], attacks)
    return Metrics(
        detector=detector,
        true_positives=counts["tp"],
        false_positives=counts["fp"],
        false_negatives=counts["fn"],
        true_negatives=counts["tn"],
        precision=precision,
        recall=recall,
        f1=_ratio(2 * precision * recall, precision + recall),
        false_alarms_per_hour=counts["fp"] / (benign * window_size / _SECONDS_PER_HOUR),
        recall_by_attack={
            attack: attack_hits[attack] / total for attack, total in sorted(attack_totals.items())
        },
    )


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0

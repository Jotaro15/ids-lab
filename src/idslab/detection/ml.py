"""Detectors that apply trained models to window features."""

from collections.abc import Sequence
from typing import Any

from idslab.detection.alerts import Alert
from idslab.features.labeling import BENIGN_LABEL
from idslab.features.windows import WindowFeatures
from idslab.ml.models import ISOLATION_FOREST, RANDOM_FOREST, feature_matrix

ANOMALY_LABEL = "anomaly"


def detect_with_random_forest(windows: Sequence[WindowFeatures], model: Any) -> list[Alert]:
    """Raise an alert for every window the Random Forest classifies as an attack.

    The alert carries the predicted attack type and the probability the forest
    gives it.
    """
    if not windows:
        return []
    probabilities = model.predict_proba(feature_matrix(windows))
    classes = list(model.classes_)

    alerts = []
    for window, row in zip(windows, probabilities, strict=True):
        best = int(row.argmax())
        if classes[best] != BENIGN_LABEL:
            alerts.append(
                Alert(
                    src_ip=window.src_ip,
                    window_start=window.window_start,
                    attack_type=str(classes[best]),
                    detector=RANDOM_FOREST,
                    evidence={"probability": float(row[best])},
                )
            )
    return alerts


def detect_with_isolation_forest(windows: Sequence[WindowFeatures], model: Any) -> list[Alert]:
    """Raise an alert for every window the Isolation Forest finds unusual.

    The model only knows what normal traffic looks like, so it cannot name the
    attack: the alert's type is "anomaly". The evidence is the anomaly score,
    where lower means more unusual.
    """
    if not windows:
        return []
    matrix = feature_matrix(windows)
    verdicts = model.predict(matrix)
    scores = model.score_samples(matrix)

    return [
        Alert(
            src_ip=window.src_ip,
            window_start=window.window_start,
            attack_type=ANOMALY_LABEL,
            detector=ISOLATION_FOREST,
            evidence={"anomaly_score": float(score)},
        )
        for window, verdict, score in zip(windows, verdicts, scores, strict=True)
        if verdict == -1
    ]

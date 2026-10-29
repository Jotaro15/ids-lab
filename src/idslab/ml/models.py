"""Training the machine learning models.

Two models look at the same window features:

- a Random Forest learns the attack types it was shown, and also recognises
  benign traffic;
- an Isolation Forest learns what normal traffic looks like and flags what is
  unusual, so it can notice an attack type it has never seen.
"""

from collections.abc import Sequence

from sklearn.ensemble import IsolationForest, RandomForestClassifier

from idslab.features.labeling import BENIGN_LABEL
from idslab.features.windows import FEATURE_COLUMNS, WindowFeatures

_TREES = 200

RANDOM_FOREST = "random_forest"
ISOLATION_FOREST = "isolation_forest"


def feature_matrix(windows: Sequence[WindowFeatures]) -> list[list[float]]:
    """Return one row of feature values per window, in `FEATURE_COLUMNS` order."""
    return [[float(getattr(window, name)) for name in FEATURE_COLUMNS] for window in windows]


def train_random_forest(
    windows: Sequence[WindowFeatures], seed: int = 42
) -> RandomForestClassifier:
    """Train a Random Forest to tell benign traffic and each attack type apart.

    Attacks are rare next to normal traffic, so classes are weighted to keep
    the forest from simply predicting "benign" every time.

    Raises:
        ValueError: If a window has no label, or the windows contain a single
            label, which leaves nothing to tell apart.
    """
    labels = [_label_of(window) for window in windows]
    if len(set(labels)) < 2:
        raise ValueError("training a classifier needs at least two different labels")

    model = RandomForestClassifier(n_estimators=_TREES, class_weight="balanced", random_state=seed)
    model.fit(feature_matrix(windows), labels)
    return model


def train_isolation_forest(
    windows: Sequence[WindowFeatures], seed: int = 42, contamination: float = 0.05
) -> IsolationForest:
    """Train an Isolation Forest on the benign windows only.

    Windows of any other label are ignored: the model is meant to learn normal
    traffic and flag whatever differs from it.

    Args:
        windows: Labelled windows; only the benign ones are used.
        seed: Seed for reproducible training.
        contamination: Share of the benign training windows the model is
            allowed to flag, which sets how sensitive it is. An Isolation
            Forest cannot tell a far outlier from the most extreme training
            window, so the threshold has to leave some room beyond the
            normal range. Raising the value catches more attacks and raises
            false alarms on normal traffic by about as much.

    Raises:
        ValueError: If a window has no label, or none of them is benign.
    """
    benign = [window for window in windows if _label_of(window) == BENIGN_LABEL]
    if not benign:
        raise ValueError("training the anomaly detector needs benign windows")

    model = IsolationForest(n_estimators=_TREES, contamination=contamination, random_state=seed)
    model.fit(feature_matrix(benign))
    return model


def _label_of(window: WindowFeatures) -> str:
    if window.label is None:
        raise ValueError("cannot train on an unlabelled window")
    return window.label

"""Preparing labelled windows for machine learning.

Windows from the same capture are strongly related: consecutive windows of one
attack look alike, and a model that sees some of them in training will score
well on their neighbours in the test set without having learned anything
general. The split therefore keeps each capture whole, on one side or the other.
"""

import logging
import random
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from idslab.features.windows import WindowFeatures, read_windows_csv

logger = logging.getLogger("dataset")


@dataclass(frozen=True, slots=True)
class Split:
    """A dataset divided into training and test captures.

    Attributes:
        train: Windows of the training captures, by capture name.
        test: Windows of the test captures, by capture name.
    """

    train: dict[str, list[WindowFeatures]]
    test: dict[str, list[WindowFeatures]]

    @property
    def train_windows(self) -> list[WindowFeatures]:
        """All training windows, captures in name order."""
        return [window for name in sorted(self.train) for window in self.train[name]]

    @property
    def test_windows(self) -> list[WindowFeatures]:
        """All test windows, captures in name order."""
        return [window for name in sorted(self.test) for window in self.test[name]]


def load_labelled_windows(path: Path) -> list[WindowFeatures]:
    """Load a window CSV file in which every window has a label.

    Raises:
        ValueError: If a window has no label, which means the CSV was built
            without `--manifests`.
    """
    windows = read_windows_csv(path)
    if any(window.label is None for window in windows):
        raise ValueError(f"{path}: unlabelled windows; build it with --manifests")
    return windows


def load_captures(paths: Sequence[Path]) -> dict[str, list[WindowFeatures]]:
    """Load labelled window CSV files, one capture per file.

    A capture is named after its file, without the extension.

    Raises:
        ValueError: If two files share a name, or a window has no label.
    """
    captures: dict[str, list[WindowFeatures]] = {}
    for path in paths:
        if path.stem in captures:
            raise ValueError(f"two captures are named {path.stem!r}")
        captures[path.stem] = load_labelled_windows(path)
    return captures


def split_captures(
    captures: dict[str, list[WindowFeatures]], test_fraction: float = 0.3, seed: int = 42
) -> Split:
    """Divide captures into a training and a test set, keeping each one whole.

    The same seed always gives the same split. At least one capture goes to
    each side.

    Args:
        captures: The captures to divide, by name.
        test_fraction: Share of the captures to hold out for testing, strictly
            between 0 and 1. It is rounded to a whole number of captures.
        seed: Seed of the shuffle that picks the test captures.

    Raises:
        ValueError: If `test_fraction` is out of range or there are fewer than
            two captures.
    """
    if not 0 < test_fraction < 1:
        raise ValueError(f"test_fraction must be between 0 and 1, got {test_fraction}")
    if len(captures) < 2:
        raise ValueError(f"need at least 2 captures to split, got {len(captures)}")

    names = sorted(captures)
    random.Random(seed).shuffle(names)  # noqa: S311  # nosec B311  # reproducible split, not security
    test_count = min(max(1, round(len(names) * test_fraction)), len(names) - 1)
    test_names = set(names[:test_count])

    split = Split(
        train={name: captures[name] for name in captures if name not in test_names},
        test={name: captures[name] for name in captures if name in test_names},
    )
    only_in_test = set(label_counts(split.test_windows)) - set(label_counts(split.train_windows))
    if only_in_test:
        logger.warning(
            "labels only present in the test set: %s; add more captures", sorted(only_in_test)
        )
    return split


def label_counts(windows: Iterable[WindowFeatures]) -> Counter[str]:
    """Count the windows of each label. Unlabelled windows are not counted."""
    return Counter(window.label for window in windows if window.label is not None)

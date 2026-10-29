"""Tests for training and storing the machine learning models."""

import hashlib
import random
from pathlib import Path

import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from idslab.features.windows import FEATURE_COLUMNS, WindowFeatures
from idslab.ml import (
    ISOLATION_FOREST,
    RANDOM_FOREST,
    ModelIntegrityError,
    feature_matrix,
    load_model,
    save_model,
    train_isolation_forest,
    train_random_forest,
)
from idslab.ml.persistence import checksum_path


def _window(label: str | None, ports: int, flows: int, ratio: float, step: int) -> WindowFeatures:
    return WindowFeatures(
        src_ip="172.30.0.20",
        window_start=100.0 + 5 * step,
        flow_count=flows,
        distinct_dst_ports=ports,
        distinct_dst_ips=1,
        max_flows_to_one_port=flows if ports == 1 else 1,
        syn_packets=flows,
        rst_packets=0,
        incomplete_ratio=ratio,
        total_packets=flows * 3,
        total_bytes=flows * 180,
        mean_flow_duration=0.2,
        label=label,
    )


def _benign(step: int) -> WindowFeatures:
    # Varied enough that no single benign window is an obvious outlier.
    rng = random.Random(step)  # noqa: S311  # test data, not cryptography
    return _window(
        "benign",
        ports=rng.randint(1, 3),
        flows=rng.randint(2, 8),
        ratio=rng.uniform(0.0, 0.2),
        step=step,
    )


def _scan(step: int) -> WindowFeatures:
    return _window("port_scan", ports=80 + step, flows=80 + step, ratio=0.95, step=step)


def _training_windows() -> list[WindowFeatures]:
    return [_benign(step) for step in range(100)] + [_scan(step) for step in range(15)]


def test_the_feature_matrix_follows_the_feature_columns() -> None:
    window = _scan(0)

    [row] = feature_matrix([window])

    assert len(row) == len(FEATURE_COLUMNS)
    assert row[FEATURE_COLUMNS.index("distinct_dst_ports")] == 80.0
    assert row[FEATURE_COLUMNS.index("incomplete_ratio")] == 0.95


def test_the_random_forest_tells_attacks_from_benign_traffic() -> None:
    model = train_random_forest(_training_windows())

    predictions = model.predict(feature_matrix([_benign(100), _scan(100)]))

    assert list(predictions) == ["benign", "port_scan"]


def test_the_random_forest_needs_two_different_labels() -> None:
    with pytest.raises(ValueError, match="at least two different labels"):
        train_random_forest([_benign(step) for step in range(5)])


def test_training_on_unlabelled_windows_is_rejected() -> None:
    windows = [_window(None, 1, 3, 0.1, 0), _benign(1)]

    with pytest.raises(ValueError, match="unlabelled"):
        train_random_forest(windows)
    with pytest.raises(ValueError, match="unlabelled"):
        train_isolation_forest(windows)


def test_the_isolation_forest_flags_traffic_unlike_the_benign_windows() -> None:
    model = train_isolation_forest(_training_windows(), contamination=0.1)

    verdicts = model.predict(feature_matrix([_benign(100), _scan(100)]))

    assert list(verdicts) == [1, -1]


def test_the_isolation_forest_learns_from_benign_windows_only() -> None:
    with_attacks = train_isolation_forest(_training_windows())
    benign_only = train_isolation_forest([_benign(step) for step in range(100)])

    probe = feature_matrix([_scan(100)])
    assert with_attacks.score_samples(probe)[0] == benign_only.score_samples(probe)[0]


def test_the_isolation_forest_needs_benign_windows() -> None:
    with pytest.raises(ValueError, match="needs benign windows"):
        train_isolation_forest([_scan(step) for step in range(5)])


def test_training_is_reproducible_with_a_seed() -> None:
    first = train_random_forest(_training_windows(), seed=3)
    second = train_random_forest(_training_windows(), seed=3)

    probe = feature_matrix([_benign(7), _scan(7)])
    assert first.predict_proba(probe).tolist() == second.predict_proba(probe).tolist()


def test_a_saved_model_is_loaded_back(tmp_path: Path) -> None:
    model = train_random_forest(_training_windows())
    path = save_model(model, RANDOM_FOREST, tmp_path / "models" / "rf.joblib")

    loaded = load_model(path, RANDOM_FOREST)

    assert isinstance(loaded, RandomForestClassifier)
    probe = feature_matrix([_scan(100)])
    assert list(loaded.predict(probe)) == list(model.predict(probe))


def test_the_checksum_file_matches_the_model_file(tmp_path: Path) -> None:
    path = save_model(
        train_isolation_forest(_training_windows()), ISOLATION_FOREST, tmp_path / "m.joblib"
    )

    recorded = checksum_path(path).read_text(encoding="utf-8").split()

    assert recorded == [hashlib.sha256(path.read_bytes()).hexdigest(), "m.joblib"]
    assert isinstance(load_model(path, ISOLATION_FOREST), IsolationForest)


def test_a_modified_model_file_is_refused(tmp_path: Path) -> None:
    path = save_model(
        train_random_forest(_training_windows()), RANDOM_FOREST, tmp_path / "m.joblib"
    )
    path.write_bytes(path.read_bytes() + b"tampering")

    with pytest.raises(ModelIntegrityError, match="checksum mismatch"):
        load_model(path, RANDOM_FOREST)


def test_a_model_without_a_checksum_file_is_refused(tmp_path: Path) -> None:
    path = save_model(
        train_random_forest(_training_windows()), RANDOM_FOREST, tmp_path / "m.joblib"
    )
    checksum_path(path).unlink()

    with pytest.raises(ModelIntegrityError, match="no checksum file"):
        load_model(path, RANDOM_FOREST)


def test_a_model_of_the_wrong_kind_is_refused(tmp_path: Path) -> None:
    path = save_model(
        train_random_forest(_training_windows()), RANDOM_FOREST, tmp_path / "m.joblib"
    )

    with pytest.raises(ModelIntegrityError, match="expected a isolation_forest model"):
        load_model(path, ISOLATION_FOREST)


def test_a_model_trained_on_other_features_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = save_model(
        train_random_forest(_training_windows()), RANDOM_FOREST, tmp_path / "m.joblib"
    )
    monkeypatch.setattr("idslab.ml.persistence.FEATURE_COLUMNS", [*FEATURE_COLUMNS, "new_feature"])

    with pytest.raises(ModelIntegrityError, match="different features"):
        load_model(path, RANDOM_FOREST)

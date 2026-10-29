"""Tests for preparing windows for machine learning."""

import logging
from pathlib import Path
from typing import Any

import pytest

from idslab.features.windows import WindowFeatures, write_windows_csv
from idslab.ml import label_counts, load_captures, split_captures


def _window(label: str | None, start: float = 100.0) -> WindowFeatures:
    return WindowFeatures(
        src_ip="172.30.0.20",
        window_start=start,
        flow_count=2,
        distinct_dst_ports=2,
        distinct_dst_ips=1,
        max_flows_to_one_port=1,
        syn_packets=2,
        rst_packets=0,
        incomplete_ratio=0.5,
        total_packets=20,
        total_bytes=2000,
        mean_flow_duration=0.25,
        label=label,
    )


def _write_csv(path: Path, windows: list[WindowFeatures]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as destination:
        write_windows_csv(windows, destination)
    return path


def _captures(count: int) -> dict[str, list[WindowFeatures]]:
    return {f"capture{index}": [_window("benign", start=index * 10.0)] for index in range(count)}


def test_captures_are_named_after_their_files(tmp_path: Path) -> None:
    first = _write_csv(tmp_path / "scan.csv", [_window("port_scan"), _window("benign", 105.0)])
    second = _write_csv(tmp_path / "normal.csv", [_window("benign")])

    captures = load_captures([first, second])

    assert list(captures) == ["scan", "normal"]
    assert [window.label for window in captures["scan"]] == ["port_scan", "benign"]


def test_windows_survive_a_trip_through_csv(tmp_path: Path) -> None:
    original = _window("port_scan")

    [loaded] = load_captures([_write_csv(tmp_path / "scan.csv", [original])])["scan"]

    assert loaded == original


def test_unlabelled_windows_are_rejected(tmp_path: Path) -> None:
    path = _write_csv(tmp_path / "raw.csv", [_window(None)])

    with pytest.raises(ValueError, match="unlabelled windows"):
        load_captures([path])


def test_two_captures_with_the_same_name_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = _write_csv(tmp_path / "a" / "scan.csv", [_window("benign")])
    second = _write_csv(tmp_path / "b" / "scan.csv", [_window("benign")])

    with pytest.raises(ValueError, match="two captures are named 'scan'"):
        load_captures([first, second])


def test_a_csv_with_other_columns_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "other.csv"
    path.write_text("a,b\n1,2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected columns"):
        load_captures([path])


def test_a_csv_with_a_bad_value_names_the_file(tmp_path: Path) -> None:
    good = _write_csv(tmp_path / "bad.csv", [_window("benign")])
    good.write_text(
        good.read_text(encoding="utf-8").replace("172.30.0.20,100.0,2", "172.30.0.20,soon,2")
    )

    with pytest.raises(ValueError, match=r"bad\.csv: invalid row"):
        load_captures([good])


def test_a_capture_is_never_split_between_train_and_test() -> None:
    captures = {
        f"capture{index}": [_window("benign", start=float(n)) for n in range(5)]
        for index in range(6)
    }

    split = split_captures(captures, test_fraction=0.5, seed=1)

    assert set(split.train) | set(split.test) == set(captures)
    assert not set(split.train) & set(split.test)
    assert len(split.test) == 3
    assert all(len(windows) == 5 for windows in [*split.train.values(), *split.test.values()])


def test_the_same_seed_gives_the_same_split() -> None:
    captures = _captures(10)

    first = split_captures(captures, seed=7)
    second = split_captures(captures, seed=7)

    assert set(first.test) == set(second.test)


def test_different_seeds_can_pick_different_test_captures() -> None:
    captures = _captures(10)

    chosen = {frozenset(split_captures(captures, seed=seed).test) for seed in range(10)}

    assert len(chosen) > 1


def test_each_side_gets_at_least_one_capture() -> None:
    tiny = split_captures(_captures(2), test_fraction=0.01)
    huge = split_captures(_captures(4), test_fraction=0.99)

    assert (len(tiny.train), len(tiny.test)) == (1, 1)
    assert (len(huge.train), len(huge.test)) == (1, 3)


@pytest.mark.parametrize("fraction", [0.0, 1.0, -0.2, 1.5])
def test_a_test_fraction_outside_the_open_unit_interval_is_rejected(fraction: float) -> None:
    with pytest.raises(ValueError, match="test_fraction"):
        split_captures(_captures(4), test_fraction=fraction)


def test_a_single_capture_cannot_be_split() -> None:
    with pytest.raises(ValueError, match="at least 2 captures"):
        split_captures(_captures(1))


def test_a_label_missing_from_training_is_reported(caplog: pytest.LogCaptureFixture) -> None:
    captures: dict[str, list[WindowFeatures]] = {
        "normal": [_window("benign")],
        "scan": [_window("port_scan")],
    }

    with caplog.at_level(logging.WARNING, logger="dataset"):
        split_captures(captures, test_fraction=0.5)

    assert "only present in the test set" in caplog.text


def test_window_lists_are_ordered_by_capture_name() -> None:
    captures: dict[str, list[WindowFeatures]] = {
        "b": [_window("benign", 2.0)],
        "a": [_window("benign", 1.0)],
        "c": [_window("benign", 3.0)],
    }

    split = split_captures(captures, test_fraction=0.01)

    starts: Any = [window.window_start for window in split.train_windows]
    assert starts == sorted(starts)


def test_labels_are_counted_and_unlabelled_windows_ignored() -> None:
    windows = [_window("benign"), _window("benign"), _window("port_scan"), _window(None)]

    assert label_counts(windows) == {"benign": 2, "port_scan": 1}

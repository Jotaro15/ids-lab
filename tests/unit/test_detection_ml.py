"""Tests for the detectors that apply trained models."""

import random

from idslab.detection import ANOMALY_LABEL, detect_with_isolation_forest, detect_with_random_forest
from idslab.features.windows import WindowFeatures
from idslab.ml import train_isolation_forest, train_random_forest


def _window(label: str | None, ports: int, flows: int, ratio: float, step: int) -> WindowFeatures:
    return WindowFeatures(
        src_ip=f"172.30.0.{20 + step % 5}",
        window_start=100.0 + 5 * step,
        flow_count=flows,
        distinct_dst_ports=ports,
        distinct_dst_ips=1,
        max_flows_to_one_port=1,
        syn_packets=flows,
        rst_packets=0,
        incomplete_ratio=ratio,
        total_packets=flows * 3,
        total_bytes=flows * 180,
        mean_flow_duration=0.2,
        label=label,
    )


def _benign(step: int) -> WindowFeatures:
    rng = random.Random(step)  # noqa: S311  # test data, not cryptography
    return _window("benign", rng.randint(1, 3), rng.randint(2, 8), rng.uniform(0, 0.2), step)


def _scan(step: int) -> WindowFeatures:
    return _window("port_scan", 80 + step, 80 + step, 0.95, step)


def _training_windows() -> list[WindowFeatures]:
    return [_benign(step) for step in range(100)] + [_scan(step) for step in range(15)]


def test_the_random_forest_raises_an_alert_for_each_attack_window() -> None:
    model = train_random_forest(_training_windows())
    windows = [_benign(200), _scan(201), _benign(202)]

    [alert] = detect_with_random_forest(windows, model)

    assert alert.src_ip == windows[1].src_ip
    assert alert.window_start == windows[1].window_start
    assert alert.attack_type == "port_scan"
    assert alert.detector == "random_forest"
    assert 0.5 < alert.evidence["probability"] <= 1.0


def test_the_random_forest_stays_quiet_on_benign_traffic() -> None:
    model = train_random_forest(_training_windows())

    assert detect_with_random_forest([_benign(step) for step in range(300, 320)], model) == []


def test_the_isolation_forest_reports_unusual_windows_as_anomalies() -> None:
    model = train_isolation_forest(_training_windows(), contamination=0.1)
    windows = [_benign(200), _scan(201)]

    [alert] = detect_with_isolation_forest(windows, model)

    assert alert.src_ip == windows[1].src_ip
    assert alert.attack_type == ANOMALY_LABEL
    assert alert.detector == "isolation_forest"
    assert "anomaly_score" in alert.evidence


def test_detectors_handle_an_empty_capture() -> None:
    forest = train_random_forest(_training_windows())
    isolation = train_isolation_forest(_training_windows())

    assert detect_with_random_forest([], forest) == []
    assert detect_with_isolation_forest([], isolation) == []

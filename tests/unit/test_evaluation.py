"""Tests for scoring detectors."""

import io
import json

import pytest

from idslab.detection import Alert
from idslab.evaluation import Metrics, evaluate, format_table, write_report_json
from idslab.features.windows import WindowFeatures


def _window(label: str | None, step: int, src: str = "172.30.0.20") -> WindowFeatures:
    return WindowFeatures(
        src_ip=src,
        window_start=100.0 + 5 * step,
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


def _alert(window: WindowFeatures) -> Alert:
    return Alert(window.src_ip, window.window_start, "port_scan", "rules", {})


def _scenario() -> list[WindowFeatures]:
    """Eight benign windows and four attack windows: three port scan, one syn flood."""
    return (
        [_window("benign", step) for step in range(8)]
        + [_window("port_scan", step) for step in range(8, 11)]
        + [_window("syn_flood", 11)]
    )


def test_counts_and_rates_follow_from_the_alerts() -> None:
    windows = _scenario()
    # 2 of 3 port scans caught, the syn flood missed, 1 false alarm.
    alerts = [_alert(windows[0]), _alert(windows[8]), _alert(windows[9])]

    result = evaluate("rules", windows, alerts, window_size=5.0)

    assert (result.true_positives, result.false_positives) == (2, 1)
    assert (result.false_negatives, result.true_negatives) == (2, 7)
    assert result.precision == pytest.approx(2 / 3)
    assert result.recall == pytest.approx(2 / 4)
    assert result.f1 == pytest.approx(2 * (2 / 3) * 0.5 / (2 / 3 + 0.5))
    assert result.recall_by_attack == {"port_scan": pytest.approx(2 / 3), "syn_flood": 0.0}


def test_false_alarms_are_scaled_to_an_hour_of_normal_traffic() -> None:
    windows = _scenario()
    alerts = [_alert(windows[0]), _alert(windows[1]), _alert(windows[8])]

    result = evaluate("rules", windows, alerts, window_size=5.0)

    # 2 false alarms over 8 benign windows of 5 seconds, which is 40 seconds.
    assert result.false_alarms_per_hour == pytest.approx(2 / (40 / 3600))


def test_a_perfect_detector_scores_one_and_raises_no_false_alarm() -> None:
    windows = _scenario()
    alerts = [_alert(window) for window in windows[8:]]

    result = evaluate("rules", windows, alerts, window_size=5.0)

    assert (result.precision, result.recall, result.f1) == (1.0, 1.0, 1.0)
    assert result.false_alarms_per_hour == 0.0


def test_a_silent_detector_scores_zero_without_dividing_by_zero() -> None:
    result = evaluate("rules", _scenario(), [], window_size=5.0)

    assert (result.precision, result.recall, result.f1) == (0.0, 0.0, 0.0)


def test_windows_of_different_sources_are_told_apart() -> None:
    windows = [
        _window("benign", 0, src="172.30.0.30"),
        _window("port_scan", 0, src="172.30.0.20"),
    ]

    result = evaluate("rules", windows, [_alert(windows[1])], window_size=5.0)

    assert (result.true_positives, result.false_positives) == (1, 0)


def test_an_alert_for_an_unknown_window_is_rejected() -> None:
    stray = Alert("10.9.9.9", 1.0, "port_scan", "rules", {})

    with pytest.raises(ValueError, match="1 alert"):
        evaluate("rules", _scenario(), [stray], window_size=5.0)


def test_unlabelled_windows_are_rejected() -> None:
    with pytest.raises(ValueError, match="unlabelled"):
        evaluate("rules", [_window(None, 0)], [], window_size=5.0)


@pytest.mark.parametrize("label", ["benign", "port_scan"])
def test_both_benign_and_attack_windows_are_required(label: str) -> None:
    windows = [_window(label, step) for step in range(3)]

    with pytest.raises(ValueError, match="both benign and attack"):
        evaluate("rules", windows, [], window_size=5.0)


def _metrics(detector: str) -> Metrics:
    return Metrics(
        detector=detector,
        true_positives=3,
        false_positives=1,
        false_negatives=1,
        true_negatives=9,
        precision=0.75,
        recall=0.75,
        f1=0.75,
        false_alarms_per_hour=12.5,
        recall_by_attack={"port_scan": 1.0, "syn_flood": 0.5},
    )


def test_the_table_has_one_row_per_detector_and_the_recall_by_attack() -> None:
    table = format_table([_metrics("rules"), _metrics("random_forest")])

    lines = table.splitlines()
    assert lines[0].split() == ["detector", "precision", "recall", "f1", "false", "alarms/h"]
    assert lines[2].split() == ["rules", "0.750", "0.750", "0.750", "12.5"]
    assert lines[3].split()[0] == "random_forest"
    assert "rules recall by attack: port_scan 1.00, syn_flood 0.50" in table


def test_the_report_is_written_as_json() -> None:
    destination = io.StringIO()

    write_report_json([_metrics("rules")], destination)

    [entry] = json.loads(destination.getvalue())
    assert entry["detector"] == "rules"
    assert entry["recall_by_attack"] == {"port_scan": 1.0, "syn_flood": 0.5}

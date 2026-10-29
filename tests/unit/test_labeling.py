"""Tests for labelling windows from scenario manifests."""

from idslab.features.labeling import BENIGN_LABEL, label_windows
from idslab.features.windows import WindowFeatures
from idslab.lab.manifest import Manifest

ATTACKER = "172.30.0.20"
CLIENT = "172.30.0.30"
SIZE = 5.0


def _window(start: float, src: str = ATTACKER) -> WindowFeatures:
    return WindowFeatures(
        src_ip=src,
        window_start=start,
        flow_count=1,
        distinct_dst_ports=1,
        distinct_dst_ips=1,
        max_flows_to_one_port=1,
        syn_packets=1,
        rst_packets=0,
        incomplete_ratio=0.0,
        total_packets=3,
        total_bytes=180,
        mean_flow_duration=0.1,
    )


def _manifest(
    attack_type: str = "port_scan",
    start: float = 100.0,
    end: float = 130.0,
    attacker: str = ATTACKER,
) -> Manifest:
    return Manifest(
        name=attack_type,
        attack_type=attack_type,
        target="victim",
        attacker_ip=attacker,
        target_ip="172.30.0.10",
        start_time=start,
        end_time=end,
        exit_code=0,
    )


def _labels(windows: list[WindowFeatures], manifests: list[Manifest]) -> list[str | None]:
    return [window.label for window in label_windows(windows, manifests, SIZE)]


def test_windows_from_the_attacker_during_the_attack_get_its_type() -> None:
    windows = [_window(100.0), _window(110.0), _window(125.0)]

    assert _labels(windows, [_manifest()]) == ["port_scan"] * 3


def test_windows_outside_the_attack_are_benign() -> None:
    windows = [_window(50.0), _window(200.0)]

    assert _labels(windows, [_manifest()]) == [BENIGN_LABEL, BENIGN_LABEL]


def test_other_sources_stay_benign_during_the_attack() -> None:
    assert _labels([_window(110.0, src=CLIENT)], [_manifest()]) == [BENIGN_LABEL]


def test_windows_overlapping_the_edges_of_the_attack_are_labelled() -> None:
    windows = [_window(96.0), _window(129.0)]

    assert _labels(windows, [_manifest()]) == ["port_scan", "port_scan"]


def test_windows_that_only_touch_the_attack_are_benign() -> None:
    windows = [_window(95.0), _window(130.0)]

    assert _labels(windows, [_manifest()]) == [BENIGN_LABEL, BENIGN_LABEL]


def test_each_attack_labels_its_own_period() -> None:
    manifests = [
        _manifest("syn_flood", start=300.0, end=320.0),
        _manifest("port_scan", start=100.0, end=130.0),
    ]

    assert _labels([_window(110.0), _window(305.0), _window(200.0)], manifests) == [
        "port_scan",
        "syn_flood",
        BENIGN_LABEL,
    ]


def test_the_earliest_attack_wins_when_two_overlap_a_window() -> None:
    manifests = [
        _manifest("ssh_brute_force", start=104.0, end=140.0),
        _manifest("port_scan", start=100.0, end=106.0),
    ]

    assert _labels([_window(100.0)], manifests) == ["port_scan"]


def test_without_manifests_everything_is_benign() -> None:
    assert _labels([_window(100.0)], []) == [BENIGN_LABEL]


def test_labelling_returns_copies_and_keeps_the_originals() -> None:
    original = _window(110.0)

    [labelled] = label_windows([original], [_manifest()], SIZE)

    assert original.label is None
    assert labelled.label == "port_scan"
    assert labelled.flow_count == original.flow_count

"""Tests for per-source window features."""

import io

import pytest

from idslab.features.windows import (
    LABEL_COLUMN,
    WINDOW_COLUMNS,
    build_windows,
    write_windows_csv,
)
from idslab.models import Flow

ATTACKER = "10.0.0.9"
CLIENT = "10.0.0.1"
VICTIM = "10.0.0.2"


def _flow(
    start: float,
    src: str = ATTACKER,
    dst: str = VICTIM,
    dst_port: int | None = 80,
    protocol: str = "tcp",
    established: bool = False,
    duration: float = 0.1,
    syn: int = 1,
    rst: int = 0,
) -> Flow:
    return Flow(
        src_ip=src,
        dst_ip=dst,
        src_port=40000,
        dst_port=dst_port,
        protocol=protocol,
        start_time=start,
        end_time=start + duration,
        fwd_packets=2,
        bwd_packets=1,
        fwd_bytes=120,
        bwd_bytes=60,
        syn_packets=syn,
        fin_packets=0,
        rst_packets=rst,
        established=established,
    )


def test_a_port_scan_shows_up_as_many_distinct_ports() -> None:
    scan = [_flow(10.0 + i * 0.01, dst_port=port) for i, port in enumerate(range(20, 40))]

    [window] = build_windows(scan)

    assert window.src_ip == ATTACKER
    assert window.flow_count == 20
    assert window.distinct_dst_ports == 20
    assert window.max_flows_to_one_port == 1
    assert window.incomplete_ratio == 1.0


def test_a_brute_force_shows_up_as_many_flows_to_one_port() -> None:
    attempts = [_flow(10.0 + i * 0.1, dst_port=22, established=True) for i in range(15)]

    [window] = build_windows(attempts)

    assert window.distinct_dst_ports == 1
    assert window.max_flows_to_one_port == 15
    assert window.incomplete_ratio == 0.0


def test_a_flow_belongs_to_the_window_it_started_in() -> None:
    flows = [_flow(4.9), _flow(5.0), _flow(9.99)]

    windows = build_windows(flows, window_size=5.0)

    assert [(w.window_start, w.flow_count) for w in windows] == [(0.0, 1), (5.0, 2)]


def test_each_source_gets_its_own_row() -> None:
    flows = [_flow(1.0, src=ATTACKER), _flow(1.5, src=CLIENT), _flow(2.0, src=CLIENT)]

    windows = build_windows(flows)

    assert {w.src_ip: w.flow_count for w in windows} == {ATTACKER: 1, CLIENT: 2}


def test_windows_are_ordered_by_start_then_source() -> None:
    flows = [_flow(11.0, src=CLIENT), _flow(1.0, src=CLIENT), _flow(1.0, src=ATTACKER)]

    windows = build_windows(flows)

    assert [(w.window_start, w.src_ip) for w in windows] == [
        (0.0, CLIENT),
        (0.0, ATTACKER),
        (10.0, CLIENT),
    ]


def test_counters_are_summed_across_the_flows_of_a_window() -> None:
    flows = [_flow(1.0, syn=1, rst=1, duration=0.2), _flow(2.0, syn=2, rst=0, duration=0.4)]

    [window] = build_windows(flows)

    assert window.syn_packets == 3
    assert window.rst_packets == 1
    assert window.total_packets == 6
    assert window.total_bytes == 360
    assert window.mean_flow_duration == pytest.approx(0.3)


def test_incomplete_ratio_only_counts_tcp_flows() -> None:
    flows = [
        _flow(1.0, established=True),
        _flow(1.1, established=False),
        _flow(1.2, protocol="udp", dst_port=53),
        _flow(1.3, protocol="icmp", dst_port=None),
    ]

    [window] = build_windows(flows)

    assert window.incomplete_ratio == 0.5
    assert window.distinct_dst_ports == 2


def test_a_window_without_tcp_has_a_zero_incomplete_ratio() -> None:
    [window] = build_windows([_flow(1.0, protocol="icmp", dst_port=None)])

    assert window.incomplete_ratio == 0.0
    assert window.distinct_dst_ports == 0


def test_no_flows_make_no_windows() -> None:
    assert build_windows([]) == []


@pytest.mark.parametrize("size", [0.0, -5.0])
def test_a_window_size_that_is_not_positive_is_rejected(size: float) -> None:
    with pytest.raises(ValueError, match="window_size"):
        build_windows([_flow(1.0)], window_size=size)


def test_windows_are_written_as_csv_with_a_header() -> None:
    windows = build_windows([_flow(1.0, dst_port=22)])
    destination = io.StringIO()

    write_windows_csv(windows, destination)

    lines = destination.getvalue().splitlines()
    assert lines[0].split(",") == WINDOW_COLUMNS
    assert lines[1].startswith(f"{ATTACKER},0.0,1,1,1,1,")
    assert len(lines) == 2


def test_labels_are_written_in_an_extra_column() -> None:
    windows = build_windows([_flow(1.0), _flow(11.0)])
    destination = io.StringIO()

    write_windows_csv(windows, destination, labels=["benign", "port_scan"])

    lines = destination.getvalue().splitlines()
    assert lines[0].split(",") == [*WINDOW_COLUMNS, LABEL_COLUMN]
    assert lines[1].endswith(",benign")
    assert lines[2].endswith(",port_scan")


def test_a_label_count_that_does_not_match_the_windows_is_rejected() -> None:
    windows = build_windows([_flow(1.0), _flow(11.0)])

    with pytest.raises(ValueError, match="expected 2 labels, got 1"):
        write_windows_csv(windows, io.StringIO(), labels=["benign"])

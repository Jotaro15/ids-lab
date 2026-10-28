"""Tests for grouping packets into flows."""

import io

from idslab.features.flows import FLOW_COLUMNS, build_flows, write_flows_csv
from idslab.models import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Packet

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"


def _tcp(
    time: float,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    flags: int = TCP_ACK,
    length: int = 60,
) -> Packet:
    return Packet(time, src, dst, sport, dport, "tcp", length, flags)


def test_both_directions_of_a_conversation_land_in_one_flow() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_SYN),
        _tcp(1.1, SERVER, 80, CLIENT, 5000, TCP_SYN | TCP_ACK),
        _tcp(1.2, CLIENT, 5000, SERVER, 80, TCP_ACK),
    ]

    flows = build_flows(packets)

    assert len(flows) == 1
    flow = flows[0]
    assert (flow.src_ip, flow.dst_ip, flow.dst_port) == (CLIENT, SERVER, 80)
    assert (flow.fwd_packets, flow.bwd_packets) == (2, 1)
    assert flow.duration == 1.2 - 1.0


def test_the_first_sender_is_the_flow_source() -> None:
    flows = build_flows([_tcp(1.0, SERVER, 80, CLIENT, 5000), _tcp(1.1, CLIENT, 5000, SERVER, 80)])

    assert flows[0].src_ip == SERVER
    assert flows[0].src_port == 80


def test_bytes_are_counted_per_direction() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80, length=100),
        _tcp(1.1, SERVER, 80, CLIENT, 5000, length=1500),
        _tcp(1.2, CLIENT, 5000, SERVER, 80, length=40),
    ]

    flow = build_flows(packets)[0]

    assert (flow.fwd_bytes, flow.bwd_bytes) == (140, 1500)


def test_a_syn_ack_from_the_destination_marks_the_flow_established() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_SYN),
        _tcp(1.1, SERVER, 80, CLIENT, 5000, TCP_SYN | TCP_ACK),
    ]

    flow = build_flows(packets)[0]

    assert flow.established is True
    assert flow.syn_packets == 1


def test_an_unanswered_syn_is_not_established() -> None:
    flow = build_flows([_tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_SYN)])[0]

    assert flow.established is False
    assert flow.syn_packets == 1


def test_a_reset_answer_counts_as_a_reset_and_not_as_established() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 81, TCP_SYN),
        _tcp(1.1, SERVER, 81, CLIENT, 5000, TCP_RST | TCP_ACK),
    ]

    flow = build_flows(packets)[0]

    assert flow.established is False
    assert flow.rst_packets == 1


def test_fin_packets_are_counted() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_FIN | TCP_ACK),
        _tcp(1.1, SERVER, 80, CLIENT, 5000, TCP_FIN | TCP_ACK),
    ]

    assert build_flows(packets)[0].fin_packets == 2


def test_different_ports_make_different_flows() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_SYN),
        _tcp(1.1, CLIENT, 5001, SERVER, 22, TCP_SYN),
    ]

    assert len(build_flows(packets)) == 2


def test_a_long_silence_starts_a_new_flow() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80),
        _tcp(200.0, CLIENT, 5000, SERVER, 80),
    ]

    flows = build_flows(packets, idle_timeout=60.0)

    assert len(flows) == 2
    assert [flow.start_time for flow in flows] == [1.0, 200.0]


def test_a_short_silence_keeps_the_same_flow() -> None:
    packets = [_tcp(1.0, CLIENT, 5000, SERVER, 80), _tcp(30.0, CLIENT, 5000, SERVER, 80)]

    assert len(build_flows(packets, idle_timeout=60.0)) == 1


def test_flows_are_sorted_by_start_time() -> None:
    packets = [
        _tcp(1.0, CLIENT, 5000, SERVER, 80),
        _tcp(2.0, CLIENT, 5001, SERVER, 22),
        _tcp(3.0, CLIENT, 5000, SERVER, 80),
    ]

    flows = build_flows(packets)

    assert [flow.start_time for flow in flows] == sorted(flow.start_time for flow in flows)


def test_icmp_packets_form_a_flow_without_ports() -> None:
    packets = [
        Packet(1.0, CLIENT, SERVER, None, None, "icmp", 84),
        Packet(1.1, SERVER, CLIENT, None, None, "icmp", 84),
    ]

    flows = build_flows(packets)

    assert len(flows) == 1
    assert flows[0].protocol == "icmp"
    assert flows[0].src_port is None
    assert (flows[0].fwd_packets, flows[0].bwd_packets) == (1, 1)


def test_no_packets_make_no_flows() -> None:
    assert build_flows([]) == []


def test_flows_are_written_as_csv_with_a_header() -> None:
    flows = build_flows([_tcp(1.0, CLIENT, 5000, SERVER, 80, TCP_SYN)])
    destination = io.StringIO()

    write_flows_csv(flows, destination)

    lines = destination.getvalue().splitlines()
    assert lines[0].split(",") == FLOW_COLUMNS
    assert lines[1].startswith(f"{CLIENT},{SERVER},5000,80,tcp,")
    assert len(lines) == 2

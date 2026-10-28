"""Grouping packets into bidirectional flows."""

import csv
from collections.abc import Iterable
from dataclasses import dataclass, fields
from typing import TextIO

from idslab.models import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Flow, Packet

DEFAULT_IDLE_TIMEOUT = 60.0

FLOW_COLUMNS = [field.name for field in fields(Flow)] + ["duration"]

_Endpoint = tuple[str, int]
_FlowKey = tuple[str, _Endpoint, _Endpoint]


@dataclass(slots=True)
class _FlowBuilder:
    """Accumulates the packets of one flow until it is complete."""

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    start_time: float
    end_time: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_packets: int = 0
    fin_packets: int = 0
    rst_packets: int = 0
    established: bool = False

    @classmethod
    def starting_with(cls, packet: Packet) -> "_FlowBuilder":
        return cls(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            start_time=packet.timestamp,
            end_time=packet.timestamp,
        )

    def add(self, packet: Packet) -> None:
        forward = packet.src_ip == self.src_ip and packet.src_port == self.src_port
        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += packet.length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet.length
        self.end_time = max(self.end_time, packet.timestamp)

        if packet.protocol != "tcp":
            return
        flags = packet.tcp_flags
        if flags & TCP_SYN and not flags & TCP_ACK:
            self.syn_packets += 1
        if flags & TCP_SYN and flags & TCP_ACK and not forward:
            self.established = True
        if flags & TCP_FIN:
            self.fin_packets += 1
        if flags & TCP_RST:
            self.rst_packets += 1

    def build(self) -> Flow:
        return Flow(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            start_time=self.start_time,
            end_time=self.end_time,
            fwd_packets=self.fwd_packets,
            bwd_packets=self.bwd_packets,
            fwd_bytes=self.fwd_bytes,
            bwd_bytes=self.bwd_bytes,
            syn_packets=self.syn_packets,
            fin_packets=self.fin_packets,
            rst_packets=self.rst_packets,
            established=self.established,
        )


def _flow_key(packet: Packet) -> _FlowKey:
    """Return the same key for both directions of a conversation."""
    ends = sorted([(packet.src_ip, packet.src_port or 0), (packet.dst_ip, packet.dst_port or 0)])
    return (packet.protocol, ends[0], ends[1])


def build_flows(
    packets: Iterable[Packet], idle_timeout: float = DEFAULT_IDLE_TIMEOUT
) -> list[Flow]:
    """Group packets into bidirectional flows.

    Packets are expected in capture order. A flow ends when no packet has
    been seen for `idle_timeout` seconds; a later packet between the same two
    endpoints starts a new flow, which is how a reused port is told apart
    from the connection that used it before.

    Args:
        packets: The packets to group.
        idle_timeout: Seconds of silence after which a flow is considered over.

    Returns:
        The flows, ordered by start time.
    """
    active: dict[_FlowKey, _FlowBuilder] = {}
    finished: list[Flow] = []

    for packet in packets:
        key = _flow_key(packet)
        builder = active.get(key)
        if builder is not None and packet.timestamp - builder.end_time > idle_timeout:
            finished.append(builder.build())
            builder = None
        if builder is None:
            builder = _FlowBuilder.starting_with(packet)
            active[key] = builder
        builder.add(packet)

    finished.extend(builder.build() for builder in active.values())
    return sorted(finished, key=lambda flow: flow.start_time)


def write_flows_csv(flows: Iterable[Flow], destination: TextIO) -> None:
    """Write flows as CSV, with a header row and one line per flow."""
    writer = csv.DictWriter(destination, fieldnames=FLOW_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for flow in flows:
        row = {name: getattr(flow, name) for name in FLOW_COLUMNS}
        writer.writerow(row)

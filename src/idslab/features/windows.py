"""Summarising flows into per-source time windows.

Detectors do not look at single flows: a port scan or a brute force attack is
only visible when many flows from the same source are seen together. This
module cuts time into fixed windows and computes one row of features per
source IP and window.
"""

import csv
import math
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, fields
from typing import TextIO

from idslab.models import Flow

DEFAULT_WINDOW_SIZE = 5.0

_TCP = "tcp"


@dataclass(frozen=True, slots=True)
class WindowFeatures:
    """Behaviour of one source IP during one time window.

    Attributes:
        src_ip: The source IP address, meaning the side that opened the flows.
        window_start: Start of the window, in seconds since the epoch.
        flow_count: Number of flows started in the window.
        distinct_dst_ports: Number of different destination ports contacted.
        distinct_dst_ips: Number of different destination addresses contacted.
        max_flows_to_one_port: Flows sent to the busiest destination port.
        syn_packets: Total connection attempts (SYN without ACK).
        rst_packets: Total packets with the RST flag set.
        incomplete_ratio: Share of TCP flows whose handshake never completed,
            between 0 and 1. It is 0 when the window has no TCP flow.
        total_packets: Packets sent in both directions.
        total_bytes: Bytes sent in both directions.
        mean_flow_duration: Average flow duration, in seconds.
        label: Ground-truth label ("benign" or an attack type), or None while
            the window has not been labelled.
    """

    src_ip: str
    window_start: float
    flow_count: int
    distinct_dst_ports: int
    distinct_dst_ips: int
    max_flows_to_one_port: int
    syn_packets: int
    rst_packets: int
    incomplete_ratio: float
    total_packets: int
    total_bytes: int
    mean_flow_duration: float
    label: str | None = None


WINDOW_COLUMNS = [field.name for field in fields(WindowFeatures)]


def build_windows(
    flows: Iterable[Flow], window_size: float = DEFAULT_WINDOW_SIZE
) -> list[WindowFeatures]:
    """Group flows by source IP and time window, and compute their features.

    A flow belongs to the window in which it started. Windows with no flow
    are not reported.

    Args:
        flows: The flows to summarise.
        window_size: Length of a window, in seconds. Must be positive.

    Returns:
        One WindowFeatures per source IP and window, ordered by window start
        and then by source IP.

    Raises:
        ValueError: If `window_size` is not positive.
    """
    if window_size <= 0:
        raise ValueError(f"window_size must be positive, got {window_size}")

    groups: defaultdict[tuple[float, str], list[Flow]] = defaultdict(list)
    for flow in flows:
        window_start = math.floor(flow.start_time / window_size) * window_size
        groups[(window_start, flow.src_ip)].append(flow)

    return [
        _summarise(src_ip, window_start, group)
        for (window_start, src_ip), group in sorted(groups.items())
    ]


def _summarise(src_ip: str, window_start: float, flows: list[Flow]) -> WindowFeatures:
    flows_per_port: defaultdict[int | None, int] = defaultdict(int)
    for flow in flows:
        flows_per_port[flow.dst_port] += 1

    tcp_flows = [flow for flow in flows if flow.protocol == _TCP]
    incomplete = sum(1 for flow in tcp_flows if not flow.established)

    return WindowFeatures(
        src_ip=src_ip,
        window_start=window_start,
        flow_count=len(flows),
        distinct_dst_ports=len({flow.dst_port for flow in flows if flow.dst_port is not None}),
        distinct_dst_ips=len({flow.dst_ip for flow in flows}),
        max_flows_to_one_port=max(flows_per_port.values()),
        syn_packets=sum(flow.syn_packets for flow in flows),
        rst_packets=sum(flow.rst_packets for flow in flows),
        incomplete_ratio=incomplete / len(tcp_flows) if tcp_flows else 0.0,
        total_packets=sum(flow.fwd_packets + flow.bwd_packets for flow in flows),
        total_bytes=sum(flow.fwd_bytes + flow.bwd_bytes for flow in flows),
        mean_flow_duration=sum(flow.duration for flow in flows) / len(flows),
    )


def write_windows_csv(windows: Iterable[WindowFeatures], destination: TextIO) -> None:
    """Write window features as CSV, with a header row and one line per window.

    The `label` column is left empty for windows that have not been labelled.
    """
    writer = csv.DictWriter(destination, fieldnames=WINDOW_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for window in windows:
        writer.writerow(asdict(window))

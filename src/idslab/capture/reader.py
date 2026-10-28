"""Reading pcap files into Packet objects."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader

from idslab.models import Packet


def read_packets(path: Path) -> Iterator[Packet]:
    """Read the IPv4 packets of a pcap file, one at a time.

    Frames that are not IPv4, such as ARP, are skipped. The file is read
    lazily, so large captures do not have to fit in memory.

    Args:
        path: The pcap file to read.

    Yields:
        One Packet per IPv4 frame, in file order.
    """
    with PcapReader(str(path)) as reader:
        for frame in reader:
            packet = _to_packet(frame)
            if packet is not None:
                yield packet


def _to_packet(frame: Any) -> Packet | None:
    if IP not in frame:
        return None
    ip = frame[IP]

    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags = 0
    if TCP in frame:
        protocol = "tcp"
        src_port, dst_port = int(frame[TCP].sport), int(frame[TCP].dport)
        tcp_flags = int(frame[TCP].flags)
    elif UDP in frame:
        protocol = "udp"
        src_port, dst_port = int(frame[UDP].sport), int(frame[UDP].dport)
    elif ICMP in frame:
        protocol = "icmp"
    else:
        protocol = "other"

    return Packet(
        timestamp=float(frame.time),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(frame),
        tcp_flags=tcp_flags,
    )

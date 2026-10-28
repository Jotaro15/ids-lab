"""Data classes shared across the package."""

from dataclasses import dataclass

# TCP flag bits, as found in the TCP header.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


@dataclass(frozen=True, slots=True)
class Packet:
    """A single IP packet, reduced to the fields the detectors need.

    Attributes:
        timestamp: Capture time, in seconds since the epoch.
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source port, or None for protocols without ports.
        dst_port: Destination port, or None for protocols without ports.
        protocol: "tcp", "udp", "icmp" or "other".
        length: Size of the whole frame, in bytes.
        tcp_flags: TCP flag bits, 0 for other protocols.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: int = 0


@dataclass(frozen=True, slots=True)
class Flow:
    """A bidirectional conversation between two endpoints.

    The source is whichever side sent the first packet. "Forward" means from
    that side to the other, "backward" means the reverse.

    Attributes:
        src_ip: IP address of the side that started the flow.
        dst_ip: IP address of the other side.
        src_port: Port of the side that started the flow, if any.
        dst_port: Port of the other side, if any.
        protocol: "tcp", "udp", "icmp" or "other".
        start_time: Time of the first packet, in seconds since the epoch.
        end_time: Time of the last packet, in seconds since the epoch.
        fwd_packets: Packets sent from source to destination.
        bwd_packets: Packets sent from destination to source.
        fwd_bytes: Bytes sent from source to destination.
        bwd_bytes: Bytes sent from destination to source.
        syn_packets: Connection attempts: packets with SYN set and ACK clear.
        fin_packets: Packets with the FIN flag set.
        rst_packets: Packets with the RST flag set.
        established: True if the destination answered a SYN with a SYN-ACK.
    """

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    start_time: float
    end_time: float
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    syn_packets: int
    fin_packets: int
    rst_packets: int
    established: bool

    @property
    def duration(self) -> float:
        """Time between the first and the last packet, in seconds."""
        return self.end_time - self.start_time

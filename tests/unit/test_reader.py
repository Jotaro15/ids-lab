"""Tests for reading pcap files."""

from collections.abc import Sequence
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet as ScapyPacket
from scapy.utils import wrpcap

from idslab.capture.reader import read_packets
from idslab.models import TCP_ACK, TCP_SYN


def _write(path: Path, frames: Sequence[ScapyPacket]) -> Path:
    for index, frame in enumerate(frames):
        frame.time = 100.0 + index
    wrpcap(str(path), frames)
    return path


def test_tcp_packets_keep_their_addresses_ports_and_flags(tmp_path: Path) -> None:
    frame = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="SA")
    pcap = _write(tmp_path / "tcp.pcap", [frame])

    packets = list(read_packets(pcap))

    assert len(packets) == 1
    packet = packets[0]
    assert (packet.src_ip, packet.dst_ip) == ("10.0.0.1", "10.0.0.2")
    assert (packet.src_port, packet.dst_port) == (5000, 80)
    assert packet.protocol == "tcp"
    assert packet.tcp_flags == TCP_SYN | TCP_ACK
    assert packet.length == len(frame)
    assert packet.timestamp == 100.0


def test_udp_icmp_and_other_protocols_are_labelled(tmp_path: Path) -> None:
    frames = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=47),
    ]
    pcap = _write(tmp_path / "mixed.pcap", frames)

    packets = list(read_packets(pcap))

    assert [packet.protocol for packet in packets] == ["udp", "icmp", "other"]
    assert (packets[0].src_port, packets[0].dst_port) == (53, 5353)
    assert packets[1].src_port is None
    assert packets[1].tcp_flags == 0


def test_frames_without_an_ip_layer_are_skipped(tmp_path: Path) -> None:
    frames = [
        Ether() / ARP(),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(),
    ]
    pcap = _write(tmp_path / "arp.pcap", frames)

    assert len(list(read_packets(pcap))) == 1

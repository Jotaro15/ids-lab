"""Packet capture and pcap reading for the lab."""

from idslab.capture.capture import CaptureError, capture_packets
from idslab.capture.reader import read_packets

__all__ = ["CaptureError", "capture_packets", "read_packets"]

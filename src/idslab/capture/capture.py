"""Packet capture, run as a thin wrapper around tcpdump.

tcpdump already does reliable, efficient packet capture; this module only
adds a bounded duration and a predictable interface for the rest of the
project to call.
"""

import logging
import subprocess  # nosec B404  # only ever called with a fixed argument list, never a shell
import time
from pathlib import Path

logger = logging.getLogger("capture")

_STARTUP_GRACE = 1.0  # seconds given to tcpdump to open its capture socket
_SHUTDOWN_GRACE = 5.0  # seconds given to tcpdump to flush the pcap file


class CaptureError(Exception):
    """Raised when tcpdump exits on its own before being asked to stop."""


def capture_packets(interface: str, duration: float, output: Path) -> Path:
    """Capture packets on `interface` for `duration` seconds into `output`.

    Starts tcpdump, waits, and stops it with SIGTERM so it flushes the pcap
    file cleanly rather than leaving it truncated.

    `-Z root` keeps tcpdump running as root instead of letting it switch to
    its own "tcpdump" user. That switch would leave the capture process owned
    by another user, which this module could no longer stop or write next to.
    tcpdump still goes through its privilege-drop steps even for root, which
    is why the sensor container is granted CAP_CHOWN, CAP_SETUID and
    CAP_SETGID alongside CAP_NET_RAW.

    Args:
        interface: Network interface to capture on (e.g. "eth0").
        duration: How long to capture, in seconds.
        output: Path of the pcap file to write.

    Returns:
        The path to the pcap file written.

    Raises:
        CaptureError: If tcpdump exits on its own before the duration is up,
            which usually means a bad interface name or a missing capability.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(  # noqa: S603  # nosec B603 B607  # fixed arguments, no shell
        ["tcpdump", "-i", interface, "-Z", "root", "-w", str(output)],  # noqa: S607
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(_STARTUP_GRACE)

    try:
        process.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        pass
    else:
        output_text = process.stdout.read() if process.stdout else ""
        raise CaptureError(f"tcpdump exited early with code {process.returncode}: {output_text}")

    process.terminate()
    try:
        process.wait(timeout=_SHUTDOWN_GRACE)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

    logger.info("captured %.0fs on %s to %s", duration, interface, output)
    return output

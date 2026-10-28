"""Safety check that keeps scenarios confined to the lab network.

A scenario's target is only ever allowed to resolve to an address inside the
lab's own subnet. This is the one control every attack scenario goes through
before anything runs, and it is the single place that logic lives.
"""

import ipaddress
import socket


class TargetOutsideLabError(Exception):
    """Raised when a scenario's target does not resolve inside the lab subnet."""


def check_target(target: str, lab_subnet: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve `target` and confirm it is inside `lab_subnet`.

    Args:
        target: A host name or IP address, as given in a scenario file.
        lab_subnet: The lab network, in CIDR notation (e.g. "172.30.0.0/24").

    Returns:
        The resolved address.

    Raises:
        TargetOutsideLabError: If the target cannot be resolved, or resolves
            to an address outside the lab subnet.
    """
    network = ipaddress.ip_network(lab_subnet)
    try:
        resolved = ipaddress.ip_address(socket.gethostbyname(target))
    except OSError as error:
        raise TargetOutsideLabError(f"could not resolve {target!r}: {error}") from error
    if resolved not in network:
        raise TargetOutsideLabError(
            f"{target!r} resolves to {resolved}, which is outside the lab subnet {network}"
        )
    return resolved

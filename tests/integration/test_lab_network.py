"""Integration tests for the lab network and the victim container.

These tests need Docker and are skipped by default. Run them with:

    pytest -m integration --no-cov
"""

import shutil
import subprocess
from collections.abc import Iterator

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is not installed"),
]

NETWORK = "ids-lab_lab"
VICTIM = "ids-lab-victim"
VICTIM_IP = "172.30.0.10"
IMAGE = "ids-lab/victim:dev"


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a docker command and return its result without raising on failure."""
    return subprocess.run(  # noqa: S603  # fixed arguments, no shell
        ["docker", *args],  # noqa: S607  # docker is looked up on PATH on purpose
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


@pytest.fixture(scope="module", autouse=True)
def lab() -> Iterator[None]:
    """Start the lab for the tests in this module and tear it down afterwards."""
    up = _docker("compose", "up", "-d", "--build", "--wait")
    try:
        assert up.returncode == 0, up.stderr
        yield
    finally:
        _docker("compose", "down", "--volumes")


def test_network_is_internal() -> None:
    result = _docker("network", "inspect", NETWORK, "--format", "{{.Internal}}")
    assert result.stdout.strip() == "true"


def test_victim_is_healthy() -> None:
    result = _docker("inspect", VICTIM, "--format", "{{.State.Health.Status}}")
    assert result.stdout.strip() == "healthy"


def test_victim_publishes_no_ports_on_the_host() -> None:
    result = _docker("inspect", VICTIM, "--format", "{{json .NetworkSettings.Ports}}")
    ports = result.stdout.strip()
    # Exposed but unpublished ports appear as null, published ones as a list.
    assert "HostPort" not in ports


def test_ssh_banner_is_reachable_from_inside_the_lab() -> None:
    # sshd sends its banner as soon as a client connects. `timeout` ends nc,
    # which would otherwise wait for the server to close the connection.
    result = _docker(
        "run", "--rm", "--network", NETWORK, "--entrypoint", "sh",
        IMAGE, "-c", f"timeout 3 nc {VICTIM_IP} 22 < /dev/null",
    )  # fmt: skip
    assert "SSH-2.0-OpenSSH" in result.stdout


def test_victim_is_reachable_from_inside_the_lab() -> None:
    result = _docker(
        "run", "--rm", "--network", NETWORK, "--entrypoint", "wget",
        IMAGE, "-q", "-O", "-", f"http://{VICTIM_IP}/",
    )  # fmt: skip
    assert result.returncode == 0
    assert "ids-lab victim" in result.stdout


def test_lab_has_no_route_to_the_internet() -> None:
    result = _docker(
        "run", "--rm", "--network", NETWORK, "--entrypoint", "wget",
        IMAGE, "-q", "-T", "3", "-O", "-", "http://1.1.1.1/",
    )  # fmt: skip
    assert result.returncode != 0

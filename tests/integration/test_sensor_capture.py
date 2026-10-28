"""Integration test for the sensor's packet capture.

Needs Docker and is skipped by default. Run with:

    pytest -m integration --no-cov
"""

import shutil
import subprocess

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is not installed"),
]


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # fixed arguments, no shell
        ["docker", *args],  # noqa: S607  # docker is looked up on PATH on purpose
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_sensor_captures_victim_traffic(tmp_path_factory: pytest.TempPathFactory) -> None:
    output_dir = tmp_path_factory.mktemp("capture")
    up = _docker("compose", "up", "-d", "--build", "--wait", "victim")
    assert up.returncode == 0, up.stderr
    try:
        run = _docker(
            "compose", "--profile", "capture", "run", "--build", "--rm",
            "-v", f"{output_dir}:/work/data/raw",
            "sensor", "idslab", "capture", "run",
            "--duration", "5", "--output", "data/raw/smoke.pcap",
        )  # fmt: skip
        assert run.returncode == 0, run.stderr
        pcap = output_dir / "smoke.pcap"
        assert pcap.exists()
        assert pcap.stat().st_size > 0
    finally:
        _docker("compose", "down", "--volumes")

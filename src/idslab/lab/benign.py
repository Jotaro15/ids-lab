"""Benign traffic generator for the lab.

It plays the part of ordinary users: web requests and the occasional SSH login
against the victim. This is the normal traffic that the detectors must learn
not to flag.

The module only uses the standard library, so the benign container can run this
single file without installing the rest of the package.
"""

import argparse
import logging
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass

logger = logging.getLogger("benign")

# Relative frequency of each kind of request. Web pages dominate, and a few
# requests hit a missing page, as real visitors do.
ACTION_WEIGHTS: dict[str, float] = {
    "web_index": 0.55,
    "web_page": 0.20,
    "web_missing": 0.10,
    "ssh_login": 0.15,
}

_WEB_PATHS: dict[str, str] = {
    "web_index": "/",
    "web_page": "/index.html",
    "web_missing": "/missing.html",
}


@dataclass(frozen=True, slots=True)
class Config:
    """Settings for one run of the generator.

    Attributes:
        target: Host name or IP address of the victim.
        user: SSH account used for the login requests.
        password: Password of that account.
        mean_interval: Average pause between two requests, in seconds.
        duration: How long to run, in seconds. None means run until stopped.
        seed: Seed for the random generator. None means a different run each time.
    """

    target: str
    user: str
    password: str
    mean_interval: float
    duration: float | None
    seed: int | None


def next_action(rng: random.Random) -> str:
    """Pick the next kind of request according to ACTION_WEIGHTS."""
    names = list(ACTION_WEIGHTS)
    return rng.choices(names, weights=list(ACTION_WEIGHTS.values()))[0]


def http_get(url: str, timeout: float = 5.0) -> int:
    """Fetch a URL and return the HTTP status code.

    An error status such as 404 is a normal answer here, not a failure.
    """
    try:
        # The URL is built from the lab target, never from outside input.
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            response.read()
            return int(response.status)
    except urllib.error.HTTPError as error:
        return error.code


def ssh_login(target: str, user: str, password: str, timeout: float = 15.0) -> bool:
    """Open an SSH session, run a no-op command and close it.

    Returns:
        True if the login succeeded.
    """
    # Host keys change every time the lab is rebuilt, so they are not checked.
    # The password goes through the environment to keep it out of the process list.
    result = subprocess.run(  # noqa: S603  # fixed arguments, no shell
        [  # noqa: S607  # sshpass is looked up on PATH inside the container
            "sshpass", "-e", "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=5",
            f"{user}@{target}",
            "true",
        ],
        env={**os.environ, "SSHPASS": password},
        capture_output=True,
        timeout=timeout,
        check=False,
    )  # fmt: skip
    return result.returncode == 0


def perform(config: Config, action: str) -> None:
    """Carry out one request. Failures are logged and never stop the generator."""
    try:
        if action == "ssh_login":
            ok = ssh_login(config.target, config.user, config.password)
            logger.info("%s ok=%s", action, ok)
        else:
            status = http_get(f"http://{config.target}{_WEB_PATHS[action]}")
            logger.info("%s status=%d", action, status)
    except (OSError, subprocess.SubprocessError) as error:
        logger.warning("%s failed: %s", action, error)


def run(
    config: Config,
    *,
    do: Callable[[Config, str], None] = perform,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Generate traffic until the duration is over, or forever if there is none.

    Args:
        config: Settings for this run.
        do: Function that performs one request. Replaced in tests.
        sleep: Function that pauses. Replaced in tests.
        clock: Function that returns a monotonic time. Replaced in tests.

    Returns:
        The number of requests made.
    """
    rng = random.Random(config.seed)  # noqa: S311  # simulation, not cryptography
    deadline = None if config.duration is None else clock() + config.duration
    count = 0
    while deadline is None or clock() < deadline:
        do(config, next_action(rng))
        count += 1
        # Exponential pauses give the irregular rhythm of real users.
        sleep(rng.expovariate(1 / config.mean_interval))
    return count


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return value


def parse_args(argv: Sequence[str] | None = None) -> Config:
    """Build a Config from command-line arguments and the environment."""
    parser = argparse.ArgumentParser(description="Generate benign traffic for the lab.")
    parser.add_argument("--target", default="victim", help="victim host name or IP address")
    parser.add_argument("--user", default="labuser", help="SSH account")
    parser.add_argument(
        "--mean-interval", type=_positive_float, default=1.0,
        help="average pause between requests, in seconds",
    )  # fmt: skip
    parser.add_argument(
        "--duration", type=_positive_float, default=None,
        help="seconds to run (default: until stopped)",
    )  # fmt: skip
    parser.add_argument("--seed", type=int, default=None, help="seed for reproducible traffic")
    args = parser.parse_args(argv)

    password = os.environ.get("LAB_SSH_PASSWORD")
    if not password:
        parser.error("the LAB_SSH_PASSWORD environment variable is required")
    return Config(
        target=args.target,
        user=args.user,
        password=password,
        mean_interval=args.mean_interval,
        duration=args.duration,
        seed=args.seed,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    config = parse_args(argv)
    try:
        run(config)
    except KeyboardInterrupt:
        logger.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Tests for the lab-only target guard."""

import ipaddress
import socket

import pytest

from idslab.lab import guard

SUBNET = "172.30.0.0/24"


def test_check_target_accepts_an_address_inside_the_subnet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda _name: "172.30.0.10")
    assert guard.check_target("victim", SUBNET) == ipaddress.ip_address("172.30.0.10")


def test_check_target_accepts_a_bare_ip_address() -> None:
    assert guard.check_target("172.30.0.10", SUBNET) == ipaddress.ip_address("172.30.0.10")


def test_check_target_rejects_an_address_outside_the_subnet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda _name: "8.8.8.8")
    with pytest.raises(guard.TargetOutsideLabError, match="outside the lab subnet"):
        guard.check_target("not-the-lab", SUBNET)


def test_check_target_rejects_a_name_that_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_name: str) -> str:
        raise OSError("name or service not known")

    monkeypatch.setattr(socket, "gethostbyname", fail)
    with pytest.raises(guard.TargetOutsideLabError, match="could not resolve"):
        guard.check_target("nowhere.example.com", SUBNET)

"""Smoke test: the package imports and reports a version."""

import idslab


def test_package_exposes_a_version() -> None:
    assert idslab.__version__

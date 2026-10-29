"""Tests for loading scenario manifests."""

import json
from pathlib import Path
from typing import Any

import pytest

from idslab.lab.manifest import Manifest, load_manifest, load_manifests


def _data(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "port_scan",
        "attack_type": "port_scan",
        "target": "victim",
        "attacker_ip": "172.30.0.20",
        "target_ip": "172.30.0.10",
        "start_time": 100.0,
        "end_time": 130.5,
        "exit_code": 0,
    }
    data.update(changes)
    return data


def _write(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_manifest_is_loaded_from_json(tmp_path: Path) -> None:
    manifest = load_manifest(_write(tmp_path / "m.json", _data()))

    assert manifest == Manifest(
        name="port_scan",
        attack_type="port_scan",
        target="victim",
        attacker_ip="172.30.0.20",
        target_ip="172.30.0.10",
        start_time=100.0,
        end_time=130.5,
        exit_code=0,
    )


def test_invalid_json_is_reported_with_the_file_name(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match=r"broken\.json: not valid JSON"):
        load_manifest(path)


def test_a_manifest_must_be_a_json_object(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="JSON object"):
        load_manifest(_write(tmp_path / "list.json", [1, 2]))


def test_missing_fields_are_listed(tmp_path: Path) -> None:
    data = _data()
    del data["attacker_ip"], data["end_time"]

    with pytest.raises(ValueError, match="attacker_ip, end_time"):
        load_manifest(_write(tmp_path / "m.json", data))


def test_a_field_with_the_wrong_type_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid field value"):
        load_manifest(_write(tmp_path / "m.json", _data(start_time="yesterday")))


def test_manifests_of_a_directory_are_ordered_by_start_time(tmp_path: Path) -> None:
    _write(tmp_path / "a.json", _data(name="late", start_time=500.0, end_time=520.0))
    _write(tmp_path / "b.json", _data(name="early", start_time=100.0))
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    manifests = load_manifests(tmp_path)

    assert [manifest.name for manifest in manifests] == ["early", "late"]


def test_an_empty_directory_has_no_manifests(tmp_path: Path) -> None:
    assert load_manifests(tmp_path) == []


def test_a_missing_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="manifest directory not found"):
        load_manifests(tmp_path / "typo")

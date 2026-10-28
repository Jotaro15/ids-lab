"""Tests for loading and validating scenario files."""

from pathlib import Path

import pytest

from idslab.lab.scenario import load_scenario


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "scenario.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_scenario_reads_all_fields(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        name: port_scan
        attack_type: port_scan
        description: A TCP SYN scan.
        target: victim
        timeout: 30
        command: ["nmap", "-sS", "victim"]
        """,
    )
    scenario = load_scenario(path)
    assert scenario.name == "port_scan"
    assert scenario.command == ["nmap", "-sS", "victim"]
    assert scenario.timeout == 30.0


def test_load_scenario_defaults_command_to_empty(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        name: syn_flood
        attack_type: syn_flood
        description: A SYN flood.
        target: victim
        """,
    )
    scenario = load_scenario(path)
    assert scenario.command == []
    assert scenario.timeout == 60.0


def test_load_scenario_rejects_a_missing_field(tmp_path: Path) -> None:
    path = _write(tmp_path, "name: incomplete\ntarget: victim\n")
    with pytest.raises(ValueError, match="missing required field"):
        load_scenario(path)


def test_load_scenario_rejects_a_non_mapping_document(tmp_path: Path) -> None:
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="expected a YAML mapping"):
        load_scenario(path)


def test_load_scenario_rejects_a_command_that_is_not_a_string_list(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        name: bad
        attack_type: bad
        description: Bad command type.
        target: victim
        command: "nmap -sS victim"
        """,
    )
    with pytest.raises(ValueError, match="'command' must be a list of strings"):
        load_scenario(path)

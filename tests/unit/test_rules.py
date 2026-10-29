"""Tests for the rule engine."""

import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from idslab.detection import Alert, detect, load_rules, write_alerts_jsonl
from idslab.detection.rules import Condition, Rule
from idslab.features.windows import WindowFeatures

SHIPPED_RULES = Path(__file__).parents[2] / "configs" / "rules.yaml"


def _window(**changes: Any) -> WindowFeatures:
    values: dict[str, Any] = {
        "src_ip": "172.30.0.20",
        "window_start": 100.0,
        "flow_count": 2,
        "distinct_dst_ports": 2,
        "distinct_dst_ips": 1,
        "max_flows_to_one_port": 1,
        "syn_packets": 2,
        "rst_packets": 0,
        "incomplete_ratio": 0.0,
        "total_packets": 20,
        "total_bytes": 2000,
        "mean_flow_duration": 0.3,
    }
    values.update(changes)
    return WindowFeatures(**values)


def _write_rules(tmp_path: Path, data: Any) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _rule(**changes: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": "scan",
        "attack_type": "port_scan",
        "all_of": [{"feature": "distinct_dst_ports", "at_least": 15}],
    }
    rule.update(changes)
    return rule


def test_a_condition_checks_both_bounds() -> None:
    condition = Condition("flow_count", at_least=2, at_most=4)

    assert [condition.holds_for(_window(flow_count=n)) for n in (1, 2, 4, 5)] == [
        False,
        True,
        True,
        False,
    ]


def test_a_rule_needs_every_condition_to_hold() -> None:
    rule = Rule(
        "scan",
        "port_scan",
        "",
        (Condition("distinct_dst_ports", at_least=15), Condition("incomplete_ratio", at_least=0.5)),
    )

    assert rule.matches(_window(distinct_dst_ports=20, incomplete_ratio=0.9))
    assert not rule.matches(_window(distinct_dst_ports=20, incomplete_ratio=0.1))
    assert not rule.matches(_window(distinct_dst_ports=3, incomplete_ratio=0.9))


def test_rules_are_loaded_from_yaml(tmp_path: Path) -> None:
    rules = load_rules(_write_rules(tmp_path, {"rules": [_rule(description="Many ports.")]}))

    assert rules == [
        Rule("scan", "port_scan", "Many ports.", (Condition("distinct_dst_ports", at_least=15.0),))
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "'rules' list"),
        ({"rules": "nope"}, "'rules' list"),
        ({"rules": ["scan"]}, "must be a mapping"),
        ({"rules": [_rule(color="red")]}, "unknown rule key"),
        ({"rules": [{"name": "scan"}]}, "missing: all_of, attack_type"),
        ({"rules": [_rule(all_of=[])]}, "non-empty 'all_of'"),
        ({"rules": [_rule(all_of=["x"])]}, "must be a mapping"),
        ({"rules": [_rule(all_of=[{"feature": "speed", "at_least": 1}])]}, "unknown feature"),
        ({"rules": [_rule(all_of=[{"feature": "src_ip", "at_least": 1}])]}, "unknown feature"),
        ({"rules": [_rule(all_of=[{"feature": "flow_count"}])]}, "needs 'at_least' or 'at_most'"),
        (
            {"rules": [_rule(all_of=[{"feature": "flow_count", "at_least": "ten"}])]},
            "must be a number",
        ),
        (
            {"rules": [_rule(all_of=[{"feature": "flow_count", "at_least": True}])]},
            "must be a number",
        ),
        (
            {"rules": [_rule(all_of=[{"feature": "flow_count", "at_leats": 5}])]},
            "unknown condition key",
        ),
        ({"rules": [_rule(), _rule()]}, "duplicate rule name"),
    ],
)
def test_invalid_rule_files_are_rejected(tmp_path: Path, data: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_rules(_write_rules(tmp_path, data))


def test_windows_matching_a_rule_raise_an_alert_with_evidence() -> None:
    rules = [
        Rule("scan", "port_scan", "", (Condition("distinct_dst_ports", at_least=15),)),
    ]
    quiet = _window(window_start=95.0)
    noisy = _window(distinct_dst_ports=30)

    alerts = detect([quiet, noisy], rules)

    assert alerts == [
        Alert(
            src_ip="172.30.0.20",
            window_start=100.0,
            attack_type="port_scan",
            detector="scan",
            evidence={"distinct_dst_ports": 30.0},
        )
    ]


def test_the_first_matching_rule_wins() -> None:
    rules = [
        Rule("flood", "syn_flood", "", (Condition("syn_packets", at_least=100),)),
        Rule("scan", "port_scan", "", (Condition("distinct_dst_ports", at_least=15),)),
    ]

    [alert] = detect([_window(syn_packets=500, distinct_dst_ports=30)], rules)

    assert alert.detector == "flood"


def test_no_rules_or_no_windows_raise_no_alerts() -> None:
    assert detect([_window(distinct_dst_ports=99)], []) == []
    assert detect([], [Rule("scan", "port_scan", "", (Condition("flow_count", at_least=1),))]) == []


def test_alerts_are_written_as_json_lines() -> None:
    alert = Alert("172.30.0.20", 100.0, "port_scan", "scan", {"distinct_dst_ports": 30.0})
    destination = io.StringIO()

    write_alerts_jsonl([alert, alert], destination)

    lines = destination.getvalue().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {
        "src_ip": "172.30.0.20",
        "window_start": 100.0,
        "attack_type": "port_scan",
        "detector": "scan",
        "evidence": {"distinct_dst_ports": 30.0},
    }


def _attack_type_with_shipped_rules(window: WindowFeatures) -> str | None:
    alerts = detect([window], load_rules(SHIPPED_RULES))
    return alerts[0].attack_type if alerts else None


def test_the_shipped_rules_catch_a_syn_flood() -> None:
    window = _window(
        flow_count=400,
        distinct_dst_ports=1,
        max_flows_to_one_port=400,
        syn_packets=400,
        incomplete_ratio=1.0,
    )

    assert _attack_type_with_shipped_rules(window) == "syn_flood"


def test_the_shipped_rules_catch_a_port_scan() -> None:
    window = _window(flow_count=100, distinct_dst_ports=100, syn_packets=100, incomplete_ratio=0.95)

    assert _attack_type_with_shipped_rules(window) == "port_scan"


def test_the_shipped_rules_catch_an_ssh_brute_force() -> None:
    window = _window(
        flow_count=40, distinct_dst_ports=1, max_flows_to_one_port=40, incomplete_ratio=0.0
    )

    assert _attack_type_with_shipped_rules(window) == "ssh_brute_force"


def test_the_shipped_rules_leave_ordinary_browsing_alone() -> None:
    window = _window(flow_count=6, distinct_dst_ports=2, max_flows_to_one_port=5)

    assert _attack_type_with_shipped_rules(window) is None

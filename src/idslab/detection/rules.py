"""A rule engine that flags windows whose features cross fixed thresholds.

Rules live in a YAML file so that thresholds can be reviewed and tuned without
touching the code. A rule fires when every one of its conditions holds.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from idslab.detection.alerts import Alert
from idslab.features.windows import FEATURE_COLUMNS, WindowFeatures

FEATURE_NAMES = frozenset(FEATURE_COLUMNS)

_RULE_KEYS = {"name", "attack_type", "description", "all_of"}
_CONDITION_KEYS = {"feature", "at_least", "at_most"}


@dataclass(frozen=True, slots=True)
class Condition:
    """A bound on one window feature.

    Attributes:
        feature: Name of a numeric field of WindowFeatures.
        at_least: The feature must be greater than or equal to this, if set.
        at_most: The feature must be less than or equal to this, if set.
    """

    feature: str
    at_least: float | None = None
    at_most: float | None = None

    def holds_for(self, window: WindowFeatures) -> bool:
        """Return True if the window's value for the feature is within bounds."""
        value = float(getattr(window, self.feature))
        if self.at_least is not None and value < self.at_least:
            return False
        return self.at_most is None or value <= self.at_most


@dataclass(frozen=True, slots=True)
class Rule:
    """A named detection rule.

    Attributes:
        name: Short identifier, reported in alerts.
        attack_type: The attack the rule is meant to catch.
        description: One sentence on what the rule looks for.
        conditions: Every condition must hold for the rule to fire.
    """

    name: str
    attack_type: str
    description: str
    conditions: tuple[Condition, ...]

    def matches(self, window: WindowFeatures) -> bool:
        """Return True if all conditions hold for the window."""
        return all(condition.holds_for(window) for condition in self.conditions)


def load_rules(path: Path) -> list[Rule]:
    """Load and validate the rules of a YAML file.

    Raises:
        ValueError: If the file is malformed, a rule or condition is invalid,
            a feature name is unknown, or two rules share a name.
    """
    data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{path}: expected a mapping with a 'rules' list")

    rules = [_parse_rule(path, entry) for entry in data["rules"]]
    names = [rule.name for rule in rules]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"{path}: duplicate rule name(s): {', '.join(duplicates)}")
    return rules


def _parse_rule(path: Path, entry: Any) -> Rule:
    if not isinstance(entry, dict):
        raise ValueError(f"{path}: each rule must be a mapping")
    unknown = entry.keys() - _RULE_KEYS
    if unknown:
        raise ValueError(f"{path}: unknown rule key(s): {', '.join(sorted(unknown))}")
    missing = {"name", "attack_type", "all_of"} - entry.keys()
    if missing:
        raise ValueError(f"{path}: rule is missing: {', '.join(sorted(missing))}")

    name = str(entry["name"])
    raw_conditions = entry["all_of"]
    if not isinstance(raw_conditions, list) or not raw_conditions:
        raise ValueError(f"{path}: rule {name!r} needs a non-empty 'all_of' list")

    return Rule(
        name=name,
        attack_type=str(entry["attack_type"]),
        description=str(entry.get("description", "")),
        conditions=tuple(_parse_condition(path, name, raw) for raw in raw_conditions),
    )


def _parse_condition(path: Path, rule_name: str, raw: Any) -> Condition:
    where = f"{path}: rule {rule_name!r}"
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: each condition must be a mapping")
    unknown = raw.keys() - _CONDITION_KEYS
    if unknown:
        raise ValueError(f"{where}: unknown condition key(s): {', '.join(sorted(unknown))}")

    feature = raw.get("feature")
    if feature not in FEATURE_NAMES:
        raise ValueError(f"{where}: unknown feature {feature!r}")
    if "at_least" not in raw and "at_most" not in raw:
        raise ValueError(f"{where}: condition on {feature!r} needs 'at_least' or 'at_most'")

    bounds: dict[str, float | None] = {}
    for key in ("at_least", "at_most"):
        value = raw.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
            raise ValueError(f"{where}: '{key}' on {feature!r} must be a number")
        bounds[key] = None if value is None else float(value)
    return Condition(feature=feature, at_least=bounds["at_least"], at_most=bounds["at_most"])


def detect(windows: Iterable[WindowFeatures], rules: list[Rule]) -> list[Alert]:
    """Check every window against the rules and return the alerts raised.

    Rules are tried in order and the first one that fires wins, so a window
    raises at most one alert. Put the most specific rules first.
    """
    alerts: list[Alert] = []
    for window in windows:
        for rule in rules:
            if rule.matches(window):
                alerts.append(_alert(window, rule))
                break
    return alerts


def _alert(window: WindowFeatures, rule: Rule) -> Alert:
    return Alert(
        src_ip=window.src_ip,
        window_start=window.window_start,
        attack_type=rule.attack_type,
        detector=rule.name,
        evidence={
            condition.feature: float(getattr(window, condition.feature))
            for condition in rule.conditions
        },
    )

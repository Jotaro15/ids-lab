"""Detectors that turn window features into alerts."""

from idslab.detection.alerts import Alert, write_alerts_jsonl
from idslab.detection.ml import (
    ANOMALY_LABEL,
    detect_with_isolation_forest,
    detect_with_random_forest,
)
from idslab.detection.rules import Condition, Rule, detect, load_rules

__all__ = [
    "ANOMALY_LABEL",
    "Alert",
    "Condition",
    "Rule",
    "detect",
    "detect_with_isolation_forest",
    "detect_with_random_forest",
    "load_rules",
    "write_alerts_jsonl",
]

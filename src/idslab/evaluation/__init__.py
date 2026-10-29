"""Scoring detectors against ground-truth labels."""

from idslab.evaluation.metrics import Metrics, evaluate
from idslab.evaluation.report import format_table, write_report_json

__all__ = ["Metrics", "evaluate", "format_table", "write_report_json"]

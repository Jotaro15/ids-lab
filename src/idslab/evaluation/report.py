"""Presenting evaluation results."""

import json
from collections.abc import Sequence
from dataclasses import asdict
from typing import TextIO

from idslab.evaluation.metrics import Metrics


def format_table(results: Sequence[Metrics]) -> str:
    """Return the results as a plain-text table, one row per detector."""
    header = f"{'detector':<18}{'precision':>10}{'recall':>8}{'f1':>8}{'false alarms/h':>16}"
    lines = [header, "-" * len(header)]
    for result in results:
        lines.append(
            f"{result.detector:<18}{result.precision:>10.3f}{result.recall:>8.3f}"
            f"{result.f1:>8.3f}{result.false_alarms_per_hour:>16.1f}"
        )

    for result in results:
        by_attack = ", ".join(
            f"{name} {value:.2f}" for name, value in result.recall_by_attack.items()
        )
        lines.append("")
        lines.append(f"{result.detector} recall by attack: {by_attack}")
    return "\n".join(lines)


def write_report_json(results: Sequence[Metrics], destination: TextIO) -> None:
    """Write the results as a JSON list, one object per detector."""
    json.dump([asdict(result) for result in results], destination, indent=2)
    destination.write("\n")

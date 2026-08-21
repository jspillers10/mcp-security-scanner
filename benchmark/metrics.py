"""Metric calculations for benchmark classifications."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def score(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None:
        f1 = round(0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall), 6)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "precision_ci95_wilson": _wilson(tp, tp + fp),
        "recall": recall,
        "recall_ci95_wilson": _wilson(tp, tp + fn),
        "f1": f1,
    }


def summarize(classification: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    matches = classification["matches"]
    false_positives = classification["false_positives"]
    false_negatives = classification["false_negatives"]
    overall = score(len(matches), len(false_positives), len(false_negatives))

    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for item in matches:
        counts[item["rule_id"]]["tp"] += 1
    for item in false_positives:
        counts[item["rule_id"]]["fp"] += 1
    for item in false_negatives:
        counts[item["rule_id"]]["fn"] += 1

    by_rule = {rule_id: score(values["tp"], values["fp"], values["fn"]) for rule_id, values in sorted(counts.items())}
    return {"overall": overall, "by_rule": by_rule}

"""Threshold calibration utilities for semantic mitigation relevance scoring."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from services.common.config import ROOT_DIR, load_yaml_config
from services.common.models import CalibrationPair, CalibrationReport, ThresholdMetrics
from services.validation_engine.semantic import SemanticScorer


def load_calibration_pairs(
    relative_path: str = "tests/fixtures/semantic_pairs.json",
) -> list[CalibrationPair]:
    """Load labeled mitigation relevance pairs for threshold calibration."""
    resolved = ROOT_DIR / relative_path
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    return [CalibrationPair.model_validate(item) for item in payload]


async def calibrate_semantic_threshold(
    pairs: list[CalibrationPair] | None = None,
    profile_name: str = "default",
) -> CalibrationReport:
    """Sweep threshold candidates and choose the best operating point for the configured objective."""
    calibration_cfg = load_yaml_config("config/calibration.yaml").get(
        "semantic_threshold_calibration", {}
    )
    threshold_candidates = [
        float(value) for value in calibration_cfg.get("threshold_candidates", [0.72])
    ]
    target_threshold = float(calibration_cfg.get("target_threshold", 0.72))
    objective = str(calibration_cfg.get("objective", "f1"))

    scorer = SemanticScorer(profile_name=profile_name)
    dataset = pairs or load_calibration_pairs()
    similarities = await _score_pairs(scorer, dataset)

    metrics = [
        _metrics_for_threshold(threshold, similarities)
        for threshold in threshold_candidates
    ]
    selected = max(
        metrics,
        key=lambda metric: (
            getattr(metric, objective),
            metric.accuracy,
            -abs(metric.threshold - target_threshold),
        ),
    )
    return CalibrationReport(
        selected_threshold=selected.threshold,
        target_threshold=target_threshold,
        objective=objective,
        metrics=metrics,
        profile_name=profile_name,
    )


async def _score_pairs(
    scorer: SemanticScorer,
    pairs: list[CalibrationPair],
) -> list[tuple[bool, float]]:
    similarities: list[tuple[bool, float]] = []
    for pair in pairs:
        _, similarity = await scorer.similarity(pair.claim_text, [pair.evidence_text])
        similarities.append((pair.label, similarity))
    return similarities


def _metrics_for_threshold(
    threshold: float, similarities: list[tuple[bool, float]]
) -> ThresholdMetrics:
    tp = tn = fp = fn = 0
    for label, similarity in similarities:
        predicted = similarity >= threshold
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif not predicted and label:
            fn += 1
        else:
            tn += 1

    total = max(1, tp + tn + fp + fn)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (
        0.0
        if precision + recall == 0
        else 2 * precision * recall / (precision + recall)
    )
    accuracy = (tp + tn) / total
    return ThresholdMetrics(
        threshold=round(threshold, 2),
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
    )


async def main() -> None:
    """CLI helper for printing the selected calibration threshold."""
    report = await calibrate_semantic_threshold()
    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())

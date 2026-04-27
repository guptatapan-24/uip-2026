"""Unit tests for semantic threshold calibration."""

from __future__ import annotations

import asyncio

from services.common.models import CalibrationPair
from services.validation_engine.calibration import calibrate_semantic_threshold


def test_calibration_returns_threshold_report() -> None:
    report = asyncio.run(
        calibrate_semantic_threshold(
            pairs=[
                CalibrationPair(
                    claim_text="Patch exposed Outlook systems immediately",
                    evidence_text="Patch exposed Outlook systems now to reduce exploitation risk.",
                    label=True,
                ),
                CalibrationPair(
                    claim_text="Disable all outbound traffic for the data center",
                    evidence_text="Patch Outlook systems and rotate credentials.",
                    label=False,
                ),
            ]
        )
    )
    assert 0.0 <= report.selected_threshold <= 1.0
    assert report.metrics

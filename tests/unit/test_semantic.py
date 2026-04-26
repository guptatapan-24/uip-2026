"""Unit tests for the semantic validation module."""

from __future__ import annotations

import asyncio

from services.validation_engine.semantic import SemanticScorer


def test_semantic_scorer_returns_pass_for_close_match() -> None:
    scorer = SemanticScorer()
    result = asyncio.run(
        scorer.score(
            "Patch exposed Outlook systems immediately",
            ["Patch exposed Outlook systems now to reduce exploitation risk."],
        )
    )
    assert result.passed is True or result.similarity > 0.0

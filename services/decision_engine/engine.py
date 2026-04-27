"""Policy-driven decision engine for hallucination firewall outcomes."""

from __future__ import annotations

from collections import defaultdict

from services.common.config import load_profile
from services.common.models import (
    CorrectionCandidate,
    DecisionResult,
    RuleResult,
    RuleSignal,
)


class DecisionEngine:
    """Compute weighted trust scores and map them to actionable outcomes."""

    def __init__(self, profile_name: str = "default") -> None:
        self.profile_name = profile_name
        self.profile = load_profile(profile_name)

    async def decide(self, rule_results: list[RuleResult]) -> DecisionResult:
        """Generate the final decision outcome from validation rule outputs."""
        signal_scores = self._score_signals(rule_results)
        risk_score = round(
            sum(
                float(weight) * signal_scores[signal]
                for signal, weight in self.profile.get("weights", {}).items()
            ),
            4,
        )

        thresholds = self.profile.get("thresholds", {})
        hard_fail_rule_ids = [
            result.rule_id
            for result in rule_results
            if not result.passed
            and (
                result.hard_fail
                or result.rule_id in self.profile.get("hard_fail_rule_ids", [])
            )
        ]

        correction = self._rank_correction_candidates(rule_results)
        if hard_fail_rule_ids or risk_score < float(thresholds.get("flag_min", 0.6)):
            outcome = "CORRECT" if correction is not None else "BLOCK"
        elif risk_score >= float(thresholds.get("allow_min", 0.85)):
            outcome = "ALLOW"
        else:
            outcome = "FLAG"

        rationale = self._build_rationale(
            outcome, risk_score, signal_scores, hard_fail_rule_ids, correction
        )
        return DecisionResult(
            outcome=outcome,
            risk_score=risk_score,
            correction=correction,
            applied_profile=self.profile_name,
            signal_scores=signal_scores,
            hard_fail_rule_ids=hard_fail_rule_ids,
            rationale=rationale,
        )

    def _score_signals(self, rule_results: list[RuleResult]) -> dict[str, float]:
        defaults = self.profile.get("signal_defaults", {})
        scores_by_signal: dict[str, list[float]] = defaultdict(list)
        for result in rule_results:
            if result.signal is None:
                continue
            scores_by_signal[result.signal.value].append(self._rule_score(result))

        signal_scores: dict[str, float] = {}
        for signal in RuleSignal:
            values = scores_by_signal.get(signal.value)
            if values:
                signal_scores[signal.value] = round(sum(values) / len(values), 4)
            else:
                signal_scores[signal.value] = round(
                    float(defaults.get(signal.value, 0.5)), 4
                )
        return signal_scores

    @staticmethod
    def _rule_score(result: RuleResult) -> float:
        return round(
            result.confidence if result.passed else (1.0 - result.confidence), 4
        )

    def _rank_correction_candidates(
        self, rule_results: list[RuleResult]
    ) -> CorrectionCandidate | None:
        correction_cfg = self.profile.get("correction", {})
        min_score = float(correction_cfg.get("min_candidate_score", 0.55))
        scores: dict[str, float] = defaultdict(float)
        support_counts: dict[str, int] = defaultdict(int)
        reasons: dict[str, str] = {}

        for result in rule_results:
            if result.passed:
                continue
            for candidate in result.correction_candidates:
                scores[candidate] += result.confidence
                support_counts[candidate] += 1
                reasons.setdefault(
                    candidate, f"Suggested by {result.rule_id}: {result.evidence}"
                )

        if not scores:
            return None

        ranked_value, ranked_score = max(scores.items(), key=lambda item: item[1])
        normalised = min(1.0, ranked_score / max(1, support_counts[ranked_value]))
        if normalised < min_score:
            return None

        return CorrectionCandidate(
            value=ranked_value, reason=reasons[ranked_value], score=round(normalised, 4)
        )

    @staticmethod
    def _build_rationale(
        outcome: str,
        risk_score: float,
        signal_scores: dict[str, float],
        hard_fail_rule_ids: list[str],
        correction: CorrectionCandidate | None,
    ) -> str:
        message = f"Outcome {outcome} with weighted risk score {risk_score:.2f}."
        if hard_fail_rule_ids:
            message += f" Hard-fail rules triggered: {', '.join(hard_fail_rule_ids)}."
        if correction is not None:
            message += f" Top correction candidate: {correction.value}."
        dominant_signal = max(signal_scores, key=signal_scores.get)
        message += f" Strongest signal: {dominant_signal} ({signal_scores[dominant_signal]:.2f})."
        return message


async def decide(
    rule_results: list[RuleResult], profile_name: str = "default"
) -> DecisionResult:
    """Convenience async wrapper for the decision engine."""
    return await DecisionEngine(profile_name=profile_name).decide(rule_results)

"""Synthetic benchmark and ablation runner for the Tanushree validation stack."""

from __future__ import annotations

import asyncio
import json

from services.claim_extractor.extractor import extract_claims
from services.common.config import ROOT_DIR
from services.common.models import (
    BenchmarkCase,
    BenchmarkRunResult,
    BenchmarkSummary,
    BenchmarkValidationInput,
    ClaimType,
    RuleResult,
    RuleSignal,
)
from services.decision_engine.engine import decide
from services.validation_engine.deterministic import (
    attack_id_valid,
    cve_exists_in_nvd,
    cvss_score_in_range,
    mitigation_maps_to_attack,
    version_in_affected_range,
)
from services.validation_engine.semantic import SemanticScorer


def load_benchmark_cases(relative_path: str = "tests/fixtures/hallucination_benchmark.json") -> list[BenchmarkCase]:
    """Load the synthetic hallucination benchmark dataset."""
    payload = json.loads((ROOT_DIR / relative_path).read_text(encoding="utf-8"))
    return [BenchmarkCase.model_validate(item) for item in payload]


async def run_ablation_suite(profile_name: str = "default") -> list[BenchmarkSummary]:
    """Evaluate the validation stack under the configured ablation scenarios."""
    cases = load_benchmark_cases()
    scenarios = [
        ("baseline_no_firewall", {"baseline": True}),
        ("full_system", {}),
        ("without_deterministic", {"disable_deterministic": True}),
        ("without_semantic", {"disable_semantic": True}),
        ("without_correction", {"disable_correction": True}),
        ("without_urgency", {"disable_urgency": True}),
    ]

    summaries: list[BenchmarkSummary] = []
    for scenario_name, options in scenarios:
        results: list[BenchmarkRunResult] = []
        for case in cases:
            results.append(await _evaluate_case(case, profile_name=profile_name, **options))
        summaries.append(_summarise_results(scenario_name, results))
    return summaries


async def _evaluate_case(
    case: BenchmarkCase,
    profile_name: str = "default",
    baseline: bool = False,
    disable_deterministic: bool = False,
    disable_semantic: bool = False,
    disable_correction: bool = False,
    disable_urgency: bool = False,
) -> BenchmarkRunResult:
    extracted_claims = await extract_claims(case.text)
    extraction_recall = _extraction_recall(extracted_claims, case.expected_claim_types)

    if baseline:
        return BenchmarkRunResult(
            case_id=case.id,
            expected_outcome=case.expected_outcome,
            actual_outcome="ALLOW",
            hallucinated=case.hallucinated,
            extraction_recall=extraction_recall,
            risk_score=1.0,
        )

    rule_results: list[RuleResult] = []
    validation = case.validation

    if not disable_deterministic:
        if validation.cve_id:
            rule_results.append(cve_exists_in_nvd(validation.cve_id, {"cves": validation.known_cves}))
        if validation.claimed_cvss is not None and validation.nvd_cvss is not None:
            rule_results.append(cvss_score_in_range(validation.claimed_cvss, validation.nvd_cvss))
        if validation.technique_id:
            rule_results.append(attack_id_valid(validation.technique_id, {"techniques": validation.known_attack_ids}))
        if validation.version and validation.cpe_list:
            rule_results.append(version_in_affected_range(validation.version, validation.cpe_list))
        if validation.mitigation_text and validation.technique_id:
            rule_results.append(
                mitigation_maps_to_attack(
                    validation.mitigation_text,
                    validation.technique_id,
                    validation.mitigation_mapping_data,
                )
            )

    if not disable_semantic and validation.mitigation_text:
        semantic_result = await SemanticScorer(profile_name=profile_name).score(
            validation.mitigation_text,
            validation.evidence_texts,
        )
        rule_results.append(
            RuleResult(
                rule_id="semantic_mitigation_relevance",
                passed=semantic_result.passed,
                evidence=f"Semantic similarity {semantic_result.similarity:.2f} vs threshold {semantic_result.threshold:.2f}.",
                confidence=semantic_result.similarity if semantic_result.passed else 1.0 - semantic_result.similarity,
                signal=RuleSignal.MITIGATION_RELEVANCE,
            )
        )

    if not disable_urgency:
        rule_results.append(_urgency_rule(validation))

    if disable_correction:
        rule_results = [result.model_copy(update={"correction_candidates": []}) for result in rule_results]

    decision = await decide(rule_results, profile_name=profile_name)
    return BenchmarkRunResult(
        case_id=case.id,
        expected_outcome=case.expected_outcome,
        actual_outcome=decision.outcome,
        hallucinated=case.hallucinated,
        extraction_recall=extraction_recall,
        risk_score=decision.risk_score,
    )


def _urgency_rule(validation: BenchmarkValidationInput) -> RuleResult:
    expected = bool(validation.urgency_expected)
    observed = bool(validation.urgency_text_present)
    passed = expected == observed
    return RuleResult(
        rule_id="urgency_consistency",
        passed=passed,
        evidence=f"Urgency observed={observed}, expected={expected}.",
        confidence=0.92 if passed else 0.88,
        signal=RuleSignal.URGENCY_CONSISTENCY,
    )


def _extraction_recall(extracted_claims: list, expected_claim_types: list[ClaimType]) -> float:
    if not expected_claim_types:
        return 1.0
    extracted_types = {claim.claim_type for claim in extracted_claims}
    matched = sum(1 for claim_type in expected_claim_types if claim_type in extracted_types)
    return round(matched / len(expected_claim_types), 4)


def _summarise_results(scenario_name: str, results: list[BenchmarkRunResult]) -> BenchmarkSummary:
    hallucinated = [result for result in results if result.hallucinated]
    benign = [result for result in results if not result.hallucinated]
    caught = [result for result in hallucinated if result.actual_outcome != "ALLOW"]
    false_approvals = [result for result in hallucinated if result.actual_outcome == "ALLOW"]
    false_blocks = [result for result in benign if result.actual_outcome in {"BLOCK", "CORRECT"}]
    consistent = [result for result in results if result.actual_outcome == result.expected_outcome]
    extraction_recall = sum(result.extraction_recall for result in results) / max(1, len(results))

    return BenchmarkSummary(
        scenario_name=scenario_name,
        case_count=len(results),
        hallucination_catch_rate=round(len(caught) / max(1, len(hallucinated)), 4),
        false_approval_rate=round(len(false_approvals) / max(1, len(hallucinated)), 4),
        false_block_rate=round(len(false_blocks) / max(1, len(benign)), 4),
        decision_consistency=round(len(consistent) / max(1, len(results)), 4),
        extraction_recall=round(extraction_recall, 4),
        results=results,
    )


async def main() -> None:
    """CLI helper for printing the benchmark summaries as JSON."""
    summaries = await run_ablation_suite()
    print(json.dumps([summary.model_dump() for summary in summaries], indent=2))


if __name__ == "__main__":
    asyncio.run(main())

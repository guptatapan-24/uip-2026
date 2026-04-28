"""Deterministic validation rules for CVE, CVSS, ATT&CK, version, and mitigation claims."""

from __future__ import annotations

import re
from typing import Any

from services.common.config import load_yaml_config
from services.common.models import RuleResult, RuleSignal

_CONFIG = load_yaml_config("config/deterministic_rules.yaml").get("deterministic", {})


def cve_exists_in_nvd(cve_id: str, nvd_data: dict[str, Any]) -> RuleResult:
    """Validate that a CVE identifier exists in the provided NVD payload."""
    known_ids = _normalise_cve_ids(nvd_data)
    passed = cve_id.upper() in known_ids
    return RuleResult(
        rule_id="cve_exists_in_nvd",
        passed=passed,
        evidence=f"{cve_id} {'found' if passed else 'not found'} in provided NVD dataset.",
        confidence=_confidence_for(passed),
        signal=RuleSignal.CVE_VALIDITY,
        hard_fail=not passed,
        correction_candidates=sorted(known_ids)[:3] if not passed else [],
        metadata={"known_ids": sorted(known_ids)},
    )


def cvss_score_in_range(claimed_score: float, nvd_score: float) -> RuleResult:
    """Validate that the claimed CVSS score is within the configured tolerance."""
    tolerance = float(_CONFIG.get("cvss_tolerance", 0.3))
    delta = abs(float(claimed_score) - float(nvd_score))
    passed = delta <= tolerance
    return RuleResult(
        rule_id="cvss_score_in_range",
        passed=passed,
        evidence=f"Claimed CVSS {claimed_score:.1f}, authoritative CVSS {nvd_score:.1f}, delta {delta:.1f}.",
        confidence=_confidence_for(
            passed, proximity=max(0.0, 1.0 - (delta / max(tolerance, 0.001)))
        ),
        signal=RuleSignal.SEVERITY_ACCURACY,
        correction_candidates=[f"{nvd_score:.1f}"] if not passed else [],
        metadata={
            "claimed_score": claimed_score,
            "nvd_score": nvd_score,
            "delta": round(delta, 3),
        },
    )


def attack_id_valid(technique_id: str, attack_data: dict[str, Any]) -> RuleResult:
    """Validate ATT&CK technique format and existence in the provided ATT&CK dataset."""
    format_valid = re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id.upper()) is not None
    known_ids = _normalise_attack_ids(attack_data)
    exists = technique_id.upper() in known_ids
    passed = format_valid and exists
    evidence = (
        f"{technique_id} {'matches format and exists' if passed else 'failed format or existence validation'} "
        "in provided ATT&CK dataset."
    )
    return RuleResult(
        rule_id="attack_id_valid",
        passed=passed,
        evidence=evidence,
        confidence=_confidence_for(passed),
        signal=RuleSignal.CVE_VALIDITY,
        hard_fail=not passed and format_valid,
        correction_candidates=sorted(known_ids)[:3] if not passed else [],
        metadata={"format_valid": format_valid, "known_ids": sorted(known_ids)},
    )


def version_in_affected_range(
    version: str, cpe_list: list[str | dict[str, Any]]
) -> RuleResult:
    """Validate whether a version falls in any affected CPE range."""
    version_key = _version_key(version)
    wildcard_versions = set(_CONFIG.get("wildcard_versions", ["*", "-"]))
    matched_entry: str | dict[str, Any] | None = None

    for cpe in cpe_list:
        candidate = _extract_cpe_version(cpe)
        if candidate in wildcard_versions:
            matched_entry = cpe
            break
        if isinstance(cpe, dict) and _dict_range_matches(version_key, cpe):
            matched_entry = cpe
            break
        if candidate and _version_key(candidate) == version_key:
            matched_entry = cpe
            break

    passed = matched_entry is not None
    evidence = f"Version {version} {'falls within' if passed else 'does not fall within'} the affected CPE range."
    return RuleResult(
        rule_id="version_in_affected_range",
        passed=passed,
        evidence=evidence,
        confidence=_confidence_for(passed),
        signal=RuleSignal.CVE_VALIDITY,
        correction_candidates=(
            [_stringify_cpe(candidate) for candidate in cpe_list[:2]]
            if not passed
            else []
        ),
        metadata={
            "matched_entry": (
                _stringify_cpe(matched_entry) if matched_entry is not None else None
            )
        },
    )


def mitigation_maps_to_attack(
    mitigation_text: str,
    technique_id: str,
    mapping_data: dict[str, list[str]] | None = None,
) -> RuleResult:
    """Validate whether a mitigation aligns with the ATT&CK technique's approved mitigation patterns."""
    configured_mappings = _CONFIG.get("mitigation_mappings", {})
    known_mitigations = (mapping_data or configured_mappings).get(
        technique_id.upper(), []
    )
    overlap_threshold = float(_CONFIG.get("mitigation_overlap_threshold", 0.25))
    mitigation_tokens = _normalise_text_tokens(mitigation_text)

    best_match = ""
    best_overlap = 0.0
    for known_mitigation in known_mitigations:
        overlap = _token_overlap(
            mitigation_tokens, _normalise_text_tokens(known_mitigation)
        )
        if overlap > best_overlap:
            best_overlap = overlap
            best_match = known_mitigation

    passed = bool(known_mitigations) and best_overlap >= overlap_threshold
    evidence = f"Mitigation overlap for {technique_id} is {best_overlap:.2f}" + (
        f" against '{best_match}'."
        if best_match
        else " with no mapped mitigation match."
    )
    return RuleResult(
        rule_id="mitigation_maps_to_attack",
        passed=passed,
        evidence=evidence,
        confidence=_confidence_for(passed, proximity=best_overlap),
        signal=RuleSignal.MITIGATION_RELEVANCE,
        correction_candidates=known_mitigations[:3] if not passed else [],
        metadata={"best_match": best_match, "best_overlap": round(best_overlap, 4)},
    )


class DeterministicValidator:
    """Compatibility wrapper that applies the deterministic rules over legacy claim payloads."""

    async def validate(
        self, claims: list[dict[str, Any]], threat_intel: dict[str, Any]
    ) -> list[RuleResult]:
        """Validate legacy claim dictionaries against the supplied threat-intel payload."""
        results: list[RuleResult] = []
        for claim in claims:
            claim_type = str(claim.get("claim_type", "")).upper()
            text = str(claim.get("text") or claim.get("extracted_value") or "").strip()
            if not text:
                continue

            if claim_type in {"CVE_ID", "CVE"}:
                results.append(cve_exists_in_nvd(text, threat_intel))
                continue

            if claim_type in {"CVSS_SCORE", "CVSS"}:
                authoritative_score = _extract_authoritative_cvss(threat_intel)
                if authoritative_score is not None:
                    results.append(
                        cvss_score_in_range(float(text), authoritative_score)
                    )
                continue

            if claim_type in {"ATTACK_TECHNIQUE", "ATTACK_ID"}:
                results.append(attack_id_valid(text, threat_intel))
                continue

            if claim_type == "VERSION":
                cpe_list = _extract_cpe_list(threat_intel)
                if cpe_list:
                    results.append(version_in_affected_range(text, cpe_list))

        return results


def _confidence_for(passed: bool, proximity: float | None = None) -> float:
    base = float(
        _CONFIG.get(
            "pass_confidence" if passed else "fail_confidence", 0.96 if passed else 0.95
        )
    )
    if proximity is None:
        return round(base, 2)
    adjusted = 0.5 * base + 0.5 * (proximity if passed else 1.0 - proximity)
    return round(max(0.0, min(adjusted, 1.0)), 2)


def _normalise_cve_ids(nvd_data: dict[str, Any]) -> set[str]:
    if "cves" in nvd_data:
        if isinstance(nvd_data["cves"], list):
            return {str(item).upper() for item in nvd_data["cves"]}
        if isinstance(nvd_data["cves"], dict):
            return {str(item).upper() for item in nvd_data["cves"].keys()}
    vulnerabilities = nvd_data.get("vulnerabilities", [])
    known_ids: set[str] = set()
    for item in vulnerabilities:
        cve_id = item.get("cve", {}).get("id") if isinstance(item, dict) else None
        if cve_id:
            known_ids.add(str(cve_id).upper())
    return known_ids


def _normalise_attack_ids(attack_data: dict[str, Any]) -> set[str]:
    if "techniques" in attack_data:
        if isinstance(attack_data["techniques"], list):
            return {str(item).upper() for item in attack_data["techniques"]}
        if isinstance(attack_data["techniques"], dict):
            return {str(item).upper() for item in attack_data["techniques"].keys()}
    techniques = attack_data.get("objects", [])
    known_ids: set[str] = set()
    for item in techniques:
        external_refs = (
            item.get("external_references", []) if isinstance(item, dict) else []
        )
        for ref in external_refs:
            external_id = ref.get("external_id")
            if external_id:
                known_ids.add(str(external_id).upper())
    return known_ids


def _extract_cpe_version(cpe: str | dict[str, Any]) -> str | None:
    if isinstance(cpe, dict):
        return str(
            cpe.get("version")
            or cpe.get("versionStartIncluding")
            or cpe.get("versionEndIncluding")
            or ""
        )
    parts = cpe.split(":")
    index = int(_CONFIG.get("cpe_version_index", 5))
    return parts[index] if len(parts) > index else None


def _version_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts) if parts else (0,)


def _dict_range_matches(version_key: tuple[int, ...], cpe: dict[str, Any]) -> bool:
    lower_inclusive = cpe.get("versionStartIncluding")
    lower_exclusive = cpe.get("versionStartExcluding")
    upper_inclusive = cpe.get("versionEndIncluding")
    upper_exclusive = cpe.get("versionEndExcluding")

    # If no explicit range boundaries are provided, do not consider this a range match.
    if not any([lower_inclusive, lower_exclusive, upper_inclusive, upper_exclusive]):
        return False

    if lower_inclusive and version_key < _version_key(str(lower_inclusive)):
        return False
    if lower_exclusive and version_key <= _version_key(str(lower_exclusive)):
        return False
    if upper_inclusive and version_key > _version_key(str(upper_inclusive)):
        return False
    if upper_exclusive and version_key >= _version_key(str(upper_exclusive)):
        return False
    return True


def _stringify_cpe(cpe: str | dict[str, Any] | None) -> str:
    if cpe is None:
        return ""
    return cpe if isinstance(cpe, str) else str(cpe)


def _normalise_text_tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if token}


def _token_overlap(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _extract_authoritative_cvss(threat_intel: dict[str, Any]) -> float | None:
    if "cvss_score" in threat_intel:
        return float(threat_intel["cvss_score"])

    cves = threat_intel.get("cves")
    if isinstance(cves, dict):
        for payload in cves.values():
            if not isinstance(payload, dict):
                continue
            base_score = payload.get("base_score") or payload.get("cvss_v3_score")
            if base_score is not None:
                return float(base_score)
    return None


def _extract_cpe_list(threat_intel: dict[str, Any]) -> list[str | dict[str, Any]]:
    cpe_list = threat_intel.get("cpe_list")
    if isinstance(cpe_list, list):
        return cpe_list

    cves = threat_intel.get("cves")
    if isinstance(cves, dict):
        for payload in cves.values():
            if not isinstance(payload, dict):
                continue
            affected = payload.get("cpe_list") or payload.get("affected_products")
            if isinstance(affected, list):
                return affected
    return []

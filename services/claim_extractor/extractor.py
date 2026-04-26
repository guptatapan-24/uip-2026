"""Three-pass claim extraction pipeline for SOC-oriented security text."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from services.common.config import load_yaml_config
from services.common.models import Claim, ClaimType

try:
    import spacy
    from spacy.language import Language
    from spacy.pipeline import EntityRuler
except Exception:  # pragma: no cover - optional dependency fallback
    spacy = None
    Language = Any  # type: ignore[assignment]
    EntityRuler = Any  # type: ignore[assignment]

try:
    from transformers import pipeline
except Exception:  # pragma: no cover - optional dependency fallback
    pipeline = None  # type: ignore[assignment]


@dataclass(slots=True)
class RegexSpec:
    """Compiled regex specification for one claim type."""

    claim_type: ClaimType
    pattern: re.Pattern[str]
    confidence: float


class RegexPassExtractor:
    """Pass 1 extractor for structured CVE, ATT&CK, and CVSS patterns."""

    def __init__(self, config: dict[str, Any]) -> None:
        regex_section = config.get("regex", {})
        self._specs = [
            RegexSpec(ClaimType.CVE, re.compile(regex_section["cve"]["pattern"], re.IGNORECASE), regex_section["cve"]["confidence"]),
            RegexSpec(
                ClaimType.ATTACK_ID,
                re.compile(regex_section["attack"]["pattern"], re.IGNORECASE),
                regex_section["attack"]["confidence"],
            ),
            RegexSpec(ClaimType.CVSS, re.compile(regex_section["cvss"]["pattern"], re.IGNORECASE), regex_section["cvss"]["confidence"]),
        ]

    def extract(self, text: str) -> list[Claim]:
        claims: list[Claim] = []
        for spec in self._specs:
            for match in spec.pattern.finditer(text):
                extracted = match.group("score") if spec.claim_type == ClaimType.CVSS and "score" in match.groupdict() else match.group(0)
                claims.append(
                    Claim(
                        claim_type=spec.claim_type,
                        raw_text=match.group(0),
                        extracted_value=extracted,
                        position=(match.start(), match.end()),
                        confidence=spec.confidence,
                        metadata={"source_pass": "regex"},
                    )
                )
        return claims


class SecuritySpacyExtractor:
    """Pass 2 extractor using spaCy with a security-oriented fallback entity ruler."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config.get("spacy", {})

    @cached_property
    def nlp(self) -> Language | None:
        if spacy is None:
            return None

        model_path = os.getenv(self._config.get("model_path_env", "SECURITY_SPACY_MODEL_PATH"))
        model_name = model_path or self._config.get("model_name", "en_core_web_sm")
        try:
            return spacy.load(model_name)
        except Exception:
            nlp = spacy.blank("en")
            ruler = nlp.add_pipe("entity_ruler")  # type: ignore[assignment]
            assert isinstance(ruler, EntityRuler)
            patterns: list[dict[str, Any]] = []
            for label, values in self._config.get("entity_patterns", {}).items():
                for value in values:
                    patterns.append({"label": label, "pattern": value})
            ruler.add_patterns(patterns)
            return nlp

    def extract(self, text: str) -> list[Claim]:
        label_map = {
            "PRODUCT": ClaimType.PRODUCT,
            "VERSION": ClaimType.VERSION,
            "SEVERITY": ClaimType.SEVERITY,
        }

        claims: list[Claim] = []
        nlp = self.nlp
        if nlp is not None:
            doc = nlp(text)
            for ent in doc.ents:
                claim_type = label_map.get(ent.label_)
                if claim_type is None:
                    continue
                claims.append(
                    Claim(
                        claim_type=claim_type,
                        raw_text=ent.text,
                        extracted_value=ent.text,
                        position=(ent.start_char, ent.end_char),
                        confidence=float(self._config.get("fallback_confidence", 0.78)),
                        metadata={
                            "source_pass": "spacy",
                            "entity_label": ent.label_,
                            "custom_model_loaded": bool(os.getenv(self._config.get("model_path_env", "SECURITY_SPACY_MODEL_PATH"))),
                        },
                    )
                )
        claims.extend(self._extract_from_config_patterns(text, label_map))
        return self._deduplicate(claims)

    def _extract_from_config_patterns(self, text: str, label_map: dict[str, ClaimType]) -> list[Claim]:
        claims: list[Claim] = []
        for label, values in self._config.get("entity_patterns", {}).items():
            claim_type = label_map.get(label)
            if claim_type is None:
                continue
            for value in values:
                pattern = re.compile(rf"\b{re.escape(value)}\b", re.IGNORECASE)
                for match in pattern.finditer(text):
                    claims.append(
                        Claim(
                            claim_type=claim_type,
                            raw_text=match.group(0),
                            extracted_value=match.group(0),
                            position=(match.start(), match.end()),
                            confidence=float(self._config.get("fallback_confidence", 0.78)),
                            metadata={"source_pass": "spacy-pattern-fallback", "entity_label": label},
                        )
                    )
        return claims

    @staticmethod
    def _deduplicate(claims: list[Claim]) -> list[Claim]:
        seen: set[tuple[str, str, tuple[int, int]]] = set()
        unique_claims: list[Claim] = []
        for claim in sorted(claims, key=lambda item: item.position):
            key = (claim.claim_type.value, claim.extracted_value.lower(), claim.position)
            if key in seen:
                continue
            seen.add(key)
            unique_claims.append(claim)
        return unique_claims


class BertSpanExtractor:
    """Pass 3 extractor using token-classification with a robust heuristic fallback."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config.get("bert", {})

    @cached_property
    def token_classifier(self) -> Any | None:
        if pipeline is None:
            return None
        model_name = os.getenv(self._config.get("model_name_env", "SECURITY_BERT_MODEL_NAME"), self._config.get("model_name"))
        try:
            return pipeline(
                "token-classification",
                model=model_name,
                aggregation_strategy=self._config.get("aggregation_strategy", "simple"),
            )
        except Exception:
            return None

    def extract(self, text: str) -> list[Claim]:
        model_claims = self._extract_with_model(text)
        fallback_claims = self._extract_with_heuristics(text)
        return self._deduplicate(model_claims + fallback_claims)

    def _extract_with_model(self, text: str) -> list[Claim]:
        classifier = self.token_classifier
        if classifier is None:
            return []

        claims: list[Claim] = []
        mitigation_groups = {group.upper() for group in self._config.get("mitigation_entity_groups", ["ACTION", "MITIGATION"])}
        urgency_groups = {group.upper() for group in self._config.get("urgency_entity_groups", ["URGENCY", "PRIORITY"])}
        for item in classifier(text):
            entity_group = str(item.get("entity_group", "")).upper()
            word = str(item.get("word", "")).strip()
            start = int(item.get("start", 0))
            end = int(item.get("end", start + len(word)))
            score = float(item.get("score", 0.0))
            if entity_group in mitigation_groups:
                claims.append(
                    Claim(
                        claim_type=ClaimType.MITIGATION,
                        raw_text=word,
                        extracted_value=word,
                        position=(start, end),
                        confidence=score,
                        metadata={"source_pass": "bert", "entity_group": entity_group},
                    )
                )
            if entity_group in urgency_groups:
                claims.append(
                    Claim(
                        claim_type=ClaimType.URGENCY,
                        raw_text=word,
                        extracted_value=word,
                        position=(start, end),
                        confidence=score,
                        metadata={"source_pass": "bert", "entity_group": entity_group},
                    )
                )
        return claims

    def _extract_with_heuristics(self, text: str) -> list[Claim]:
        claims: list[Claim] = []
        verb_pattern = "|".join(re.escape(verb) for verb in self._config.get("mitigation_verbs", []))
        mitigation_regex = re.compile(
            rf"\b(?:{verb_pattern})\b.*?(?=(?:[.!?]\s+[A-Z]|[.!?]$|\n|$))",
            re.IGNORECASE,
        )
        for match in mitigation_regex.finditer(text):
            claims.append(
                Claim(
                    claim_type=ClaimType.MITIGATION,
                    raw_text=match.group(0).strip(),
                    extracted_value=match.group(0).strip(),
                    position=(match.start(), match.end()),
                    confidence=float(self._config.get("mitigation_confidence", 0.74)),
                    metadata={"source_pass": "bert-fallback"},
                )
            )

        for keyword in self._config.get("urgency_keywords", []):
            urgency_regex = re.compile(rf"\b{re.escape(keyword)}\b", re.IGNORECASE)
            for match in urgency_regex.finditer(text):
                claims.append(
                    Claim(
                        claim_type=ClaimType.URGENCY,
                        raw_text=match.group(0),
                        extracted_value=match.group(0).lower(),
                        position=(match.start(), match.end()),
                        confidence=float(self._config.get("urgency_confidence", 0.72)),
                        metadata={"source_pass": "bert-fallback"},
                    )
                )
        return claims

    @staticmethod
    def _deduplicate(claims: list[Claim]) -> list[Claim]:
        seen: set[tuple[str, str, tuple[int, int]]] = set()
        unique_claims: list[Claim] = []
        for claim in claims:
            key = (claim.claim_type.value, claim.extracted_value, claim.position)
            if key in seen:
                continue
            seen.add(key)
            unique_claims.append(claim)
        return unique_claims


class ClaimExtractor:
    """Coordinator for the three-pass extraction pipeline."""

    def __init__(self) -> None:
        self._config = load_yaml_config("config/extraction.yaml")
        self._regex_extractor = RegexPassExtractor(self._config)
        self._spacy_extractor = SecuritySpacyExtractor(self._config)
        self._bert_extractor = BertSpanExtractor(self._config)

    async def extract(self, text: str) -> list[Claim]:
        """Run all extraction passes and return a deduplicated claim list."""
        if not text.strip():
            return []

        regex_claims = await asyncio.to_thread(self._regex_extractor.extract, text)
        spacy_claims = await asyncio.to_thread(self._spacy_extractor.extract, text)
        bert_claims = await asyncio.to_thread(self._bert_extractor.extract, text)
        return self._deduplicate(regex_claims + spacy_claims + bert_claims)

    @staticmethod
    def _deduplicate(claims: list[Claim]) -> list[Claim]:
        merged: dict[tuple[str, str, tuple[int, int]], Claim] = {}
        for claim in claims:
            key = (claim.claim_type.value, claim.extracted_value, claim.position)
            existing = merged.get(key)
            if existing is None or claim.confidence > existing.confidence:
                merged[key] = claim
        return sorted(merged.values(), key=lambda claim: claim.position)


async def extract_claims(text: str) -> list[Claim]:
    """Convenience async function for extracting claims from free text."""
    extractor = ClaimExtractor()
    return await extractor.extract(text)

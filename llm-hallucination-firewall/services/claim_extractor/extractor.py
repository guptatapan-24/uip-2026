# services/claim_extractor/extractor.py
"""
Claim extraction pipeline using regex, spaCy NER, and BERT span extraction.

Combines three approaches:
1. Regex patterns for structured claims (CVE IDs, CVSS scores, technique IDs)
2. spaCy NER for entity recognition (ORG, PERSON, GPE, etc.)
3. BERT span extraction for semantic claim boundaries

Returns structured Claim objects with confidence scores and evidence.
"""


import re
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from models import Claim, ClaimRequest, ClaimResponse
try:
    import spacy
except ImportError:
    spacy = None
try:
    from transformers import pipeline
except ImportError:
    pipeline = None


class ClaimExtractor:
    """
    Extracts claims from unstructured LLM recommendations.
    
    Supports:
    - CVE ID extraction (CVE-YYYY-NNNN format)
    - CVSS score extraction
    - MITRE ATT&CK technique ID extraction (TXXXX format)
    - Severity level extraction
    - Affected product/version extraction
    """
    
    # Regex patterns for structured extraction
    PATTERNS = {
        "CVE_ID": re.compile(r"CVE-\d{4}-\d{4,}"),
        "CVSS_SCORE": re.compile(r"(?:CVSS v3\.1: |CVSS: )(\d+\.\d)"),
        "ATTACK_TECHNIQUE": re.compile(r"(?:technique |Technique )(T\d{4})"),
        "SEVERITY_LEVEL": re.compile(r"(?:severity|Severity)[:=\s]+(?:CRITICAL|HIGH|MEDIUM|LOW|Critical|High|Medium|Low)"),
        "VERSION": re.compile(r"(?:version |v)(\d+\.\d+(?:\.\d+)?)"),
        "DATE": re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    }
    
    def __init__(self):
        """Initialize extraction models."""
        self.nlp = None
        if spacy:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except Exception:
                self.nlp = None
        self.bert_pipeline = None
        if pipeline:
            try:
                self.bert_pipeline = pipeline("token-classification")
            except Exception:
                self.bert_pipeline = None
    

    def extract(self, request: ClaimRequest) -> ClaimResponse:
        """
        Main extraction pipeline orchestrator.
        Returns ClaimResponse with extracted claims.
        """
        start_time = datetime.now()
        text = request.text or ""
        claims: List[Claim] = []
        # Pass 1: Regex
        claims.extend(self._extract_regex_patterns(text))
        # Pass 2: spaCy NER
        if request.enable_ner and self.nlp:
            claims.extend(self._extract_ner_entities(text))
        # Pass 3: BERT span extraction
        if request.enable_span_extraction and self.bert_pipeline:
            claims.extend(self._extract_spans(text))
        # Deduplicate
        claims = self._deduplicate_claims(claims)
        latency_ms = (datetime.now() - start_time).total_seconds() * 1000
        return ClaimResponse(
            input_text=text,
            claims=[self._claim_to_dict(c) for c in claims],
            extraction_timestamp=datetime.now().isoformat(),
            latency_ms=latency_ms,
            model_version=request.model_version
        )
    
    def _extract_regex_patterns(self, text: str) -> List[Claim]:
        """Extract claims using regex patterns."""
        claims: List[Claim] = []
        for key, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                if key == "CVSS_SCORE":
                    val = match.group(1) if match.lastindex else match.group(0)
                elif key == "VERSION":
                    val = match.group(1) if match.lastindex else match.group(0)
                elif key == "ATTACK_TECHNIQUE":
                    val = match.group(1) if match.lastindex else match.group(0)
                else:
                    val = match.group(0)
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=val,
                    claim_type=key,
                    confidence=0.95 if key == "CVE_ID" else 0.90,
                    span_start=match.start(),
                    span_end=match.end(),
                    evidence_tokens=[val]
                ))
        return claims

    def _extract_ner_entities(self, text: str) -> List[Claim]:
        """Extract claims using spaCy NER (product, version, severity)."""
        if not self.nlp:
            return []
        doc = self.nlp(text)
        claims = []
        for ent in doc.ents:
            if ent.label_ in {"PRODUCT", "ORG", "GPE"}:
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=ent.text,
                    claim_type="PRODUCT",
                    confidence=0.85,
                    span_start=ent.start_char,
                    span_end=ent.end_char,
                    evidence_tokens=[ent.text]
                ))
            elif ent.label_ == "CARDINAL":
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=ent.text,
                    claim_type="VERSION",
                    confidence=0.80,
                    span_start=ent.start_char,
                    span_end=ent.end_char,
                    evidence_tokens=[ent.text]
                ))
            elif ent.label_ == "NORP":
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=ent.text,
                    claim_type="SEVERITY_LEVEL",
                    confidence=0.80,
                    span_start=ent.start_char,
                    span_end=ent.end_char,
                    evidence_tokens=[ent.text]
                ))
        return claims

    def _extract_spans(self, text: str) -> List[Claim]:
        """Extract mitigation/urgency spans using BERT token classification."""
        if not self.bert_pipeline:
            return []
        results = self.bert_pipeline(text)
        claims = []
        for r in results:
            label = r.get("entity", "")
            if "mitigation" in label.lower():
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=text[r["start"]:r["end"]],
                    claim_type="MITIGATION_ACTION",
                    confidence=0.80,
                    span_start=r["start"],
                    span_end=r["end"],
                    evidence_tokens=[text[r["start"]:r["end"]]]
                ))
            elif "urgency" in label.lower():
                claims.append(Claim(
                    claim_id=str(uuid.uuid4()),
                    text=text[r["start"]:r["end"]],
                    claim_type="URGENCY_ASSERTION",
                    confidence=0.80,
                    span_start=r["start"],
                    span_end=r["end"],
                    evidence_tokens=[text[r["start"]:r["end"]]]
                ))
        return claims

    def _deduplicate_claims(self, claims: List[Claim]) -> List[Claim]:
        seen = set()
        deduped = []
        for c in claims:
            key = (c.claim_type, c.text, c.span_start, c.span_end)
            if key not in seen:
                seen.add(key)
                deduped.append(c)
        return deduped

    def _claim_to_dict(self, c: Claim) -> Dict[str, Any]:
        return {
            "claim_id": c.claim_id,
            "raw_text": c.text,
            "claim_type": c.claim_type,
            "extracted_value": c.text,
            "position": (c.span_start, c.span_end),
            "confidence": c.confidence
        }
                span_start=match.start(),
                span_end=match.end(),
                evidence_tokens=[match.group(1)]
            ))
        
        # MITRE ATT&CK Techniques
        for match in self.PATTERNS["ATTACK_TECHNIQUE"].finditer(text):
            technique_id = match.group(1)
            claims.append(Claim(
                claim_id=str(uuid.uuid4()),
                text=technique_id,
                claim_type="ATTACK_TECHNIQUE",
                confidence=0.92,
                span_start=match.start(1),
                span_end=match.end(1),
                evidence_tokens=[technique_id]
            ))
        
        # Severity levels
        for match in self.PATTERNS["SEVERITY_LEVEL"].finditer(text):
            claims.append(Claim(
                claim_id=str(uuid.uuid4()),
                text=match.group(),
                claim_type="SEVERITY",
                confidence=0.88,
                span_start=match.start(),
                span_end=match.end(),
                evidence_tokens=[match.group()]
            ))
        
        return claims
    
    def _extract_ner_entities(self, text: str) -> List[Claim]:
        """
        Extract entities using spaCy NER.
        
        Maps spaCy entity types to claim types.
        """
        claims = []
        
        # TODO: Process with self.nlp(text)
        # doc = self.nlp(text)
        # for ent in doc.ents:
        #     if ent.label_ in ["ORG", "PRODUCT", "GPE"]:
        #         claims.append(Claim(...))
        
        return claims
    
    def _extract_spans(self, text: str) -> List[Claim]:
        """
        Extract semantic claim spans using BERT.
        
        Identifies sentence fragments most likely to contain claims.
        """
        claims = []
        
        # TODO: Tokenize with BERT
        # TODO: Compute span embeddings
        # TODO: Identify high-confidence claim boundaries
        
        return claims
    
    def _deduplicate_claims(self, claims: List[Claim]) -> List[Claim]:
        """Remove duplicate claims and keep highest confidence version."""
        seen = {}
        for claim in sorted(claims, key=lambda c: c.confidence, reverse=True):
            key = (claim.claim_type, claim.text.lower())
            if key not in seen:
                seen[key] = claim
        return list(seen.values())
    
    def _claim_to_dict(self, claim: Claim) -> dict:
        """Convert Claim dataclass to dictionary for JSON response."""
        return {
            "claim_id": claim.claim_id,
            "text": claim.text,
            "claim_type": claim.claim_type,
            "confidence": claim.confidence,
            "span_start": claim.span_start,
            "span_end": claim.span_end,
            "evidence_tokens": claim.evidence_tokens
        }
    
    async def extract_async(self, request: ClaimRequest) -> ClaimResponse:
        """Async version of extract for FastAPI integration."""
        # TODO: Run extraction in thread pool if models are not async
        return self.extract(request)


# Singleton instance
_extractor = None


def get_extractor() -> ClaimExtractor:
    """Get or create singleton ClaimExtractor instance."""
    global _extractor
    if _extractor is None:
        _extractor = ClaimExtractor()
    return _extractor

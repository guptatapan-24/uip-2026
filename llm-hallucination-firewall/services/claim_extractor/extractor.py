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
from typing import List, Optional
from datetime import datetime

from models import Claim, ClaimRequest, ClaimResponse

# TODO: Import spacy
# TODO: Import transformers (BERT)


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
        # TODO: Load spaCy English model
        # self.nlp = spacy.load("en_core_web_sm")
        
        # TODO: Load BERT tokenizer and model for span extraction
        # self.bert_tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
        # self.bert_model = BertModel.from_pretrained("bert-base-uncased")
        
        pass
    
    def extract(self, request: ClaimRequest) -> ClaimResponse:
        """
        Main extraction pipeline orchestrator.
        
        Args:
            request: Extraction request with text and options
            
        Returns:
            ClaimResponse with extracted claims
        """
        start_time = datetime.now()
        text = request.text
        claims = []
        
        # Step 1: Regex-based extraction for structured patterns
        regex_claims = self._extract_regex_patterns(text)
        claims.extend(regex_claims)
        
        # Step 2: spaCy NER if enabled
        if request.enable_ner:
            ner_claims = self._extract_ner_entities(text)
            claims.extend(ner_claims)
        
        # Step 3: BERT span extraction if enabled
        if request.enable_span_extraction:
            span_claims = self._extract_spans(text)
            claims.extend(span_claims)
        
        # Deduplicate and normalize
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
        claims = []
        
        # CVE IDs
        for match in self.PATTERNS["CVE_ID"].finditer(text):
            claims.append(Claim(
                claim_id=str(uuid.uuid4()),
                text=match.group(),
                claim_type="CVE_ID",
                confidence=0.95,  # High confidence for regex match
                span_start=match.start(),
                span_end=match.end(),
                evidence_tokens=[match.group()]
            ))
        
        # CVSS Scores
        for match in self.PATTERNS["CVSS_SCORE"].finditer(text):
            claims.append(Claim(
                claim_id=str(uuid.uuid4()),
                text=match.group(),
                claim_type="CVSS_SCORE",
                confidence=0.90,
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

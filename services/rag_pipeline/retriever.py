# services/rag_pipeline/retriever.py
"""
Unified threat intelligence retriever.

Orchestrates NVD, ATT&CK, KEV, and FAISS to retrieve relevant threat intelligence
for validation claims with semantic search + exact matching.

TODO: Integrate Dhruv's rag_pipeline orchestration
"""

from typing import Any, Dict, List, Optional

from attack_client import get_attack_client
from faiss_index import get_faiss_index
from kev_client import get_kev_client
from nvd_client import CVERecord, get_nvd_client
from pydantic import BaseModel


class RetrievalResult(BaseModel):
    """Single retrieval result."""

    source: str  # "NVD", "ATT&CK", "KEV", "FAISS"
    match_id: str
    similarity_score: Optional[float] = None
    data: Dict[str, Any]


class Retriever:
    """
    Unified retriever for all threat intelligence sources.
    """

    def __init__(self):
        """Initialize retriever with all clients."""
        # TODO: Async initialization
        self.nvd_client = None
        self.attack_client = None
        self.kev_client = None
        self.faiss_index = get_faiss_index()

    async def retrieve_for_cve(self, cve_id: str) -> List[RetrievalResult]:
        """
        Retrieve all available data for a CVE ID.

        Args:
            cve_id: CVE ID (e.g., "CVE-2024-1234")

        Returns:
            List of retrieval results from all sources
        """
        results = []

        # NVD data
        nvd_client = await get_nvd_client()
        cve_record = await nvd_client.get_cve(cve_id)
        if cve_record:
            results.append(
                RetrievalResult(
                    source="NVD", match_id=cve_id, data=cve_record.model_dump()
                )
            )

        # KEV status
        kev_client = await get_kev_client()
        is_exploited = await kev_client.is_known_exploited(cve_id)
        if is_exploited:
            kev_info = await kev_client.get_kev_info(cve_id)
            results.append(
                RetrievalResult(source="KEV", match_id=cve_id, data=kev_info or {})
            )

        return results

    async def retrieve_for_attack_technique(
        self, technique_id: str
    ) -> List[RetrievalResult]:
        """
        Retrieve all available data for an ATT&CK technique.

        Args:
            technique_id: Technique ID (e.g., "T1566")

        Returns:
            List of retrieval results
        """
        results = []

        attack_client = await get_attack_client()
        technique = await attack_client.get_technique(technique_id)
        if technique:
            results.append(
                RetrievalResult(source="ATT&CK", match_id=technique_id, data=technique)
            )

        return results

    async def semantic_search(self, query: str, k: int = 5) -> List[RetrievalResult]:
        """
        Semantic search over threat intelligence via FAISS.

        Args:
            query: Search query
            k: Number of results

        Returns:
            List of retrieval results with similarity scores
        """
        results = []

        faiss_results = self.faiss_index.search(query, k=k)
        for doc_id, similarity in faiss_results:
            # TODO: Fetch full document from source
            results.append(
                RetrievalResult(
                    source="FAISS",
                    match_id=doc_id,
                    similarity_score=similarity,
                    data={},
                )
            )

        return results

    async def retrieve_all(
        self, claims: List[Dict[str, str]]
    ) -> Dict[str, List[RetrievalResult]]:
        """
        Retrieve threat intelligence for multiple claims.

        Args:
            claims: List of claims [{"type": str, "value": str}, ...]

        Returns:
            Dictionary mapping claim value to retrieval results
        """
        results = {}

        for claim in claims:
            claim_type = claim.get("type", "").upper()
            claim_value = claim.get("value", "")

            if claim_type == "CVE_ID":
                results[claim_value] = await self.retrieve_for_cve(claim_value)
            elif claim_type == "ATTACK_TECHNIQUE":
                results[claim_value] = await self.retrieve_for_attack_technique(
                    claim_value
                )
            elif claim_type == "QUERY":
                results[claim_value] = await self.semantic_search(claim_value)

        return results


# Singleton
_retriever: Optional[Retriever] = None


async def get_retriever() -> Retriever:
    """Get or create Retriever singleton."""
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    return _retriever

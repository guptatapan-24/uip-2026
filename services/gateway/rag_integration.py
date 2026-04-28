"""RAG pipeline orchestration and integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class RAGPipeline:
    """
    Unified RAG pipeline for retrieving threat intelligence.

    Orchestrates NVD, ATT&CK, KEV, and FAISS sources.
    Designed for integration with Tanushree's validation modules.
    """

    def __init__(self):
        """Initialize RAG pipeline clients."""
        self._nvd_client = None
        self._attack_client = None
        self._kev_client = None

    async def _ensure_clients(self) -> None:
        if self._nvd_client is None:
            from services.rag_pipeline.nvd_client import get_nvd_client

            self._nvd_client = await get_nvd_client()
        if self._attack_client is None:
            from services.rag_pipeline.attack_client import get_attack_client

            self._attack_client = await get_attack_client()
        if self._kev_client is None:
            from services.rag_pipeline.kev_client import get_kev_client

            self._kev_client = await get_kev_client()

    async def retrieve_cve_data(self, cve_id: str) -> dict[str, Any]:
        """
        Retrieve all available NVD data for a CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-0001")

        Returns:
            Dictionary with CVE metadata suitable for deterministic validation

        Note:
            Returns empty dict on network errors; validation gracefully degrades.
        """
        try:
            logger.info(f"Retrieving NVD data for {cve_id}")
            await self._ensure_clients()
            record = await self._nvd_client.get_cve(cve_id)
            if record is not None:
                return {
                    "cve_id": record.cve_id,
                    "cvss_score": record.cvss_v3_score,
                    "affected_versions": record.affected_products,
                    "references": [],
                    "source": "nvd",
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": record.cve_id,
                            }
                        }
                    ],
                }

            return {
                "cve_id": cve_id,
                "cvss_score": None,
                "affected_versions": [],
                "references": [],
                "source": "nvd_empty",
            }
        except Exception as e:
            logger.error(f"NVD retrieval error for {cve_id}: {e}")
            return {}

    async def retrieve_attack_technique(self, technique_id: str) -> dict[str, Any]:
        """
        Retrieve ATT&CK framework data for a technique.

        Args:
            technique_id: Technique ID (e.g., "T1190")

        Returns:
            Dictionary with technique metadata

        Note:
            Returns empty dict on errors; validation gracefully degrades.
        """
        try:
            logger.info(f"Retrieving ATT&CK data for {technique_id}")
            await self._ensure_clients()
            technique = await self._attack_client.get_technique(technique_id)
            if technique:
                return {
                    "technique_id": technique_id,
                    "name": technique.get("name"),
                    "tactics": [
                        phase.get("phase_name")
                        for phase in technique.get("kill_chain_phases", [])
                        if isinstance(phase, dict)
                    ],
                    "platforms": technique.get("x_mitre_platforms", []),
                    "source": "attack",
                    "techniques": [technique_id],
                }
            return {
                "technique_id": technique_id,
                "name": None,
                "tactics": [],
                "platforms": [],
                "source": "attack_empty",
            }
        except Exception as e:
            logger.error(f"ATT&CK retrieval error for {technique_id}: {e}")
            return {}

    async def retrieve_kev_status(self, cve_id: str) -> dict[str, Any]:
        """
        Check if a CVE is in CISA Known Exploited Vulnerabilities catalog.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with KEV status and exploit details

        Note:
            Returns {"is_exploited": False} on errors.
        """
        try:
            logger.info(f"Checking KEV status for {cve_id}")
            await self._ensure_clients()
            kev_info = await self._kev_client.get_kev_info(cve_id)
            if kev_info:
                return {
                    "cve_id": cve_id,
                    "is_exploited": True,
                    "date_added": kev_info.get("dateAdded"),
                    "source": "kev",
                    "known_ransomware_campaign_use": kev_info.get(
                        "knownRansomwareCampaignUse"
                    ),
                }
            return {
                "cve_id": cve_id,
                "is_exploited": False,
                "date_added": None,
                "source": "kev_empty",
            }
        except Exception as e:
            logger.error(f"KEV lookup error for {cve_id}: {e}")
            return {"is_exploited": False}

    async def retrieve_threat_intel(
        self, cve_id: str = None, technique_id: str = None
    ) -> dict[str, Any]:
        """
        Unified retrieval for one or more threat intelligence sources.

        Args:
            cve_id: Optional CVE to look up
            technique_id: Optional ATT&CK technique to look up

        Returns:
            Dictionary with combined results from all sources

        Note:
            Used by validation pipeline to enrich validation decisions.
        """
        results = {}

        if cve_id:
            results["nvd"] = await self.retrieve_cve_data(cve_id)
            results["kev"] = await self.retrieve_kev_status(cve_id)

        if technique_id:
            results["attack"] = await self.retrieve_attack_technique(technique_id)

        return results


# Singleton instance for API routes
_rag_pipeline = None


def get_rag_pipeline() -> RAGPipeline:
    """Get or create the RAG pipeline instance."""
    global _rag_pipeline
    if _rag_pipeline is None:
        _rag_pipeline = RAGPipeline()
    return _rag_pipeline

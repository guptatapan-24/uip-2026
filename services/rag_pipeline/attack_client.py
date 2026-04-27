# services/rag_pipeline/attack_client.py
"""
MITRE ATT&CK data source client.

Retrieves MITRE ATT&CK framework data (techniques, tactics, relationships)
from GitHub CDN with local caching.

GitHub source: https://github.com/mitre/cti
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx


class AttackClient:
    """
    Client for MITRE ATT&CK data retrieval and caching.
    """

    def __init__(self):
        """Initialize ATT&CK client."""
        self.base_url = os.getenv(
            "ATTACK_API_URL",
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/",
        )
        self.cache_dir = os.getenv("ATTACK_CACHE_DIR", "/data/attack_cache")
        self.sync_interval_days = int(os.getenv("ATTACK_SYNC_INTERVAL_DAYS", "30"))
        self.techniques: Dict[str, Dict] = {}
        self.tactics: Dict[str, Dict] = {}

    async def initialize(self):
        """Load ATT&CK data from cache or API."""
        # TODO: Load techniques.json and tactics.json
        # TODO: Check cache freshness, sync if needed
        pass

    async def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get MITRE ATT&CK technique details.

        Args:
            technique_id: Technique ID (e.g., "T1566")

        Returns:
            Technique data if found
        """
        return self.techniques.get(technique_id)

    async def get_techniques_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """
        Get all techniques for a tactic.

        Args:
            tactic: Tactic name (e.g., "Initial Access")

        Returns:
            List of techniques for tactic
        """
        # TODO: Filter techniques by tactic
        return []

    async def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """
        Search techniques by description or name.

        Args:
            query: Search query

        Returns:
            List of matching techniques
        """
        # TODO: Semantic search over technique descriptions
        return []

    async def sync_data(self) -> bool:
        """
        Sync ATT&CK data from GitHub.

        Returns:
            True if successful
        """
        try:
            async with httpx.AsyncClient() as client:
                # Fetch techniques
                techniques_url = f"{self.base_url}techniques.json"
                resp = await client.get(techniques_url)
                resp.raise_for_status()
                techniques_data = resp.json()

                # Parse and cache
                self.techniques = {
                    obj["external_references"][0]["external_id"]: obj
                    for obj in techniques_data.get("objects", [])
                    if obj.get("type") == "attack-pattern"
                }

                # TODO: Fetch and parse tactics similarly

                return True

        except Exception as e:
            print(f"ATT&CK sync failed: {e}")
            return False


# Singleton
_attack_client: Optional[AttackClient] = None


async def get_attack_client() -> AttackClient:
    """Get or create ATT&CK client singleton."""
    global _attack_client
    if _attack_client is None:
        _attack_client = AttackClient()
        await _attack_client.initialize()
    return _attack_client

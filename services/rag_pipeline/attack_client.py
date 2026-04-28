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
from pathlib import Path
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
        self._cache_file = Path(self.cache_dir) / "enterprise-attack.json"

    async def initialize(self):
        """Load ATT&CK data from cache or API."""
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)

        cache_is_fresh = False
        if self._cache_file.exists():
            age_seconds = (datetime.now().timestamp() - self._cache_file.stat().st_mtime)
            cache_is_fresh = age_seconds < self.sync_interval_days * 86400

        if cache_is_fresh:
            await self._load_from_cache()
            return

        synced = await self.sync_data()
        if not synced and self._cache_file.exists():
            await self._load_from_cache()

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
        tactic_norm = tactic.strip().lower()
        results: list[dict[str, Any]] = []
        for technique in self.techniques.values():
            phases = technique.get("kill_chain_phases", [])
            phase_names = [
                str(phase.get("phase_name", "")).replace("-", " ").lower()
                for phase in phases
                if isinstance(phase, dict)
            ]
            if tactic_norm in phase_names:
                results.append(technique)
        return results

    async def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """
        Search techniques by description or name.

        Args:
            query: Search query

        Returns:
            List of matching techniques
        """
        q = query.strip().lower()
        if not q:
            return []

        matches: list[dict[str, Any]] = []
        for technique in self.techniques.values():
            name = str(technique.get("name", "")).lower()
            descriptions = " ".join(
                str(d.get("description", ""))
                for d in technique.get("external_references", [])
                if isinstance(d, dict)
            ).lower()
            if q in name or q in descriptions:
                matches.append(technique)

        return matches[:25]

    async def sync_data(self) -> bool:
        """
        Sync ATT&CK data from GitHub.

        Returns:
            True if successful
        """
        try:
            async with httpx.AsyncClient() as client:
                enterprise_attack_url = f"{self.base_url}enterprise-attack.json"
                resp = await client.get(enterprise_attack_url, timeout=30)
                resp.raise_for_status()
                dataset = resp.json()

                objects = dataset.get("objects", [])
                self.techniques = {
                    ref["external_id"]: obj
                    for obj in objects
                    if obj.get("type") == "attack-pattern"
                    for ref in obj.get("external_references", [])
                    if isinstance(ref, dict)
                    and ref.get("external_id", "").startswith("T")
                }
                self.tactics = {
                    obj.get("name", ""): obj
                    for obj in objects
                    if obj.get("type") == "x-mitre-tactic"
                }

                Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
                self._cache_file.write_text(json.dumps(dataset), encoding="utf-8")

                return True

        except Exception as e:
            print(f"ATT&CK sync failed: {e}")
            return False

    async def _load_from_cache(self) -> None:
        try:
            dataset = json.loads(self._cache_file.read_text(encoding="utf-8"))
            objects = dataset.get("objects", [])
            self.techniques = {
                ref["external_id"]: obj
                for obj in objects
                if obj.get("type") == "attack-pattern"
                for ref in obj.get("external_references", [])
                if isinstance(ref, dict)
                and ref.get("external_id", "").startswith("T")
            }
            self.tactics = {
                obj.get("name", ""): obj
                for obj in objects
                if obj.get("type") == "x-mitre-tactic"
            }
        except Exception:
            self.techniques = {}
            self.tactics = {}


# Singleton
_attack_client: Optional[AttackClient] = None


async def get_attack_client() -> AttackClient:
    """Get or create ATT&CK client singleton."""
    global _attack_client
    if _attack_client is None:
        _attack_client = AttackClient()
        await _attack_client.initialize()
    return _attack_client

# services/rag_pipeline/kev_client.py
"""
CISA Known Exploited Vulnerabilities (KEV) data source client.

Retrieves CISA's catalog of exploited vulnerabilities with exploit details.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


class KEVClient:
    """
    Client for CISA Known Exploited Vulnerabilities data.
    """

    def __init__(self):
        """Initialize KEV client."""
        self.api_url = os.getenv(
            "KEV_API_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        self.cache_dir = os.getenv("KEV_CACHE_DIR", "/data/kev_cache")
        self.sync_interval_days = int(os.getenv("KEV_SYNC_INTERVAL_DAYS", "1"))
        self.kev_data: Dict[str, Dict] = {}
        self._cache_file = Path(self.cache_dir) / "kev.json"

    async def initialize(self):
        """Load KEV data from cache or API."""
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
        cache_is_fresh = False

        if self._cache_file.exists():
            age_seconds = datetime.now().timestamp() - self._cache_file.stat().st_mtime
            cache_is_fresh = age_seconds < self.sync_interval_days * 86400

        if cache_is_fresh:
            self._load_from_cache()
            return

        synced = await self.sync_data()
        if not synced and self._cache_file.exists():
            self._load_from_cache()

    async def get_kev_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get KEV information for a CVE ID.

        Args:
            cve_id: CVE ID (e.g., "CVE-2024-1234")

        Returns:
            KEV entry if vulnerability is known to be exploited
        """
        return self.kev_data.get(cve_id)

    async def is_known_exploited(self, cve_id: str) -> bool:
        """
        Check if CVE is in CISA KEV catalog.

        Args:
            cve_id: CVE ID

        Returns:
            True if exploited
        """
        return cve_id in self.kev_data

    async def get_all_kev(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all KEV entries.

        Returns:
            Dictionary mapping CVE ID to KEV data
        """
        return self.kev_data

    async def sync_data(self) -> bool:
        """
        Sync KEV data from CISA.

        Returns:
            True if successful
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.api_url, timeout=30)
                response.raise_for_status()
                data = response.json()

                # Index by CVE ID
                self.kev_data = {
                    entry["cveID"]: entry for entry in data.get("vulnerabilities", [])
                }

                Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
                self._cache_file.write_text(json.dumps(data), encoding="utf-8")

                return True

        except Exception as e:
            print(f"KEV sync failed: {e}")
            return False

    def _load_from_cache(self) -> None:
        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            self.kev_data = {
                entry["cveID"]: entry for entry in data.get("vulnerabilities", [])
            }
        except Exception:
            self.kev_data = {}


# Singleton
_kev_client: Optional[KEVClient] = None


async def get_kev_client() -> KEVClient:
    """Get or create KEV client singleton."""
    global _kev_client
    if _kev_client is None:
        _kev_client = KEVClient()
        await _kev_client.initialize()
    return _kev_client

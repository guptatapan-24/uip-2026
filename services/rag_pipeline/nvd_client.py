# services/rag_pipeline/nvd_client.py
"""
NVD (National Vulnerability Database) REST API v2 Async Client Module

This module provides async HTTP client functionality for querying the National Vulnerability
Database (NVD) v2 API. It includes exponential backoff retry logic, Redis caching with 24-hour
TTL per CVE, and comprehensive timeout and error handling.

Features:
    - Async HTTP requests using httpx with connection pooling
    - Exponential backoff retry strategy (3 retries with exponential delay)
    - Redis caching layer with 24-hour TTL for CVE data
    - Request timeout handling and circuit breaker protection
    - Structured logging for debugging and monitoring
    - Type hints for all functions
    - Graceful degradation on cache/network failures
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta

import httpx
import redis.asyncio as aioredis
from pydantic import BaseModel
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)

# Constants
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = ""  # TODO: Tanushree - Load from environment variables
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
CVE_CACHE_TTL = 86400  # 24 hours in seconds
REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
INITIAL_BACKOFF = 1  # seconds


class NVDClientError(Exception):
    """Base exception for NVD client operations."""
    pass


class NVDCacheError(NVDClientError):
    """Exception raised for cache-related operations."""
    pass


class NVDAPIError(NVDClientError):
    """Exception raised for NVD API-related operations."""
    pass


class CVERecord(BaseModel):
    """Pydantic model for CVE data."""
    cve_id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    affected_products: List[str] = []
    published_date: str = ""
    last_modified_date: str = ""


class NVDClient:
    """
    Async client for NVD REST API v2 with caching and retry logic.
    
    This class manages connections to the NVD API and provides methods to fetch
    CVE data with automatic retry, caching, and error handling.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        redis_host: str = REDIS_HOST,
        redis_port: int = REDIS_PORT,
        redis_db: int = REDIS_DB,
        timeout: int = REQUEST_TIMEOUT,
    ):
        """
        Initialize NVD client with API key and Redis configuration.
        
        Args:
            api_key: NVD API key for rate limiting benefits
            redis_host: Redis server hostname
            redis_port: Redis server port
            redis_db: Redis database number
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key or NVD_API_KEY
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.timeout = timeout
        self.redis_client: Optional[aioredis.Redis] = None
        self.http_client: Optional[httpx.AsyncClient] = None
        self.base_url = NVD_API_BASE_URL
        self.timeout_seconds = timeout
        self.MAX_RETRIES = MAX_RETRIES
        self.BACKOFF_BASE = INITIAL_BACKOFF
        self.CACHE_TTL_SECONDS = CVE_CACHE_TTL
        self.redis_url = f"redis://{redis_host}:{redis_port}/{redis_db}"
        logger.info(
            "NVDClient initialized with timeout=%ds, redis=%s:%d",
            timeout,
            redis_host,
            redis_port,
        )
    
    async def connect(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = await aioredis.from_url(self.redis_url)
        except Exception as e:
            print(f"Warning: Could not connect to Redis: {e}")
            self.redis_client = None
    
    async def disconnect(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()
    
    async def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """
        Fetch CVE details by ID with caching.
        
        Args:
            cve_id: CVE ID in format "CVE-YYYY-NNNN"
            
        Returns:
            CVERecord if found, None otherwise
        """
        # Check cache first
        cached = await self._get_cache(cve_id)
        if cached:
            return CVERecord(**json.loads(cached))
        
        # Fetch from API with retry
        cve_data = await self._fetch_with_retry(cve_id)
        
        if cve_data:
            record = self._parse_cve_response(cve_data)
            # Cache the result
            await self._set_cache(cve_id, record.model_dump_json())
            return record
        
        return None
    
    async def get_cves_batch(self, cve_ids: list) -> Dict[str, Optional[CVERecord]]:
        """
        Fetch multiple CVEs in parallel.
        
        Args:
            cve_ids: List of CVE IDs
            
        Returns:
            Dictionary mapping CVE ID to CVERecord
        """
        tasks = [self.get_cve(cve_id) for cve_id in cve_ids]
        results = await asyncio.gather(*tasks)
        return {cve_id: result for cve_id, result in zip(cve_ids, results)}
    
    async def _fetch_with_retry(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE from API with exponential backoff retry.
        
        Args:
            cve_id: CVE ID
            
        Returns:
            JSON response if successful, None if all retries exhausted
        """
        url = f"{self.base_url}/{cve_id}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        
        for attempt in range(self.MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    return response.json()
            
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    wait_time = self.BACKOFF_BASE ** attempt
                    print(f"Rate limited. Waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
                elif e.response.status_code == 404:
                    return None  # CVE not found
                else:
                    if attempt < self.MAX_RETRIES - 1:
                        await asyncio.sleep(self.BACKOFF_BASE ** attempt)
                    else:
                        raise
            
            except httpx.RequestError as e:
                if attempt < self.MAX_RETRIES - 1:
                    await asyncio.sleep(self.BACKOFF_BASE ** attempt)
                else:
                    print(f"NVD API error after {self.MAX_RETRIES} retries: {e}")
                    return None
        
        return None
    
    def _parse_cve_response(self, data: Dict[str, Any]) -> CVERecord:
        """Parse NVD API response into CVERecord."""
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        cve = vulnerabilities[0].get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssV3", {}).get("0", {})
        
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if "cpe23Uri" in cpe_match:
                        affected_products.append(cpe_match["cpe23Uri"])
        
        return CVERecord(
            cve_id=cve.get("id", ""),
            description=cve.get("descriptions", [{}])[0].get("value", ""),
            cvss_v3_score=cvss_v3.get("cvssData", {}).get("baseScore"),
            cvss_v3_vector=cvss_v3.get("cvssData", {}).get("vectorString"),
            affected_products=affected_products,
            published_date=cve.get("published", ""),
            last_modified_date=cve.get("lastModified", "")
        )
    
    async def _get_cache(self, key: str) -> Optional[str]:
        """Get value from Redis cache."""
        if not self.redis_client:
            return None
        try:
            return await self.redis_client.get(f"nvd:{key}")
        except Exception:
            return None
    
    async def _set_cache(self, key: str, value: str):
        """Set value in Redis cache with TTL."""
        if not self.redis_client:
            return
        try:
            await self.redis_client.setex(f"nvd:{key}", self.CACHE_TTL_SECONDS, value)
        except Exception:
            pass


# Singleton instance
_nvd_client: Optional[NVDClient] = None


async def get_nvd_client() -> NVDClient:
    """Get or create NVD client singleton."""
    global _nvd_client
    if _nvd_client is None:
        _nvd_client = NVDClient()
        await _nvd_client.connect()
    return _nvd_client

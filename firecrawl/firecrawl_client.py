"""
Firecrawl API Client for CVE Intelligence
Provides direct access to Firecrawl's scraping, search, and agent capabilities
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
import logging
import httpx

from .config import FIRECRAWL_API_KEY

logger = logging.getLogger(__name__)


class FirecrawlClient:
    """Client for Firecrawl API"""
    
    BASE_URL = "https://api.firecrawl.dev"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or FIRECRAWL_API_KEY
        if not self.api_key:
            raise ValueError("Firecrawl API key is required")
    
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    async def scrape(
        self,
        url: str,
        formats: List[str] = None,
        only_main_content: bool = True,
        wait_for: int = None,
        timeout: int = 60
    ) -> Optional[Dict]:
        """
        Scrape a single URL
        
        Args:
            url: URL to scrape
            formats: Output formats (markdown, html, links, etc.)
            only_main_content: Extract only main content
            wait_for: Wait time in ms for dynamic content
            timeout: Request timeout in seconds
        
        Returns:
            Scraped content or None on error
        """
        if formats is None:
            formats = ["markdown"]
        
        payload = {
            "url": url,
            "formats": formats,
            "onlyMainContent": only_main_content
        }
        
        if wait_for:
            payload["waitFor"] = wait_for
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/v1/scrape",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Scrape error for {url}: {e}")
                return None
    
    async def search(
        self,
        query: str,
        limit: int = 10,
        scrape_options: Dict = None,
        tbs: str = None,
        timeout: int = 60
    ) -> Optional[Dict]:
        """
        Search the web
        
        Args:
            query: Search query
            limit: Max number of results
            scrape_options: Options for scraping results
            tbs: Time-based search filter (qdr:d, qdr:w, qdr:m, qdr:y)
            timeout: Request timeout
        
        Returns:
            Search results or None on error
        """
        payload = {
            "query": query,
            "limit": limit
        }
        
        if scrape_options:
            payload["scrapeOptions"] = scrape_options
        
        if tbs:
            payload["tbs"] = tbs
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/v2/search",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Search error for '{query}': {e}")
                return None
    
    async def map_site(
        self,
        url: str,
        limit: int = 100,
        search: str = None,
        timeout: int = 60
    ) -> Optional[Dict]:
        """
        Map a website to discover URLs
        
        Args:
            url: Base URL to map
            limit: Max URLs to return
            search: Filter URLs by search term
            timeout: Request timeout
        
        Returns:
            List of URLs or None on error
        """
        payload = {
            "url": url,
            "limit": limit
        }
        
        if search:
            payload["search"] = search
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/v2/map",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Map error for {url}: {e}")
                return None
    
    async def crawl(
        self,
        url: str,
        limit: int = 100,
        max_depth: int = 3,
        scrape_options: Dict = None,
        timeout: int = 120
    ) -> Optional[str]:
        """
        Start a crawl job (returns job ID for async polling)
        
        Args:
            url: Starting URL
            limit: Max pages to crawl
            max_depth: Max depth to crawl
            scrape_options: Options for scraping
            timeout: Request timeout
        
        Returns:
            Job ID or None on error
        """
        payload = {
            "url": url,
            "limit": limit,
            "maxDiscoveryDepth": max_depth
        }
        
        if scrape_options:
            payload["scrapeOptions"] = scrape_options
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/v2/crawl",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                return data.get("id")
            except Exception as e:
                logger.error(f"Crawl error for {url}: {e}")
                return None
    
    async def get_crawl_status(self, job_id: str, timeout: int = 30) -> Optional[Dict]:
        """Get crawl job status"""
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/v2/crawl/{job_id}",
                    headers=self._headers()
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Crawl status error for job {job_id}: {e}")
                return None
    
    async def agent(
        self,
        prompt: str,
        urls: List[str] = None,
        schema: Dict = None,
        model: str = "spark-1-mini",
        timeout: int = 180
    ) -> Optional[Dict]:
        """
        Use Firecrawl Agent for intelligent data gathering
        
        Args:
            prompt: Natural language description of what data to gather
            urls: Optional URLs to focus on
            schema: JSON schema for structured output
            model: Agent model (spark-1-mini or spark-1-pro)
            timeout: Request timeout
        
        Returns:
            Extracted data or None on error
        """
        payload = {
            "prompt": prompt,
            "model": model
        }
        
        if urls:
            payload["urls"] = urls
        
        if schema:
            payload["schema"] = schema
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{self.BASE_URL}/v2/agent",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Agent error: {e}")
                return None
    
    async def start_agent(
        self,
        prompt: str,
        urls: List[str] = None,
        schema: Dict = None,
        model: str = "spark-1-mini",
        timeout: int = 60
    ) -> Optional[str]:
        """
        Start an agent job (returns job ID for async polling)
        """
        payload = {
            "prompt": prompt,
            "model": model
        }
        
        if urls:
            payload["urls"] = urls
        
        if schema:
            payload["schema"] = schema
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                # Use a different endpoint or wait parameter for async
                response = await client.post(
                    f"{self.BASE_URL}/v2/agent",
                    headers=self._headers(),
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                return data.get("id")
            except Exception as e:
                logger.error(f"Start agent error: {e}")
                return None
    
    async def get_agent_status(self, job_id: str, timeout: int = 30) -> Optional[Dict]:
        """Get agent job status"""
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/v2/agent/{job_id}",
                    headers=self._headers()
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logger.error(f"Agent status error for job {job_id}: {e}")
                return None


class CVESearcher:
    """High-level CVE search utilities using Firecrawl"""
    
    def __init__(self, api_key: str = None):
        self.client = FirecrawlClient(api_key)
    
    async def search_cve_news(self, cve_id: str, limit: int = 10) -> List[Dict]:
        """Search for news about a specific CVE"""
        result = await self.client.search(
            f'"{cve_id}" vulnerability security',
            limit=limit,
            tbs="qdr:w"  # Past week
        )
        
        if result and result.get("success"):
            return result.get("data", {}).get("web", [])
        return []
    
    async def search_cve_exploits(self, cve_id: str, limit: int = 10) -> List[Dict]:
        """Search for exploits related to a CVE"""
        result = await self.client.search(
            f'"{cve_id}" exploit poc proof of concept',
            limit=limit
        )
        
        if result and result.get("success"):
            return result.get("data", {}).get("web", [])
        return []
    
    async def search_trending_cves(self, limit: int = 20) -> Dict:
        """Search for currently trending CVEs"""
        schema = {
            "type": "object",
            "properties": {
                "trending_cves": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cve_id": {"type": "string"},
                            "description": {"type": "string"},
                            "reason_trending": {"type": "string"},
                            "severity": {"type": "string"},
                            "has_exploit": {"type": "boolean"}
                        }
                    }
                }
            }
        }
        
        result = await self.client.agent(
            prompt="Find the most critical and trending CVEs from the past week. Look at security news, CISA alerts, and social media discussions. Include CVEs that are being actively exploited or have new exploits released.",
            schema=schema
        )
        
        if result and result.get("success"):
            return result.get("data", {})
        return {}
    
    async def get_cve_details(self, cve_id: str) -> Dict:
        """Get comprehensive details about a CVE"""
        schema = {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"},
                "description": {"type": "string"},
                "cvss_score": {"type": "number"},
                "severity": {"type": "string"},
                "affected_products": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "affected_vendors": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "has_exploit": {"type": "boolean"},
                "exploit_urls": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "patch_available": {"type": "boolean"},
                "patch_urls": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "references": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        }
        
        result = await self.client.agent(
            prompt=f"Find comprehensive information about {cve_id}. Include the description, CVSS score, affected products and vendors, whether exploits exist, and any patches or mitigations available.",
            schema=schema
        )
        
        if result and result.get("success"):
            return result.get("data", {})
        return {}
    
    async def monitor_security_sources(self) -> Dict:
        """Monitor multiple security sources for new CVEs"""
        sources = [
            "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "https://thehackernews.com/search/label/vulnerability",
            "https://www.bleepingcomputer.com/news/security/",
        ]
        
        schema = {
            "type": "object",
            "properties": {
                "new_cves": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cve_id": {"type": "string"},
                            "title": {"type": "string"},
                            "source": {"type": "string"},
                            "url": {"type": "string"},
                            "date": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        result = await self.client.agent(
            prompt="Find all CVEs mentioned in recent security news and advisories from these sources. Extract the CVE IDs, article titles, and links.",
            urls=sources,
            schema=schema
        )
        
        if result and result.get("success"):
            return result.get("data", {})
        return {}

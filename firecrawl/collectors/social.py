"""
Social and trending CVE collectors (Reddit, News, CVEmon)
Uses Firecrawl for web scraping
"""
import asyncio
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import httpx

from .base import BaseCollector
from .exploits import FirecrawlMixin
from ..models import CVERecord, SocialMention, Reference
from ..config import SOURCES

logger = logging.getLogger(__name__)


class RedditCollector(BaseCollector, FirecrawlMixin):
    """Collector for security community discussions via web search"""
    
    name = "reddit"
    source_type = "social"
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVE discussions using Firecrawl search + deep crawl"""
        logger.info("Collecting CVE mentions from security communities")
        
        records = {}  # CVE ID -> CVERecord
        urls_to_crawl = []  # Collect URLs for deep crawling
        
        # Use Firecrawl search endpoint which works reliably
        search_queries = [
            "CVE 2026 critical vulnerability exploit",
            "CVE 2025 zero-day actively exploited",
            "critical CVE security advisory 2026",
            "CVE patch urgent vulnerability",
        ]
        
        for query in search_queries:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                # Handle both v1 and v2 response formats
                data = result.get("data", {})
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    # Collect URL for deep crawl
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    # Extract CVE IDs from title and description
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        records[cve_id].social_mentions.append(SocialMention(
                            platform="web",
                            url=url,
                            content=title,
                            engagement=0
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.5)  # Rate limiting
        
        # Deep crawl the URLs to find more CVEs
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 10)} URLs for more CVE data")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=10)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                records[cve_id].references.append(Reference(
                    url=url,
                    source="deep_crawl",
                    type="article"
                ))
        
        for record in records.values():
            record.sources_collected.append("community")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from community discussions (with deep crawl)")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Search Reddit for mentions of a specific CVE"""
        cache_key = f"reddit_{cve.cve_id}"
        cached = self._get_cached(cache_key, max_age_hours=6)
        
        if cached:
            for mention in cached:
                if mention.get("timestamp"):
                    mention["timestamp"] = datetime.fromisoformat(mention["timestamp"])
                cve.social_mentions.append(SocialMention(**mention))
            if cached and "reddit" not in cve.sources_collected:
                cve.sources_collected.append("reddit")
            return cve
        
        # Search Reddit for CVE mentions
        result = await self.firecrawl_search(
            f"site:reddit.com {cve.cve_id}",
            limit=10
        )
        
        mentions_found = []
        if result and result.get("success"):
            for item in result.get("data", []):
                url = item.get("url", "")
                if "reddit.com" in url:
                    mention = SocialMention(
                        platform="reddit",
                        url=url,
                        content=item.get("title"),
                        engagement=0
                    )
                    cve.social_mentions.append(mention)
                    mentions_found.append(mention.to_dict())
        
        self._set_cache(cache_key, mentions_found)
        
        if mentions_found and "reddit" not in cve.sources_collected:
            cve.sources_collected.append("reddit")
        
        return cve


class TrendingCollector(BaseCollector, FirecrawlMixin):
    """Collector for trending CVE trackers (CVEmon, etc.)"""
    
    name = "trending"
    source_type = "aggregator"
    
    async def collect(self, **kwargs) -> List[CVERecord]:
        """Collect currently trending CVEs from various trackers"""
        logger.info("Collecting trending CVEs")
        
        records = {}
        
        # Collect from CVEmon
        cvemon_records = await self._collect_cvemon()
        for r in cvemon_records:
            records[r.cve_id] = r
        
        # Also search for "trending CVE" in news
        news_trending = await self._collect_trending_from_news()
        for r in news_trending:
            if r.cve_id in records:
                # Merge
                records[r.cve_id].social_mentions.extend(r.social_mentions)
                records[r.cve_id].references.extend(r.references)
            else:
                records[r.cve_id] = r
        
        logger.info(f"Found {len(records)} trending CVEs")
        return list(records.values())
    
    async def _collect_cvemon(self) -> List[CVERecord]:
        """Collect trending CVEs using Firecrawl search"""
        records = []
        
        # Use search endpoint for trending CVEs
        trending_queries = [
            "trending CVE vulnerability 2026",
            "most exploited CVE January 2026",
            "critical CVE actively exploited now",
        ]
        
        seen_cves = set()
        
        for query in trending_queries:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("web", []) or data.get("results", [])
                
                for item in items:
                    text = f"{item.get('title', '')} {item.get('description', '')}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id in seen_cves:
                            continue
                        seen_cves.add(cve_id)
                        
                        record = CVERecord(
                            cve_id=cve_id,
                            description=item.get("description")
                        )
                        record.trending_score = 50  # Mark as trending
                        record.social_mentions.append(SocialMention(
                            platform="trending",
                            url=item.get("url", ""),
                            engagement=10
                        ))
                        record.sources_collected.append("trending")
                        record.last_updated = datetime.now()
                        records.append(record)
            
            await asyncio.sleep(0.5)
        
        return records
    
    async def _collect_trending_from_news(self) -> List[CVERecord]:
        """Find trending CVEs from news using Firecrawl search"""
        records = []
        seen_cves = set()
        
        # Search for CVE news articles
        news_queries = [
            "site:thehackernews.com CVE 2026",
            "site:bleepingcomputer.com CVE vulnerability 2026",
            "CVE critical vulnerability news January 2026",
        ]
        
        for query in news_queries:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("web", []) or data.get("results", [])
                
                for item in items:
                    text = f"{item.get('title', '')} {item.get('description', '')}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id in seen_cves:
                            continue
                        seen_cves.add(cve_id)
                        
                        record = CVERecord(cve_id=cve_id)
                        record.references.append(Reference(
                            url=item.get("url", ""),
                            source="news",
                            type="article",
                            title=item.get("title")
                        ))
                        record.sources_collected.append("news_trending")
                        record.last_updated = datetime.now()
                        records.append(record)
            
            await asyncio.sleep(0.5)
        
        return records
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Check if CVE is currently trending"""
        # Trending data is ephemeral, just return current record
        return cve


class NewsCollector(BaseCollector, FirecrawlMixin):
    """Collector for security news sites using web search"""
    
    name = "news"
    source_type = "news"
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVE news using Firecrawl search + deep crawl"""
        logger.info("Collecting CVE news from security sites via web search")
        
        records = {}
        urls_to_crawl = []
        
        # Use Firecrawl search which works reliably
        news_queries = [
            "CVE vulnerability security news 2026",
            "critical CVE patch advisory 2026",
            "zero-day CVE exploit 2025 2026",
            "CVE actively exploited vulnerability",
            "site:thehackernews.com CVE",
            "site:bleepingcomputer.com CVE vulnerability",
        ]
        
        for query in news_queries:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    # Collect URL for deep crawl
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    # Extract CVE IDs
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
                        
                        records[cve_id].references.append(Reference(
                            url=url,
                            source="news",
                            type="article",
                            title=title
                        ))
            
            await asyncio.sleep(0.5)
        
        # Deep crawl news articles to find more CVEs
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 15)} news URLs for more CVE data")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=15)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                # Avoid duplicate references
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(
                        url=url,
                        source="news_crawl",
                        type="article"
                    ))
        
        for record in records.values():
            record.sources_collected.append("news")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs in news (with deep crawl)")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Search news for coverage of a specific CVE"""
        cache_key = f"news_{cve.cve_id}"
        cached = self._get_cached(cache_key, max_age_hours=12)
        
        if cached:
            for ref in cached:
                cve.references.append(Reference(**ref))
            if cached and "news" not in cve.sources_collected:
                cve.sources_collected.append("news")
            return cve
        
        # Search for news about this CVE
        result = await self.firecrawl_search(
            f"{cve.cve_id} vulnerability security",
            limit=10
        )
        
        refs_found = []
        if result and result.get("success"):
            for item in result.get("data", []):
                url = item.get("url", "")
                # Filter to known news sources
                if any(s in url for s in ["thehackernews", "bleepingcomputer", "securityweek", "darkreading"]):
                    ref = Reference(
                        url=url,
                        source="news",
                        type="article",
                        title=item.get("title")
                    )
                    cve.references.append(ref)
                    refs_found.append(ref.to_dict())
        
        self._set_cache(cache_key, refs_found)
        
        if refs_found and "news" not in cve.sources_collected:
            cve.sources_collected.append("news")
        
        return cve

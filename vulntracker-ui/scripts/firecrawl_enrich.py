#!/usr/bin/env python3
"""
Firecrawl CVE Enrichment Script

Scans the web for CVE mentions using Firecrawl and updates MongoDB with findings.
This script is designed for manual execution when you want to enrich CVE data
with web intelligence.

Usage:
    python firecrawl_enrich.py --cve CVE-2024-1234     # Enrich specific CVE
    python firecrawl_enrich.py --recent 7              # Enrich CVEs from last 7 days
    python firecrawl_enrich.py --top 50                # Enrich top 50 by CVSS score
    python firecrawl_enrich.py --trending              # Scan for trending CVEs on the web

Environment variables (or .env file):
    MONGODB_URI - MongoDB connection string
    FIRECRAWL_API_KEY - Firecrawl API key
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv
from pymongo import MongoClient
from tqdm import tqdm

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URI = os.getenv("MONGODB_URI")
FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY")
DATABASE_NAME = "vulntracker"
COLLECTION_NAME = "cves"

# Firecrawl API
FIRECRAWL_BASE_URL = "https://api.firecrawl.dev"

# Rate limiting
REQUEST_DELAY = 1.0  # seconds between requests


class FirecrawlClient:
    """Simple Firecrawl API client for CVE intelligence gathering."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    async def search(
        self, query: str, limit: int = 10, tbs: str = None, timeout: int = 60
    ) -> Optional[Dict]:
        """
        Search the web using Firecrawl.

        Args:
            query: Search query
            limit: Max number of results
            tbs: Time-based search filter (qdr:d=day, qdr:w=week, qdr:m=month)
            timeout: Request timeout in seconds

        Returns:
            Search results or None on error
        """
        payload = {"query": query, "limit": limit}

        if tbs:
            payload["tbs"] = tbs

        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{FIRECRAWL_BASE_URL}/v2/search",
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                print(f"  HTTP error searching for '{query}': {e.response.status_code}")
                return None
            except Exception as e:
                print(f"  Error searching for '{query}': {e}")
                return None

    async def scrape(
        self, url: str, formats: List[str] = None, timeout: int = 60
    ) -> Optional[Dict]:
        """
        Scrape a single URL.

        Args:
            url: URL to scrape
            formats: Output formats (markdown, html, links)
            timeout: Request timeout

        Returns:
            Scraped content or None on error
        """
        if formats is None:
            formats = ["markdown"]

        payload = {"url": url, "formats": formats, "onlyMainContent": True}

        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.post(
                    f"{FIRECRAWL_BASE_URL}/v1/scrape",
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
            except Exception as e:
                print(f"  Error scraping {url}: {e}")
                return None


def get_mongodb_client():
    """Create and return MongoDB client."""
    if not MONGODB_URI:
        print("Error: MONGODB_URI environment variable not set")
        sys.exit(1)
    return MongoClient(MONGODB_URI)


def get_firecrawl_client():
    """Create and return Firecrawl client."""
    if not FIRECRAWL_API_KEY:
        print("Error: FIRECRAWL_API_KEY environment variable not set")
        print("Get your API key from https://www.firecrawl.dev/")
        sys.exit(1)
    return FirecrawlClient(FIRECRAWL_API_KEY)


async def search_cve_news(client: FirecrawlClient, cve_id: str) -> List[Dict]:
    """Search for news articles mentioning a CVE."""
    result = await client.search(
        f'"{cve_id}" vulnerability security',
        limit=5,
        tbs="qdr:w",  # Past week
    )

    if result and result.get("success"):
        return result.get("data", [])
    return []


async def search_cve_exploits(client: FirecrawlClient, cve_id: str) -> List[Dict]:
    """Search for exploit information about a CVE."""
    result = await client.search(f'"{cve_id}" exploit poc "proof of concept"', limit=3)

    if result and result.get("success"):
        return result.get("data", [])
    return []


async def search_cve_discussions(client: FirecrawlClient, cve_id: str) -> List[Dict]:
    """Search for discussions about a CVE on forums/Reddit."""
    result = await client.search(
        f'"{cve_id}" site:reddit.com OR site:news.ycombinator.com', limit=3
    )

    if result and result.get("success"):
        return result.get("data", [])
    return []


def extract_source_site(url: str) -> str:
    """Extract the source site name from a URL."""
    try:
        from urllib.parse import urlparse

        domain = urlparse(url).netloc
        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]
        # Map common domains to readable names
        domain_names = {
            "bleepingcomputer.com": "BleepingComputer",
            "thehackernews.com": "The Hacker News",
            "securityweek.com": "SecurityWeek",
            "darkreading.com": "Dark Reading",
            "reddit.com": "Reddit",
            "news.ycombinator.com": "Hacker News",
            "github.com": "GitHub",
            "exploit-db.com": "Exploit-DB",
            "packetstormsecurity.com": "Packet Storm",
            "cisa.gov": "CISA",
            "nvd.nist.gov": "NVD",
            "arstechnica.com": "Ars Technica",
            "threatpost.com": "Threatpost",
            "zdnet.com": "ZDNet",
            "theregister.com": "The Register",
            "wired.com": "Wired",
            "krebsonsecurity.com": "Krebs on Security",
        }
        return domain_names.get(domain, domain)
    except:
        return "Unknown"


async def enrich_single_cve(
    firecrawl: FirecrawlClient, collection, cve_id: str, verbose: bool = True
) -> bool:
    """
    Enrich a single CVE with Firecrawl web intelligence.

    Returns True if any mentions were found.
    """
    if verbose:
        print(f"\nEnriching {cve_id}...")

    mentions = []
    now = datetime.now(timezone.utc)

    # Search for news
    news_results = await search_cve_news(firecrawl, cve_id)
    if verbose and news_results:
        print(f"  Found {len(news_results)} news articles")

    for result in news_results[:3]:  # Top 3 news
        mentions.append(
            {
                "title": result.get("title", "")[:200],
                "url": result.get("url", ""),
                "snippet": (result.get("description") or result.get("content", ""))[
                    :200
                ],
                "source_site": extract_source_site(result.get("url", "")),
                "found_at": now.isoformat(),
                "type": "news",
            }
        )

    # Small delay between searches
    await asyncio.sleep(REQUEST_DELAY)

    # Search for exploits
    exploit_results = await search_cve_exploits(firecrawl, cve_id)
    if verbose and exploit_results:
        print(f"  Found {len(exploit_results)} exploit references")

    for result in exploit_results[:2]:  # Top 2 exploits
        mentions.append(
            {
                "title": result.get("title", "")[:200],
                "url": result.get("url", ""),
                "snippet": (result.get("description") or result.get("content", ""))[
                    :200
                ],
                "source_site": extract_source_site(result.get("url", "")),
                "found_at": now.isoformat(),
                "type": "exploit",
            }
        )

    await asyncio.sleep(REQUEST_DELAY)

    # Search for discussions
    discussion_results = await search_cve_discussions(firecrawl, cve_id)
    if verbose and discussion_results:
        print(f"  Found {len(discussion_results)} discussions")

    for result in discussion_results[:2]:  # Top 2 discussions
        mentions.append(
            {
                "title": result.get("title", "")[:200],
                "url": result.get("url", ""),
                "snippet": (result.get("description") or result.get("content", ""))[
                    :200
                ],
                "source_site": extract_source_site(result.get("url", "")),
                "found_at": now.isoformat(),
                "type": "discussion",
            }
        )

    if not mentions:
        if verbose:
            print(f"  No web mentions found for {cve_id}")
        return False

    # Build firecrawl source entry
    firecrawl_source = {
        "source": "firecrawl",
        "first_seen": now.isoformat(),
        "url": None,  # No single URL, has multiple mentions
        "mentions": mentions,
    }

    # Update MongoDB
    # First, remove any existing firecrawl source entry, then add the new one
    result = collection.update_one(
        {"_id": cve_id},
        [
            {
                "$set": {
                    "sources": {
                        "$concatArrays": [
                            # Remove existing firecrawl entries
                            {
                                "$filter": {
                                    "input": {"$ifNull": ["$sources", []]},
                                    "as": "s",
                                    "cond": {"$ne": ["$$s.source", "firecrawl"]},
                                }
                            },
                            # Add new firecrawl entry at the beginning
                            [firecrawl_source],
                        ]
                    },
                    "firecrawl_last_scan": now,
                }
            }
        ],
    )

    if verbose:
        print(f"  Added {len(mentions)} mentions to {cve_id}")

    return True


async def enrich_cves(cve_ids: List[str], verbose: bool = True) -> Dict[str, int]:
    """Enrich multiple CVEs with Firecrawl data."""
    client = get_mongodb_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    firecrawl = get_firecrawl_client()

    stats = {"processed": 0, "enriched": 0, "errors": 0}

    for cve_id in tqdm(cve_ids, desc="Enriching CVEs", disable=verbose):
        try:
            enriched = await enrich_single_cve(firecrawl, collection, cve_id, verbose)
            stats["processed"] += 1
            if enriched:
                stats["enriched"] += 1
        except Exception as e:
            print(f"Error enriching {cve_id}: {e}")
            stats["errors"] += 1

        # Rate limiting
        await asyncio.sleep(REQUEST_DELAY)

    client.close()
    return stats


async def enrich_recent_cves(days: int = 7, limit: int = 100):
    """Enrich CVEs published in the last N days."""
    print(f"\nFetching CVEs from the last {days} days...")

    client = get_mongodb_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Find recent CVEs without firecrawl data
    cves = list(
        collection.find(
            {
                "created_at": {"$gte": cutoff},
                "$or": [
                    {"firecrawl_last_scan": {"$exists": False}},
                    {"firecrawl_last_scan": None},
                ],
            },
            {"_id": 1},
        )
        .sort("created_at", -1)
        .limit(limit)
    )

    client.close()

    if not cves:
        print("No recent CVEs need enrichment")
        return

    cve_ids = [c["_id"] for c in cves]
    print(f"Found {len(cve_ids)} CVEs to enrich")

    stats = await enrich_cves(cve_ids)
    print_stats(stats)


async def enrich_top_cves(limit: int = 50):
    """Enrich top CVEs by CVSS score without firecrawl data."""
    print(f"\nFetching top {limit} CVEs by severity...")

    client = get_mongodb_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    # Find high-severity CVEs without firecrawl data
    cves = list(
        collection.find(
            {
                "$or": [
                    {"firecrawl_last_scan": {"$exists": False}},
                    {"firecrawl_last_scan": None},
                ]
            },
            {"_id": 1},
        )
        .sort("metrics.cvssV3_1.data.score", -1)
        .limit(limit)
    )

    client.close()

    if not cves:
        print("No CVEs need enrichment")
        return

    cve_ids = [c["_id"] for c in cves]
    print(f"Found {len(cve_ids)} CVEs to enrich")

    stats = await enrich_cves(cve_ids)
    print_stats(stats)


async def scan_trending_cves():
    """Scan the web for trending CVEs and add them to the database."""
    print("\nScanning for trending CVEs on the web...")

    firecrawl = get_firecrawl_client()
    client = get_mongodb_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    # Search for trending CVE mentions
    queries = [
        "critical CVE vulnerability 2024 2025",
        "CVE exploit actively exploited",
        "zero day CVE vulnerability",
    ]

    found_cves = set()

    for query in queries:
        print(f"  Searching: {query}")
        result = await firecrawl.search(query, limit=10, tbs="qdr:w")

        if result and result.get("success"):
            for item in result.get("data", []):
                content = (
                    item.get("title", "") + " " + item.get("description", "")
                ).upper()
                # Extract CVE IDs from content
                import re

                cve_matches = re.findall(r"CVE-\d{4}-\d+", content)
                found_cves.update(cve_matches)

        await asyncio.sleep(REQUEST_DELAY)

    if not found_cves:
        print("No trending CVEs found")
        return

    print(
        f"\nFound {len(found_cves)} trending CVEs: {', '.join(list(found_cves)[:10])}..."
    )

    # Enrich each found CVE
    stats = await enrich_cves(list(found_cves), verbose=True)
    print_stats(stats)

    client.close()


def print_stats(stats: Dict[str, int]):
    """Print enrichment statistics."""
    print("\n" + "=" * 40)
    print("Enrichment Complete!")
    print("=" * 40)
    print(f"  Processed: {stats['processed']}")
    print(f"  Enriched:  {stats['enriched']}")
    print(f"  Errors:    {stats['errors']}")


async def main():
    parser = argparse.ArgumentParser(
        description="Enrich CVE data with Firecrawl web intelligence"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--cve", type=str, help="Enrich a specific CVE (e.g., CVE-2024-1234)"
    )
    group.add_argument(
        "--recent", type=int, metavar="DAYS", help="Enrich CVEs from the last N days"
    )
    group.add_argument(
        "--top", type=int, metavar="N", help="Enrich top N CVEs by severity"
    )
    group.add_argument(
        "--trending",
        action="store_true",
        help="Scan for and enrich trending CVEs on the web",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of CVEs to process (default: 100)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Firecrawl CVE Enrichment Script")
    print("=" * 60)

    if args.cve:
        stats = await enrich_cves([args.cve.upper()])
        print_stats(stats)
    elif args.recent:
        await enrich_recent_cves(days=args.recent, limit=args.limit)
    elif args.top:
        await enrich_top_cves(limit=args.top)
    elif args.trending:
        await scan_trending_cves()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nEnrichment cancelled by user")
        sys.exit(1)

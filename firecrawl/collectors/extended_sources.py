"""
Extended CVE Collectors - Additional High-Signal Sources
Covers: Mailing lists, Social media, Research blogs, OSINT aggregators
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import List, Dict, Optional

from .base import BaseCollector
from .exploits import FirecrawlMixin
from ..models import CVERecord, Reference, SocialMention

logger = logging.getLogger(__name__)


class MailingListCollector(BaseCollector, FirecrawlMixin):
    """Collector for security mailing lists via web search
    
    Sources:
    - Full Disclosure (seclists.org)
    - oss-security (openwall)
    - Debian Security Announce
    - Ubuntu Security Notices
    - SANS @Risk
    """
    
    name = "mailing_lists"
    source_type = "mailing_list"
    
    SEARCH_QUERIES = [
        # Full Disclosure
        "site:seclists.org/fulldisclosure CVE 2026",
        "site:seclists.org/fulldisclosure CVE 2025",
        # oss-security
        "site:openwall.com/lists/oss-security CVE 2026",
        "site:openwall.com/lists/oss-security CVE 2025",
        # Debian Security
        "site:lists.debian.org/debian-security-announce CVE",
        "site:debian.org/security DSA CVE",
        # Ubuntu Security
        "site:ubuntu.com/security/notices CVE",
        # Packet Storm
        "site:packetstormsecurity.com CVE 2026",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from security mailing list archives"""
        logger.info("Collecting CVEs from security mailing lists")
        
        records = {}
        urls_to_crawl = []
        
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        # Determine source from URL
                        source = "mailing_list"
                        if "seclists.org" in url:
                            source = "full_disclosure"
                        elif "openwall.com" in url:
                            source = "oss_security"
                        elif "debian" in url:
                            source = "debian_security"
                        elif "ubuntu" in url:
                            source = "ubuntu_security"
                        elif "packetstorm" in url:
                            source = "packetstorm"
                        
                        records[cve_id].references.append(Reference(
                            url=url,
                            source=source,
                            type="mailing_list",
                            title=title
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.5)
        
        # Deep crawl for more CVEs
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 10)} mailing list URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=10)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(
                        url=url,
                        source="mailing_list_crawl",
                        type="mailing_list"
                    ))
        
        for record in records.values():
            record.sources_collected.append("mailing_lists")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from mailing lists")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class SocialMediaCollector(BaseCollector, FirecrawlMixin):
    """Collector for social media CVE mentions via web search
    
    Sources:
    - Twitter/X (via search results, not direct API)
    - Reddit security subreddits
    - Hacker News discussions
    - Mastodon infosec
    """
    
    name = "social_media"
    source_type = "social"
    
    SEARCH_QUERIES = [
        # Twitter/X mentions (indexed by search engines)
        "site:twitter.com CVE 2026 vulnerability",
        "site:x.com CVE 2026 exploit",
        "site:twitter.com CVE 2025 zero-day",
        "site:twitter.com CVE actively exploited",
        "site:x.com CVE proof of concept",
        # Security influencer tweets (indexed)
        "CVE site:twitter.com security researcher",
        "CVE site:twitter.com bug bounty",
        "CVE site:twitter.com infosec",
        # Reddit security subreddits
        "site:reddit.com/r/netsec CVE",
        "site:reddit.com/r/cybersecurity CVE vulnerability",
        "site:reddit.com/r/blueteamsec CVE",
        "site:reddit.com/r/sysadmin CVE patch",
        "site:reddit.com/r/AskNetsec CVE",
        "site:reddit.com/r/redteamsec CVE exploit",
        # Hacker News
        "site:news.ycombinator.com CVE vulnerability",
        "site:news.ycombinator.com CVE exploit",
        "site:news.ycombinator.com security vulnerability",
        # Mastodon infosec
        "site:infosec.exchange CVE",
        "site:mastodon.social CVE vulnerability",
        # YouTube security channels
        "site:youtube.com CVE vulnerability explained",
        "site:youtube.com CVE exploit demonstration",
        "site:youtube.com CVE security analysis",
        # LinkedIn security discussions
        "site:linkedin.com CVE vulnerability security",
        "site:linkedin.com CVE patch advisory",
        # Technical forums
        "site:security.stackexchange.com CVE",
        "site:serverfault.com CVE vulnerability",
        "site:stackoverflow.com CVE security fix",
        # Medium/Dev.to security articles
        "site:medium.com CVE vulnerability analysis",
        "site:dev.to CVE security",
        # Security newsletters (archived)
        "site:tldrsec.com CVE",
        # General social buzz
        "CVE 2026 trending vulnerability twitter",
        "CVE 2025 actively exploited social media",
        "CVE going viral security",
        "CVE everyone talking about",
        "CVE breaking news security",
        "CVE proof of concept released",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVE mentions from social media via web search"""
        logger.info("Collecting CVEs from social media mentions")
        
        records = {}
        urls_to_crawl = []
        
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        # Determine platform
                        platform = "social"
                        if "twitter.com" in url or "x.com" in url:
                            platform = "twitter"
                        elif "reddit.com" in url:
                            platform = "reddit"
                        elif "ycombinator" in url or "news.ycombinator" in url:
                            platform = "hackernews"
                        elif "mastodon" in url or "infosec.exchange" in url:
                            platform = "mastodon"
                        elif "youtube.com" in url:
                            platform = "youtube"
                        elif "linkedin.com" in url:
                            platform = "linkedin"
                        elif "stackexchange.com" in url or "stackoverflow.com" in url or "serverfault.com" in url:
                            platform = "stackexchange"
                        elif "medium.com" in url:
                            platform = "medium"
                        elif "dev.to" in url:
                            platform = "devto"
                        
                        records[cve_id].social_mentions.append(SocialMention(
                            platform=platform,
                            url=url,
                            content=title,
                            engagement=0
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.5)
        
        # Deep crawl social posts for more context
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 15)} social media URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=15)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                records[cve_id].social_mentions.append(SocialMention(
                    platform="social_crawl",
                    url=url,
                    engagement=0
                ))
        
        for record in records.values():
            record.sources_collected.append("social_media")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from social media")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class ResearchBlogCollector(BaseCollector, FirecrawlMixin):
    """Collector for security research blogs
    
    Sources:
    - Google Project Zero
    - Trail of Bits
    - Microsoft MSRC
    - Cisco Talos
    - CrowdStrike
    - Mandiant
    - Unit 42 (Palo Alto)
    - Rapid7
    - Qualys
    - Tenable
    """
    
    name = "research_blogs"
    source_type = "research"
    
    SEARCH_QUERIES = [
        # Major research teams
        "site:googleprojectzero.blogspot.com CVE",
        "site:blog.trailofbits.com CVE vulnerability",
        "site:msrc.microsoft.com CVE",
        "site:blog.talosintelligence.com CVE",
        # Vendor security blogs
        "site:crowdstrike.com/blog CVE",
        "site:mandiant.com/resources CVE",
        "site:unit42.paloaltonetworks.com CVE",
        "site:rapid7.com/blog CVE vulnerability",
        "site:blog.qualys.com CVE",
        "site:tenable.com/blog CVE",
        # General research
        "security research blog CVE 2026 analysis",
        "CVE 2025 exploit analysis writeup",
        "zero-day CVE technical analysis 2026",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from security research blogs"""
        logger.info("Collecting CVEs from security research blogs")
        
        records = {}
        urls_to_crawl = []
        
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        # Determine source
                        source = "research_blog"
                        if "projectzero" in url:
                            source = "project_zero"
                        elif "trailofbits" in url:
                            source = "trail_of_bits"
                        elif "msrc" in url or "microsoft" in url:
                            source = "msrc"
                        elif "talos" in url:
                            source = "cisco_talos"
                        elif "crowdstrike" in url:
                            source = "crowdstrike"
                        elif "mandiant" in url:
                            source = "mandiant"
                        elif "unit42" in url:
                            source = "unit42"
                        elif "rapid7" in url:
                            source = "rapid7"
                        elif "qualys" in url:
                            source = "qualys"
                        elif "tenable" in url:
                            source = "tenable"
                        
                        records[cve_id].references.append(Reference(
                            url=url,
                            source=source,
                            type="research",
                            title=title
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.5)
        
        # Deep crawl research posts for complete CVE list
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 12)} research blog URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=12)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(
                        url=url,
                        source="research_crawl",
                        type="research"
                    ))
        
        for record in records.values():
            record.sources_collected.append("research_blogs")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from research blogs")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class OSINTAggregatorCollector(BaseCollector, FirecrawlMixin):
    """Collector for OSINT vulnerability aggregators
    
    Sources:
    - Vulners
    - OpenCVE
    - CVEmon / CVE Trends
    - VulDB
    - Snyk vulnerability DB
    """
    
    name = "osint_aggregators"
    source_type = "osint"
    
    SEARCH_QUERIES = [
        # Vulners
        "site:vulners.com CVE 2026",
        "site:vulners.com CVE 2025 exploit",
        # OpenCVE
        "site:opencve.io CVE 2026",
        # VulDB
        "site:vuldb.com CVE 2026",
        "site:vuldb.com CVE 2025",
        # Snyk
        "site:snyk.io/vuln CVE",
        "site:security.snyk.io CVE",
        # CVE Details
        "site:cvedetails.com CVE 2026",
        # Exploit references
        "CVE 2026 exploit available vulners",
        "CVE 2025 proof of concept public",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from OSINT aggregator platforms"""
        logger.info("Collecting CVEs from OSINT aggregators")
        
        records = {}
        urls_to_crawl = []
        
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        # Determine source
                        source = "osint"
                        if "vulners.com" in url:
                            source = "vulners"
                        elif "opencve.io" in url:
                            source = "opencve"
                        elif "vuldb.com" in url:
                            source = "vuldb"
                        elif "snyk" in url:
                            source = "snyk"
                        elif "cvedetails" in url:
                            source = "cvedetails"
                        
                        records[cve_id].references.append(Reference(
                            url=url,
                            source=source,
                            type="osint",
                            title=title
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.5)
        
        # Deep crawl OSINT pages
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 10)} OSINT URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=10)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(
                        url=url,
                        source="osint_crawl",
                        type="osint"
                    ))
        
        for record in records.values():
            record.sources_collected.append("osint_aggregators")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from OSINT aggregators")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class VendorAdvisoryCollector(BaseCollector, FirecrawlMixin):
    """Collector for vendor security advisories (PSIRTs)
    
    Sources:
    - Microsoft Security Update Guide
    - Cisco Security Advisories
    - Oracle Critical Patch Updates
    - Adobe Security Bulletins
    - VMware Security Advisories
    - Fortinet PSIRT
    - Ivanti Security Advisories
    """
    
    name = "vendor_advisories"
    source_type = "vendor"
    
    SEARCH_QUERIES = [
        # Microsoft
        "site:msrc.microsoft.com CVE 2026",
        "site:msrc.microsoft.com CVE 2025 security update",
        # Cisco
        "site:sec.cloudapps.cisco.com CVE",
        "site:tools.cisco.com/security/center CVE",
        # Oracle
        "site:oracle.com/security-alerts CVE",
        # Adobe
        "site:helpx.adobe.com/security CVE",
        # VMware
        "site:vmware.com/security/advisories CVE",
        # Fortinet
        "site:fortiguard.com/psirt CVE",
        # Ivanti
        "site:forums.ivanti.com/s/article CVE security",
        # General vendor advisories
        "vendor security advisory CVE 2026 critical",
        "PSIRT advisory CVE 2025 patch",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from vendor security advisories"""
        logger.info("Collecting CVEs from vendor advisories")
        
        records = {}
        urls_to_crawl = []
        
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        
                        # Determine vendor
                        vendor = "vendor"
                        if "microsoft" in url or "msrc" in url:
                            vendor = "microsoft"
                        elif "cisco" in url:
                            vendor = "cisco"
                        elif "oracle" in url:
                            vendor = "oracle"
                        elif "adobe" in url:
                            vendor = "adobe"
                        elif "vmware" in url:
                            vendor = "vmware"
                        elif "fortinet" in url or "fortiguard" in url:
                            vendor = "fortinet"
                        elif "ivanti" in url:
                            vendor = "ivanti"
                        
                        records[cve_id].references.append(Reference(
                            url=url,
                            source=f"{vendor}_advisory",
                            type="vendor_advisory",
                            title=title
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
                        
                        # Add to affected vendors
                        if vendor != "vendor" and vendor not in records[cve_id].affected_vendors:
                            records[cve_id].affected_vendors.append(vendor)
            
            await asyncio.sleep(0.5)
        
        # Deep crawl vendor advisories
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 10)} vendor advisory URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=10)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(
                        url=url,
                        source="vendor_crawl",
                        type="vendor_advisory"
                    ))
        
        for record in records.values():
            record.sources_collected.append("vendor_advisories")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from vendor advisories")
        return list(records.values())
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class SocialBuzzCollector(BaseCollector, FirecrawlMixin):
    """Collector focused on trending/viral CVE discussions
    
    Tracks:
    - CVEs going viral on social media
    - Breaking security news
    - Influencer discussions
    - Conference/event mentions
    - Real-time buzz patterns
    """
    
    name = "social_buzz"
    source_type = "trending"
    
    BUZZ_QUERIES = [
        # Viral/trending signals
        "CVE going viral security twitter",
        "CVE everyone talking about today",
        "CVE breaking news security",
        "CVE trending now",
        "CVE 2026 hottest vulnerability",
        "CVE 2025 most discussed",
        # Exploit release announcements
        "CVE proof of concept just released",
        "CVE exploit code published",
        "CVE 0day dropped",
        "CVE weaponized exploit",
        # Active exploitation signals
        "CVE actively exploited wild",
        "CVE mass exploitation",
        "CVE ransomware using",
        "CVE APT exploiting",
        # Conference/event mentions
        "CVE BlackHat",
        "CVE DEF CON",
        "CVE Pwn2Own",
        # Security community buzz
        "CVE infosec community reaction",
        "CVE security researchers warning",
        "CVE patch immediately urgent",
        "CVE critical patch now",
        # Platform-specific trending
        "site:twitter.com CVE trending",
        "site:reddit.com CVE hot post",
        "site:news.ycombinator.com CVE top",
    ]
    
    HIGH_SIGNAL_PLATFORMS = ["twitter", "hackernews", "reddit", "youtube"]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect trending/viral CVE mentions"""
        logger.info("Collecting trending CVE buzz from social platforms")
        
        records = {}
        platform_counts = {}
        urls_to_crawl = []
        
        for query in self.BUZZ_QUERIES:
            result = await self.firecrawl_search(query, limit=15)
            
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    
                    if url and url not in urls_to_crawl:
                        urls_to_crawl.append(url)
                    
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    platform = self._detect_platform(url)
                    
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                            platform_counts[cve_id] = set()
                        
                        platform_counts[cve_id].add(platform)
                        
                        records[cve_id].social_mentions.append(SocialMention(
                            platform=platform,
                            url=url,
                            content=title,
                            engagement=10 if platform in self.HIGH_SIGNAL_PLATFORMS else 5
                        ))
                        
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            
            await asyncio.sleep(0.3)
        
        logger.info(f"Deep crawling {min(len(urls_to_crawl), 20)} buzz URLs")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=20)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
                platform_counts[cve_id] = set()
            for url in source_urls:
                platform = self._detect_platform(url)
                platform_counts[cve_id].add(platform)
                records[cve_id].social_mentions.append(SocialMention(
                    platform=f"{platform}_crawl",
                    url=url,
                    engagement=5
                ))
        
        for cve_id, record in records.items():
            record.sources_collected.append("social_buzz")
            record.last_updated = datetime.now()
            
            num_platforms = len(platform_counts.get(cve_id, set()))
            if num_platforms >= 4:
                record.trending_score = 100
            elif num_platforms >= 3:
                record.trending_score = max(record.trending_score, 75)
            elif num_platforms >= 2:
                record.trending_score = max(record.trending_score, 50)
            else:
                record.trending_score = max(record.trending_score, 25)
        
        logger.info(f"Found {len(records)} trending CVEs from social buzz")
        return list(records.values())
    
    def _detect_platform(self, url: str) -> str:
        """Detect platform from URL"""
        url_lower = url.lower()
        if "twitter.com" in url_lower or "x.com" in url_lower:
            return "twitter"
        elif "reddit.com" in url_lower:
            return "reddit"
        elif "ycombinator" in url_lower:
            return "hackernews"
        elif "youtube.com" in url_lower:
            return "youtube"
        elif "linkedin.com" in url_lower:
            return "linkedin"
        elif "mastodon" in url_lower or "infosec.exchange" in url_lower:
            return "mastodon"
        elif "medium.com" in url_lower:
            return "medium"
        elif "thehackernews.com" in url_lower:
            return "hackernews_site"
        elif "bleepingcomputer" in url_lower:
            return "bleepingcomputer"
        return "web"
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class SecurityAdvisoryCollector(BaseCollector, FirecrawlMixin):
    """Collector for security mailing list archives via direct scraping
    
    Sources:
    - oss-security (Openwall) - Direct archive crawling
    - Full Disclosure (SecLists) - Direct archive crawling
    """
    
    name = "security_advisories"
    source_type = "mailing_list"
    
    # Direct URLs to scrape/map
    DIRECT_SOURCES = [
        {"name": "oss_security", "base_url": "https://www.openwall.com/lists/oss-security/", "type": "mailing_list"},
        {"name": "full_disclosure", "base_url": "https://seclists.org/fulldisclosure/", "type": "mailing_list"},
    ]
    
    SEARCH_QUERIES = [
        "site:openwall.com/lists/oss-security CVE 2026",
        "site:openwall.com/lists/oss-security vulnerability disclosure",
        "site:seclists.org/fulldisclosure CVE 2026",
        "site:seclists.org/fulldisclosure exploit",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from security mailing list archives"""
        logger.info("Collecting CVEs from security advisory archives (oss-security, Full Disclosure)")
        
        records = {}
        all_urls = []
        
        # Step 1: Map each direct source to discover pages
        for source in self.DIRECT_SOURCES:
            logger.info(f"Mapping {source['name']}: {source['base_url']}")
            try:
                map_result = await self.firecrawl_map(source["base_url"], limit=50)
                if map_result and map_result.get("success"):
                    links = map_result.get("data", {}).get("links", [])
                    if isinstance(links, list):
                        for link in links:
                            if isinstance(link, str) and ("2026" in link or "2025" in link):
                                all_urls.append({"url": link, "source": source["name"]})
            except Exception as e:
                logger.warning(f"Error mapping {source['name']}: {e}")
            await asyncio.sleep(0.5)
        
        # Step 2: Search for additional coverage
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=15)
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    if url:
                        source_name = "oss_security" if "openwall" in url else "full_disclosure"
                        all_urls.append({"url": url, "source": source_name})
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        records[cve_id].references.append(Reference(url=url, source=source_name, type="mailing_list", title=title))
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            await asyncio.sleep(0.3)
        
        # Step 3: Deep crawl discovered URLs
        unique_urls = list({u["url"]: u for u in all_urls}.values())
        urls_to_crawl = [u["url"] for u in unique_urls[:30]]
        logger.info(f"Deep crawling {len(urls_to_crawl)} mailing list archive pages")
        cve_sources = await self.firecrawl_deep_crawl(urls_to_crawl, max_pages=30)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    source_name = "oss_security" if "openwall" in url else "full_disclosure" if "seclists" in url else "mailing_list"
                    records[cve_id].references.append(Reference(url=url, source=source_name, type="mailing_list"))
        
        for record in records.values():
            record.sources_collected.append("security_advisories")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from security advisory archives")
        return list(records.values())
    
    async def firecrawl_map(self, url: str, limit: int = 100) -> Optional[Dict]:
        """Map a website to discover all pages"""
        import httpx
        from ..config import FIRECRAWL_API_KEY
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.firecrawl.dev/v1/map",
                    headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}", "Content-Type": "application/json"},
                    json={"url": url, "limit": limit}
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.warning(f"Map error for {url}: {e}")
            return None
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class CERTFeedCollector(BaseCollector, FirecrawlMixin):
    """Collector for CERT and Government security advisories
    
    Sources: CISA, CERT-EU, JPCERT/CC
    """
    
    name = "cert_feeds"
    source_type = "cert"
    
    DIRECT_SOURCES = [
        {"name": "cisa_advisories", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories", "type": "cert"},
        {"name": "cert_eu", "url": "https://cert.europa.eu/publications/security-advisories/", "type": "cert"},
        {"name": "jpcert", "url": "https://www.jpcert.or.jp/english/at/", "type": "cert"},
    ]
    
    RSS_FEEDS = [
        {"name": "cert_eu_rss", "url": "https://cert.europa.eu/rss", "source": "cert_eu"},
    ]
    
    SEARCH_QUERIES = [
        "site:cisa.gov cybersecurity advisory CVE 2026",
        "site:cisa.gov ICS advisory CVE",
        "site:cert.europa.eu security advisory CVE",
        "site:jpcert.or.jp security alert CVE",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from CERT and government advisory sources"""
        logger.info("Collecting CVEs from CERT feeds (CISA, CERT-EU, JPCERT)")
        
        records = {}
        urls_to_crawl = []
        
        # Step 1: Scrape direct advisory pages
        for source in self.DIRECT_SOURCES:
            logger.info(f"Scraping {source['name']}: {source['url']}")
            try:
                scrape_result = await self.firecrawl_scrape_url(source["url"])
                if scrape_result and scrape_result.get("success"):
                    data = scrape_result.get("data", {})
                    content = data.get("markdown", "") or data.get("content", "")
                    cve_ids = self.parse_cve_id(content)
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        records[cve_id].references.append(Reference(url=source["url"], source=source["name"], type="cert_advisory"))
                    links = data.get("links", [])
                    if isinstance(links, list):
                        for link in links[:20]:
                            link_url = link if isinstance(link, str) else link.get("url", "")
                            if link_url:
                                urls_to_crawl.append(link_url)
                    logger.info(f"Found {len(cve_ids)} CVEs from {source['name']}")
            except Exception as e:
                logger.warning(f"Error scraping {source['name']}: {e}")
            await asyncio.sleep(0.5)
        
        # Step 2: Parse RSS feeds
        for feed in self.RSS_FEEDS:
            try:
                rss_cves = await self._parse_rss_feed(feed["url"], feed["source"])
                for cve_id, refs in rss_cves.items():
                    if cve_id not in records:
                        records[cve_id] = CVERecord(cve_id=cve_id)
                    records[cve_id].references.extend(refs)
            except Exception as e:
                logger.warning(f"Error parsing RSS {feed['name']}: {e}")
        
        # Step 3: Search queries
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=10)
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    if url:
                        urls_to_crawl.append(url)
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        source_name = self._detect_cert_source(url)
                        records[cve_id].references.append(Reference(url=url, source=source_name, type="cert_advisory", title=title))
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            await asyncio.sleep(0.3)
        
        # Step 4: Deep crawl
        unique_urls = list(set(urls_to_crawl))[:25]
        logger.info(f"Deep crawling {len(unique_urls)} CERT advisory pages")
        cve_sources = await self.firecrawl_deep_crawl(unique_urls, max_pages=25)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(url=url, source=self._detect_cert_source(url), type="cert_advisory"))
        
        for record in records.values():
            record.sources_collected.append("cert_feeds")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from CERT feeds")
        return list(records.values())
    
    async def _parse_rss_feed(self, url: str, source: str) -> Dict[str, List[Reference]]:
        """Parse RSS feed and extract CVE references"""
        import httpx
        cve_refs = {}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                content = response.text
                items = re.findall(r'<item>(.*?)</item>', content, re.DOTALL)
                for item in items:
                    title_match = re.search(r'<title>(.*?)</title>', item)
                    link_match = re.search(r'<link>(.*?)</link>', item)
                    title = title_match.group(1) if title_match else ""
                    link = link_match.group(1) if link_match else ""
                    title = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', title)
                    cve_ids = self.parse_cve_id(item)
                    for cve_id in cve_ids:
                        if cve_id not in cve_refs:
                            cve_refs[cve_id] = []
                        if link:
                            cve_refs[cve_id].append(Reference(url=link, source=source, type="rss_feed", title=title[:200] if title else None))
        except Exception as e:
            logger.warning(f"RSS parse error for {url}: {e}")
        return cve_refs
    
    async def firecrawl_scrape_url(self, url: str) -> Optional[Dict]:
        """Scrape a single URL"""
        import httpx
        from ..config import FIRECRAWL_API_KEY
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.firecrawl.dev/v1/scrape",
                    headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}", "Content-Type": "application/json"},
                    json={"url": url, "formats": ["markdown", "links"]}
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.warning(f"Scrape error for {url}: {e}")
            return None
    
    def _detect_cert_source(self, url: str) -> str:
        url_lower = url.lower()
        if "cisa.gov" in url_lower:
            return "cisa"
        elif "cert.europa.eu" in url_lower:
            return "cert_eu"
        elif "jpcert" in url_lower:
            return "jpcert"
        return "cert"
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve


class VendorPSIRTCollector(BaseCollector, FirecrawlMixin):
    """Collector for Vendor PSIRT advisories: Microsoft MSRC, Cisco PSIRT, Red Hat"""
    
    name = "vendor_psirt"
    source_type = "vendor"
    
    DIRECT_SOURCES = [
        {"name": "msrc", "url": "https://msrc.microsoft.com/update-guide", "type": "vendor_advisory"},
        {"name": "cisco_psirt", "url": "https://tools.cisco.com/security/center/publicationListing.x", "type": "vendor_advisory"},
        {"name": "redhat", "url": "https://access.redhat.com/security/security-updates/", "type": "vendor_advisory"},
    ]
    
    RSS_FEEDS = [
        {"name": "cisco_rss", "url": "https://tools.cisco.com/security/center/psirtRss20.xml", "source": "cisco_psirt"},
        {"name": "redhat_rss", "url": "https://access.redhat.com/security/data/metrics/rhsamap.xml", "source": "redhat"},
    ]
    
    SEARCH_QUERIES = [
        "site:msrc.microsoft.com CVE 2026",
        "site:msrc.microsoft.com security update CVE",
        "site:tools.cisco.com/security CVE 2026",
        "cisco-sa CVE 2026",
        "site:access.redhat.com/security CVE 2026",
        "site:access.redhat.com RHSA CVE",
    ]
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect CVEs from vendor PSIRT sources"""
        logger.info("Collecting CVEs from Vendor PSIRTs (Microsoft, Cisco, Red Hat)")
        
        records = {}
        urls_to_crawl = []
        
        # Step 1: Scrape direct advisory pages
        for source in self.DIRECT_SOURCES:
            logger.info(f"Scraping {source['name']}: {source['url']}")
            try:
                scrape_result = await self.firecrawl_scrape_url(source["url"])
                if scrape_result and scrape_result.get("success"):
                    data = scrape_result.get("data", {})
                    content = data.get("markdown", "") or data.get("content", "")
                    cve_ids = self.parse_cve_id(content)
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        records[cve_id].references.append(Reference(url=source["url"], source=source["name"], type="vendor_advisory"))
                    links = data.get("links", [])
                    if isinstance(links, list):
                        for link in links[:30]:
                            link_url = link if isinstance(link, str) else link.get("url", "")
                            if link_url and ("CVE" in link_url.upper() or "advisory" in link_url.lower()):
                                urls_to_crawl.append(link_url)
                    logger.info(f"Found {len(cve_ids)} CVEs from {source['name']}")
            except Exception as e:
                logger.warning(f"Error scraping {source['name']}: {e}")
            await asyncio.sleep(0.5)
        
        # Step 2: Parse RSS feeds
        for feed in self.RSS_FEEDS:
            logger.info(f"Parsing RSS feed: {feed['name']}")
            try:
                rss_cves = await self._parse_rss_feed(feed["url"], feed["source"])
                for cve_id, refs in rss_cves.items():
                    if cve_id not in records:
                        records[cve_id] = CVERecord(cve_id=cve_id)
                    records[cve_id].references.extend(refs)
                logger.info(f"Found {len(rss_cves)} CVEs from {feed['name']} RSS")
            except Exception as e:
                logger.warning(f"Error parsing RSS {feed['name']}: {e}")
        
        # Step 3: Search queries
        for query in self.SEARCH_QUERIES:
            result = await self.firecrawl_search(query, limit=15)
            if result and result.get("success"):
                data = result.get("data", {})
                items = data if isinstance(data, list) else data.get("web", []) or data.get("results", [])
                for item in items:
                    url = item.get("url", "")
                    title = item.get("title", "")
                    description = item.get("description", "") or item.get("snippet", "")
                    if url:
                        urls_to_crawl.append(url)
                    text = f"{title} {description}"
                    cve_ids = self.parse_cve_id(text)
                    for cve_id in cve_ids:
                        if cve_id not in records:
                            records[cve_id] = CVERecord(cve_id=cve_id)
                        source_name = self._detect_vendor(url)
                        records[cve_id].references.append(Reference(url=url, source=source_name, type="vendor_advisory", title=title))
                        if not records[cve_id].description and description:
                            records[cve_id].description = description
            await asyncio.sleep(0.3)
        
        # Step 4: Deep crawl
        unique_urls = list(set(urls_to_crawl))[:30]
        logger.info(f"Deep crawling {len(unique_urls)} vendor advisory pages")
        cve_sources = await self.firecrawl_deep_crawl(unique_urls, max_pages=30)
        
        for cve_id, source_urls in cve_sources.items():
            if cve_id not in records:
                records[cve_id] = CVERecord(cve_id=cve_id)
            for url in source_urls:
                existing_urls = {r.url for r in records[cve_id].references}
                if url not in existing_urls:
                    records[cve_id].references.append(Reference(url=url, source=self._detect_vendor(url), type="vendor_advisory"))
        
        for record in records.values():
            record.sources_collected.append("vendor_psirt")
            record.last_updated = datetime.now()
        
        logger.info(f"Found {len(records)} CVEs from vendor PSIRTs")
        return list(records.values())
    
    async def _parse_rss_feed(self, url: str, source: str) -> Dict[str, List[Reference]]:
        """Parse RSS/XML feed"""
        import httpx
        cve_refs = {}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                content = response.text
                items = re.findall(r'<item>(.*?)</item>', content, re.DOTALL)
                if not items:
                    items = re.findall(r'<entry>(.*?)</entry>', content, re.DOTALL)
                for item in items:
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', item)
                    link_match = re.search(r'<link[^>]*>(.*?)</link>', item)
                    if not link_match:
                        link_match = re.search(r'href=["\']([^"\']+)["\']', item)
                    title = title_match.group(1) if title_match else ""
                    link = link_match.group(1) if link_match else ""
                    title = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', title)
                    cve_ids = self.parse_cve_id(item)
                    for cve_id in cve_ids:
                        if cve_id not in cve_refs:
                            cve_refs[cve_id] = []
                        if link:
                            cve_refs[cve_id].append(Reference(url=link, source=source, type="rss_feed", title=title[:200] if title else None))
        except Exception as e:
            logger.warning(f"RSS parse error for {url}: {e}")
        return cve_refs
    
    async def firecrawl_scrape_url(self, url: str) -> Optional[Dict]:
        """Scrape a single URL"""
        import httpx
        from ..config import FIRECRAWL_API_KEY
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    "https://api.firecrawl.dev/v1/scrape",
                    headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}", "Content-Type": "application/json"},
                    json={"url": url, "formats": ["markdown", "links"]}
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.warning(f"Scrape error for {url}: {e}")
            return None
    
    def _detect_vendor(self, url: str) -> str:
        url_lower = url.lower()
        if "microsoft.com" in url_lower or "msrc" in url_lower:
            return "msrc"
        elif "cisco.com" in url_lower:
            return "cisco_psirt"
        elif "redhat.com" in url_lower:
            return "redhat"
        return "vendor"
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        return cve

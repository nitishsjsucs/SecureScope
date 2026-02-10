"""
CVE Intelligence Orchestrator
Coordinates all collectors and generates reports
"""
import asyncio
from datetime import datetime
from typing import List, Optional
import logging

from .models import CVERecord, DailyReport
from .aggregator import CVEAggregator, PriorityScorer, ReportGenerator
from .collectors import (
    NVDCollector,
    CISAKEVCollector,
    ExploitDBCollector,
    GitHubAdvisoryCollector,
    GitHubPoCCollector,
    RedditCollector,
    TrendingCollector,
    NewsCollector,
    MailingListCollector,
    SocialMediaCollector,
    ResearchBlogCollector,
    OSINTAggregatorCollector,
    VendorAdvisoryCollector,
    SocialBuzzCollector,
    SecurityAdvisoryCollector,
    CERTFeedCollector,
    VendorPSIRTCollector
)
from .config import FIRECRAWL_API_KEY, GITHUB_TOKEN, NVD_API_KEY

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEIntelligenceOrchestrator:
    """Main orchestrator for CVE intelligence gathering"""
    
    def __init__(
        self,
        firecrawl_api_key: str = None,
        github_token: str = None,
        nvd_api_key: str = None
    ):
        self.firecrawl_api_key = firecrawl_api_key or FIRECRAWL_API_KEY
        self.github_token = github_token or GITHUB_TOKEN
        self.nvd_api_key = nvd_api_key or NVD_API_KEY
        
        # Initialize collectors
        self.collectors = self._init_collectors()
        
        # Initialize aggregator and scorer
        self.aggregator = CVEAggregator()
        self.scorer = PriorityScorer()
        self.report_generator = ReportGenerator(self.aggregator, self.scorer)
    
    def _init_collectors(self):
        """Initialize all collectors"""
        return {
            # Official sources
            "nvd": NVDCollector(
                api_key=self.firecrawl_api_key,
                nvd_api_key=self.nvd_api_key
            ),
            "cisa_kev": CISAKEVCollector(api_key=self.firecrawl_api_key),
            # Exploit databases
            "exploit_db": ExploitDBCollector(api_key=self.firecrawl_api_key),
            "github_advisory": GitHubAdvisoryCollector(
                api_key=self.firecrawl_api_key,
                github_token=self.github_token
            ),
            "github_poc": GitHubPoCCollector(
                api_key=self.firecrawl_api_key,
                github_token=self.github_token
            ),
            # Social/trending
            "reddit": RedditCollector(api_key=self.firecrawl_api_key),
            "trending": TrendingCollector(api_key=self.firecrawl_api_key),
            "news": NewsCollector(api_key=self.firecrawl_api_key),
            # Extended sources
            "mailing_lists": MailingListCollector(api_key=self.firecrawl_api_key),
            "social_media": SocialMediaCollector(api_key=self.firecrawl_api_key),
            "research_blogs": ResearchBlogCollector(api_key=self.firecrawl_api_key),
            "osint": OSINTAggregatorCollector(api_key=self.firecrawl_api_key),
            "vendor_advisories": VendorAdvisoryCollector(api_key=self.firecrawl_api_key),
            # Social buzz (prioritized trending)
            "social_buzz": SocialBuzzCollector(api_key=self.firecrawl_api_key),
            # Security advisory sources (oss-security, Full Disclosure)
            "security_advisories": SecurityAdvisoryCollector(api_key=self.firecrawl_api_key),
            # CERT feeds (CISA, CERT-EU, JPCERT)
            "cert_feeds": CERTFeedCollector(api_key=self.firecrawl_api_key),
            # Vendor PSIRTs (Microsoft, Cisco, Red Hat)
            "vendor_psirt": VendorPSIRTCollector(api_key=self.firecrawl_api_key),
        }
    
    async def collect_all(self, days_back: int = 7) -> List[CVERecord]:
        """Run all collectors and aggregate results"""
        logger.info(f"Starting CVE collection for last {days_back} days")
        
        # Load existing data
        self.aggregator.load()
        
        # Run collectors in parallel where possible
        # Group 1: Official sources (can run in parallel)
        official_tasks = [
            self.collectors["nvd"].collect(days_back=days_back),
            self.collectors["cisa_kev"].collect(days_back=30),  # KEV needs longer window
            self.collectors["github_advisory"].collect(days_back=days_back),
        ]
        
        official_results = await asyncio.gather(*official_tasks, return_exceptions=True)
        
        for result in official_results:
            if isinstance(result, Exception):
                logger.error(f"Official collector error: {result}")
            elif result:
                self.aggregator.add_records(result)
        
        # Group 2: Exploit sources
        exploit_tasks = [
            self.collectors["exploit_db"].collect(days_back=days_back),
            self.collectors["github_poc"].collect(days_back=days_back),
        ]
        
        exploit_results = await asyncio.gather(*exploit_tasks, return_exceptions=True)
        
        for result in exploit_results:
            if isinstance(result, Exception):
                logger.error(f"Exploit collector error: {result}")
            elif result:
                self.aggregator.add_records(result)
        
        # Group 3: Social and trending
        social_tasks = [
            self.collectors["trending"].collect(),
            self.collectors["reddit"].collect(days_back=days_back),
            self.collectors["news"].collect(days_back=days_back),
        ]
        
        social_results = await asyncio.gather(*social_tasks, return_exceptions=True)
        
        for result in social_results:
            if isinstance(result, Exception):
                logger.error(f"Social collector error: {result}")
            elif result:
                self.aggregator.add_records(result)
        
        # Save aggregated data
        self.aggregator.save()
        
        all_records = self.aggregator.get_all_records()
        logger.info(f"Collection complete. Total CVEs: {len(all_records)}")
        
        return all_records
    
    async def enrich_cves(self, cve_ids: List[str] = None, top_n: int = 50):
        """Enrich CVE records with additional data from all sources"""
        logger.info(f"Enriching CVE records")
        
        if cve_ids:
            cves_to_enrich = [
                self.aggregator.get_record(cve_id) 
                for cve_id in cve_ids 
                if self.aggregator.get_record(cve_id)
            ]
        else:
            # Enrich top N by priority
            all_cves = self.scorer.score_all(self.aggregator.get_all_records())
            cves_to_enrich = all_cves[:top_n]
        
        for cve in cves_to_enrich:
            logger.info(f"Enriching {cve.cve_id}")
            
            # Run enrichment from each collector
            for name, collector in self.collectors.items():
                try:
                    enriched = await collector.enrich(cve)
                    if enriched:
                        self.aggregator.add_records([enriched])
                except Exception as e:
                    logger.error(f"Enrichment error for {cve.cve_id} from {name}: {e}")
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        self.aggregator.save()
        logger.info(f"Enrichment complete")
    
    def generate_report(self, days_back: int = 1) -> DailyReport:
        """Generate a daily intelligence report"""
        logger.info("Generating daily report")
        
        report = self.report_generator.generate_daily_report(days_back=days_back)
        filepath = self.report_generator.save_report(report)
        
        logger.info(f"Report saved to {filepath}")
        return report
    
    async def run_daily_pipeline(self, days_back: int = 7) -> DailyReport:
        """Run the complete daily intelligence pipeline"""
        logger.info("=" * 60)
        logger.info("CVE INTELLIGENCE DAILY PIPELINE")
        logger.info("=" * 60)
        
        # Step 1: Collect from all sources
        await self.collect_all(days_back=days_back)
        
        # Step 2: Enrich top priority CVEs
        await self.enrich_cves(top_n=50)
        
        # Step 3: Generate report
        report = self.generate_report(days_back=days_back)
        
        logger.info("=" * 60)
        logger.info("PIPELINE COMPLETE")
        logger.info(f"Total CVEs tracked: {len(self.aggregator.get_all_records())}")
        logger.info(f"Critical CVEs: {len(report.critical_cves)}")
        logger.info(f"Trending CVEs: {len(report.trending_cves)}")
        logger.info(f"CVEs with exploits: {len(report.newly_exploited)}")
        logger.info(f"In CISA KEV: {len(report.kev_additions)}")
        logger.info("=" * 60)
        
        return report


async def main():
    """Main entry point"""
    orchestrator = CVEIntelligenceOrchestrator()
    report = await orchestrator.run_daily_pipeline(days_back=7)
    return report


if __name__ == "__main__":
    asyncio.run(main())

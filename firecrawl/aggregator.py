"""
CVE Aggregator and Deduplication System
Merges data from multiple collectors and calculates priority scores
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional
import logging

from .models import CVERecord, DailyReport, Severity
from .config import PRIORITY_WEIGHTS, CVSS_CRITICAL, CVSS_HIGH, DATA_DIR

logger = logging.getLogger(__name__)


def _normalize_datetime(dt: Optional[datetime]) -> Optional[datetime]:
    """Convert datetime to offset-naive UTC for comparison"""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


class CVEAggregator:
    """Aggregates and deduplicates CVE data from multiple sources"""
    
    def __init__(self):
        self.cve_store: Dict[str, CVERecord] = {}
        self.storage_path = DATA_DIR / "cve_store.json"
    
    def add_records(self, records: List[CVERecord]):
        """Add records to the store, merging with existing data"""
        for record in records:
            if record.cve_id in self.cve_store:
                self._merge_records(self.cve_store[record.cve_id], record)
            else:
                self.cve_store[record.cve_id] = record
    
    def _merge_records(self, existing: CVERecord, new: CVERecord):
        """Merge new record data into existing record"""
        # Description - prefer longer/more detailed
        if new.description and (not existing.description or len(new.description) > len(existing.description)):
            existing.description = new.description
        
        # Dates - use earliest published, latest modified (normalize for comparison)
        if new.published:
            new_pub = _normalize_datetime(new.published)
            existing_pub = _normalize_datetime(existing.published)
            if not existing_pub or new_pub < existing_pub:
                existing.published = new.published
        if new.modified:
            new_mod = _normalize_datetime(new.modified)
            existing_mod = _normalize_datetime(existing.modified)
            if not existing_mod or new_mod > existing_mod:
                existing.modified = new.modified
        
        # Lists - merge unique items
        existing.affected_products = list(set(existing.affected_products + new.affected_products))
        existing.affected_vendors = list(set(existing.affected_vendors + new.affected_vendors))
        existing.cwe_ids = list(set(existing.cwe_ids + new.cwe_ids))
        existing.sources_collected = list(set(existing.sources_collected + new.sources_collected))
        
        # CVSS scores - avoid duplicates by (version, source)
        existing_scores = {(s.version, s.source) for s in existing.cvss_scores}
        for score in new.cvss_scores:
            if (score.version, score.source) not in existing_scores:
                existing.cvss_scores.append(score)
        
        # EPSS - use if not set
        if new.epss_score and not existing.epss_score:
            existing.epss_score = new.epss_score
        
        # KEV status - True if any source says True
        if new.in_cisa_kev:
            existing.in_cisa_kev = True
            if new.kev_date_added:
                existing.kev_date_added = new.kev_date_added
        
        # Exploits - merge unique by URL
        existing_urls = {e.url for e in existing.exploits}
        for exploit in new.exploits:
            if exploit.url not in existing_urls:
                existing.exploits.append(exploit)
        
        # References - merge unique by URL
        existing_ref_urls = {r.url for r in existing.references}
        for ref in new.references:
            if ref.url not in existing_ref_urls:
                existing.references.append(ref)
        
        # Social mentions - merge unique by (platform, url)
        existing_mentions = {(m.platform, m.url) for m in existing.social_mentions}
        for mention in new.social_mentions:
            if (mention.platform, mention.url) not in existing_mentions:
                existing.social_mentions.append(mention)
        
        # Trending score - keep highest
        if new.trending_score > existing.trending_score:
            existing.trending_score = new.trending_score
        
        # Raw data - merge dictionaries
        existing.raw_data.update(new.raw_data)
        
        # Update timestamp
        existing.last_updated = datetime.now()
    
    def get_record(self, cve_id: str) -> Optional[CVERecord]:
        """Get a specific CVE record"""
        return self.cve_store.get(cve_id)
    
    def get_all_records(self) -> List[CVERecord]:
        """Get all CVE records"""
        return list(self.cve_store.values())
    
    def save(self):
        """Save CVE store to disk"""
        data = {
            cve_id: record.to_dict() 
            for cve_id, record in self.cve_store.items()
        }
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(data)} CVE records to {self.storage_path}")
    
    def load(self):
        """Load CVE store from disk"""
        if not self.storage_path.exists():
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            for cve_id, record_data in data.items():
                self.cve_store[cve_id] = CVERecord.from_dict(record_data)
            
            logger.info(f"Loaded {len(self.cve_store)} CVE records from {self.storage_path}")
        except Exception as e:
            logger.error(f"Error loading CVE store: {e}")


class PriorityScorer:
    """Calculates priority scores for CVEs based on multiple factors"""
    
    def __init__(self, weights: Dict[str, int] = None):
        self.weights = weights or PRIORITY_WEIGHTS
    
    def score(self, cve: CVERecord) -> int:
        """Calculate priority score for a CVE"""
        score = 0
        
        # In CISA KEV = Critical priority
        if cve.in_cisa_kev:
            score += self.weights.get("cisa_kev", 100)
        
        # Public exploit available
        if cve.has_exploit:
            score += self.weights.get("exploit_available", 50)
        
        # High CVSS score
        highest_cvss = cve.highest_cvss
        if highest_cvss:
            if highest_cvss >= CVSS_CRITICAL:
                score += self.weights.get("high_cvss", 25) * 2
            elif highest_cvss >= CVSS_HIGH:
                score += self.weights.get("high_cvss", 25)
        
        # Recent publication
        if cve.published:
            days_old = (datetime.now() - cve.published.replace(tzinfo=None)).days
            if days_old <= 7:
                score += self.weights.get("recent", 20)
        
        # Social media trending (boosted weight)
        if cve.social_engagement > 100:
            score += self.weights.get("trending_social", 50)
        elif cve.social_engagement > 50:
            score += self.weights.get("trending_social", 50) // 2
        elif cve.social_engagement > 10:
            score += self.weights.get("trending_social", 50) // 4
        
        # Trending score from aggregators (viral velocity)
        if cve.trending_score >= 75:
            score += self.weights.get("viral_velocity", 40)
        elif cve.trending_score >= 50:
            score += self.weights.get("viral_velocity", 40) // 2
        elif cve.trending_score > 0:
            score += self.weights.get("trending_social", 50) // 4
        
        # Multi-platform mentions (CVE discussed on multiple platforms)
        platforms = set()
        for mention in cve.social_mentions:
            platform = mention.platform.replace("_crawl", "")
            platforms.add(platform)
        if len(platforms) >= 4:
            score += self.weights.get("multi_platform", 30)
        elif len(platforms) >= 2:
            score += self.weights.get("multi_platform", 30) // 2
        
        # Forum discussions (StackExchange, Reddit deep discussions)
        forum_mentions = [m for m in cve.social_mentions 
                         if m.platform in ("stackexchange", "reddit", "hackernews")]
        if len(forum_mentions) >= 2:
            score += self.weights.get("forum_discussion", 10)
        
        # GitHub PoC available
        github_pocs = [e for e in cve.exploits if e.source == "github-poc"]
        if github_pocs:
            score += self.weights.get("github_poc", 10)
        
        # News coverage (boosted weight)
        news_refs = [r for r in cve.references if r.type == "article"]
        if len(news_refs) >= 3:
            score += self.weights.get("news_coverage", 25) * 2
        elif news_refs:
            score += self.weights.get("news_coverage", 25)
        
        # Vendor advisory
        vendor_refs = [r for r in cve.references if r.type == "advisory" or r.type == "vendor_advisory"]
        if vendor_refs:
            score += self.weights.get("vendor_advisory", 15)
        
        # Research blog coverage (high signal)
        research_refs = [r for r in cve.references if r.type == "research"]
        if research_refs:
            score += self.weights.get("influencer_mention", 15)
        
        return score
    
    def score_all(self, cves: List[CVERecord]) -> List[CVERecord]:
        """Score all CVEs and sort by priority"""
        for cve in cves:
            cve.priority_score = self.score(cve)
        
        return sorted(cves, key=lambda x: x.priority_score, reverse=True)


class ReportGenerator:
    """Generates daily CVE intelligence reports"""
    
    def __init__(self, aggregator: CVEAggregator, scorer: PriorityScorer):
        self.aggregator = aggregator
        self.scorer = scorer
    
    def generate_daily_report(self, days_back: int = 1) -> DailyReport:
        """Generate a daily report of CVE intelligence"""
        cutoff = datetime.now() - timedelta(days=days_back)
        
        all_cves = self.aggregator.get_all_records()
        
        # Score all CVEs
        scored_cves = self.scorer.score_all(all_cves)
        
        # Filter recent CVEs
        recent_cves = [
            cve for cve in scored_cves
            if cve.published and cve.published.replace(tzinfo=None) >= cutoff
            or cve.last_updated and cve.last_updated >= cutoff
        ]
        
        # Categorize
        critical = [cve for cve in scored_cves if cve.severity == Severity.CRITICAL]
        trending = [cve for cve in scored_cves if cve.trending_score > 50 or cve.social_engagement > 50]
        exploited = [cve for cve in scored_cves if cve.has_exploit]
        kev_additions = [cve for cve in scored_cves if cve.in_cisa_kev]
        
        report = DailyReport(
            date=datetime.now(),
            total_new_cves=len(recent_cves),
            critical_cves=critical[:20],  # Top 20
            trending_cves=trending[:20],
            newly_exploited=exploited[:20],
            kev_additions=kev_additions[:20],
            all_cves=scored_cves[:100]  # Top 100 by priority
        )
        
        return report
    
    def save_report(self, report: DailyReport, filename: str = None):
        """Save report to JSON file"""
        if filename is None:
            filename = f"cve_report_{report.date.strftime('%Y%m%d')}.json"
        
        filepath = DATA_DIR / filename
        with open(filepath, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)
        
        logger.info(f"Saved report to {filepath}")
        return filepath

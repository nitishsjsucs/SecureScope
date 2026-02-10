"""
Data models for CVE Intelligence System
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class SourceType(Enum):
    OFFICIAL = "official"           # NVD, CVE.org, MITRE
    VENDOR = "vendor"               # Microsoft, Cisco, etc.
    EXPLOIT_DB = "exploit_db"       # Exploit-DB, Packet Storm
    SOCIAL = "social"               # Twitter, Reddit
    NEWS = "news"                   # Security news sites
    RESEARCH = "research"           # Research blogs
    AGGREGATOR = "aggregator"       # OpenCVE, Vulners


@dataclass
class CVSSScore:
    """CVSS Score information"""
    version: str  # "2.0", "3.0", "3.1", "4.0"
    score: float
    vector: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity,
            "source": self.source
        }


@dataclass
class Reference:
    """External reference for a CVE"""
    url: str
    source: str
    type: str  # advisory, exploit, patch, article, etc.
    title: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "type": self.type,
            "title": self.title
        }


@dataclass
class Exploit:
    """Exploit information"""
    source: str  # exploit-db, github, packet-storm, etc.
    url: str
    title: Optional[str] = None
    published: Optional[datetime] = None
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "url": self.url,
            "title": self.title,
            "published": self.published.isoformat() if self.published else None,
            "verified": self.verified
        }


@dataclass
class SocialMention:
    """Social media mention of a CVE"""
    platform: str  # twitter, reddit, hackernews, etc.
    url: str
    content: Optional[str] = None
    author: Optional[str] = None
    timestamp: Optional[datetime] = None
    engagement: int = 0  # likes, upvotes, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "url": self.url,
            "content": self.content,
            "author": self.author,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "engagement": self.engagement
        }


@dataclass
class CVERecord:
    """Complete CVE record with all collected intelligence"""
    cve_id: str
    description: Optional[str] = None
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    
    # Affected products
    affected_products: List[str] = field(default_factory=list)
    affected_vendors: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    
    # Scores from multiple sources
    cvss_scores: List[CVSSScore] = field(default_factory=list)
    epss_score: Optional[float] = None  # Exploit Prediction Scoring System
    
    # Exploitation status
    in_cisa_kev: bool = False
    kev_date_added: Optional[datetime] = None
    exploits: List[Exploit] = field(default_factory=list)
    
    # References and mentions
    references: List[Reference] = field(default_factory=list)
    social_mentions: List[SocialMention] = field(default_factory=list)
    
    # Intelligence metadata
    sources_collected: List[str] = field(default_factory=list)
    last_updated: Optional[datetime] = None
    trending_score: int = 0
    priority_score: int = 0
    
    # Raw data from sources
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def highest_cvss(self) -> Optional[float]:
        """Get the highest CVSS score"""
        if not self.cvss_scores:
            return None
        valid_scores = [s.score for s in self.cvss_scores if s.score is not None]
        return max(valid_scores) if valid_scores else None
    
    @property
    def severity(self) -> Severity:
        """Determine severity based on highest CVSS"""
        score = self.highest_cvss
        if score is None:
            return Severity.UNKNOWN
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    
    @property
    def has_exploit(self) -> bool:
        """Check if any exploits are available"""
        return len(self.exploits) > 0
    
    @property
    def social_engagement(self) -> int:
        """Total social engagement across platforms"""
        return sum(m.engagement for m in self.social_mentions)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published": self.published.isoformat() if self.published else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "affected_products": self.affected_products,
            "affected_vendors": self.affected_vendors,
            "cwe_ids": self.cwe_ids,
            "cvss_scores": [s.to_dict() for s in self.cvss_scores],
            "highest_cvss": self.highest_cvss,
            "severity": self.severity.value,
            "epss_score": self.epss_score,
            "in_cisa_kev": self.in_cisa_kev,
            "kev_date_added": self.kev_date_added.isoformat() if self.kev_date_added else None,
            "has_exploit": self.has_exploit,
            "exploits": [e.to_dict() for e in self.exploits],
            "references": [r.to_dict() for r in self.references],
            "social_mentions": [m.to_dict() for m in self.social_mentions],
            "social_engagement": self.social_engagement,
            "sources_collected": self.sources_collected,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "trending_score": self.trending_score,
            "priority_score": self.priority_score
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVERecord":
        """Create CVERecord from dictionary"""
        record = cls(cve_id=data["cve_id"])
        record.description = data.get("description")
        
        if data.get("published"):
            record.published = datetime.fromisoformat(data["published"])
        if data.get("modified"):
            record.modified = datetime.fromisoformat(data["modified"])
        
        record.affected_products = data.get("affected_products", [])
        record.affected_vendors = data.get("affected_vendors", [])
        record.cwe_ids = data.get("cwe_ids", [])
        
        for score_data in data.get("cvss_scores", []):
            record.cvss_scores.append(CVSSScore(**score_data))
        
        record.epss_score = data.get("epss_score")
        record.in_cisa_kev = data.get("in_cisa_kev", False)
        
        if data.get("kev_date_added"):
            record.kev_date_added = datetime.fromisoformat(data["kev_date_added"])
        
        for exploit_data in data.get("exploits", []):
            if exploit_data.get("published"):
                exploit_data["published"] = datetime.fromisoformat(exploit_data["published"])
            record.exploits.append(Exploit(**exploit_data))
        
        for ref_data in data.get("references", []):
            record.references.append(Reference(**ref_data))
        
        for mention_data in data.get("social_mentions", []):
            if mention_data.get("timestamp"):
                mention_data["timestamp"] = datetime.fromisoformat(mention_data["timestamp"])
            record.social_mentions.append(SocialMention(**mention_data))
        
        record.sources_collected = data.get("sources_collected", [])
        
        if data.get("last_updated"):
            record.last_updated = datetime.fromisoformat(data["last_updated"])
        
        record.trending_score = data.get("trending_score", 0)
        record.priority_score = data.get("priority_score", 0)
        record.raw_data = data.get("raw_data", {})
        
        return record


@dataclass
class DailyReport:
    """Daily CVE intelligence report"""
    date: datetime
    total_new_cves: int = 0
    critical_cves: List[CVERecord] = field(default_factory=list)
    trending_cves: List[CVERecord] = field(default_factory=list)
    newly_exploited: List[CVERecord] = field(default_factory=list)
    kev_additions: List[CVERecord] = field(default_factory=list)
    all_cves: List[CVERecord] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.date.isoformat(),
            "total_new_cves": self.total_new_cves,
            "critical_cves": [c.to_dict() for c in self.critical_cves],
            "trending_cves": [c.to_dict() for c in self.trending_cves],
            "newly_exploited": [c.to_dict() for c in self.newly_exploited],
            "kev_additions": [c.to_dict() for c in self.kev_additions],
            "all_cves": [c.to_dict() for c in self.all_cves]
        }

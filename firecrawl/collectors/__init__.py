"""
CVE Data Collectors
"""
from .base import BaseCollector
from .official import NVDCollector, CISAKEVCollector
from .exploits import ExploitDBCollector, GitHubAdvisoryCollector, GitHubPoCCollector
from .social import RedditCollector, TrendingCollector, NewsCollector
from .extended_sources import (
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

__all__ = [
    "BaseCollector",
    # Official sources
    "NVDCollector",
    "CISAKEVCollector", 
    # Exploit databases
    "ExploitDBCollector",
    "GitHubAdvisoryCollector",
    "GitHubPoCCollector",
    # Social/trending
    "RedditCollector",
    "TrendingCollector",
    "NewsCollector",
    # Extended sources
    "MailingListCollector",
    "SocialMediaCollector",
    "ResearchBlogCollector",
    "OSINTAggregatorCollector",
    "VendorAdvisoryCollector",
    "SocialBuzzCollector",
    # New security advisory sources
    "SecurityAdvisoryCollector",
    "CERTFeedCollector",
    "VendorPSIRTCollector"
]

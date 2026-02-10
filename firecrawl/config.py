"""
Configuration for CVE Intelligence System
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# API Keys
FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "cve_data"
CACHE_DIR = DATA_DIR / "cache"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

# Source URLs
SOURCES = {
    # Official CVE/NVD Sources
    "nvd_recent": "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=&search_type=all&isCpeNameSearch=false&startDate=&endDate=",
    "nvd_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cve_org": "https://www.cve.org/CVERecord",
    
    # CISA KEV (Known Exploited Vulnerabilities)
    "cisa_kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "cisa_kev_json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    
    # Exploit Databases
    "exploit_db": "https://www.exploit-db.com/",
    "exploit_db_recent": "https://www.exploit-db.com/search?q=",
    "packet_storm": "https://packetstormsecurity.com/files/",
    
    # GitHub Security
    "github_advisories": "https://github.com/advisories",
    "github_advisory_api": "https://api.github.com/advisories",
    
    # Trending/Social Sources
    "cvemon": "https://cvemon.com/",
    "cvetrends": "https://cvetrends.com/",
    
    # Reddit Security Subreddits
    "reddit_netsec": "https://www.reddit.com/r/netsec/",
    "reddit_cybersecurity": "https://www.reddit.com/r/cybersecurity/",
    "reddit_blueteamsec": "https://www.reddit.com/r/blueteamsec/",
    
    # News Sources
    "hacker_news_security": "https://thehackernews.com/search/label/vulnerability",
    "bleeping_computer": "https://www.bleepingcomputer.com/news/security/",
    "security_week": "https://www.securityweek.com/vulnerabilities/",
    "dark_reading": "https://www.darkreading.com/vulnerabilities-threats",
    
    # Vendor PSIRTs
    "microsoft_msrc": "https://msrc.microsoft.com/update-guide/vulnerability",
    "cisco_psirt": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "oracle_cpu": "https://www.oracle.com/security-alerts/",
    
    # Research Blogs
    "project_zero": "https://googleprojectzero.blogspot.com/",
    "trail_of_bits": "https://blog.trailofbits.com/",
    
    # Aggregators
    "vulners": "https://vulners.com/search?query=",
    "opencve": "https://www.opencve.io/cve",
}

# Priority weights for scoring
PRIORITY_WEIGHTS = {
    "cisa_kev": 100,           # In CISA KEV = critical
    "exploit_available": 50,    # Public exploit exists
    "trending_social": 50,      # High social media activity (boosted)
    "viral_velocity": 40,       # Fast-spreading CVE mentions (new)
    "multi_platform": 30,       # Mentioned on multiple platforms (new)
    "high_cvss": 25,            # CVSS >= 9.0
    "news_coverage": 25,        # Covered by news sites (boosted)
    "recent": 20,               # Published in last 7 days
    "influencer_mention": 15,   # Mentioned by security influencers (new)
    "vendor_advisory": 15,      # Has vendor advisory
    "github_poc": 10,           # GitHub PoC available
    "forum_discussion": 10,     # Active forum discussions (new)
}

# CVSS Severity thresholds
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

# Time windows
RECENT_DAYS = 7
TRENDING_HOURS = 24

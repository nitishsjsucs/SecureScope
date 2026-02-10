# CVE Intelligence System

A comprehensive, multi-source CVE (Common Vulnerabilities and Exposures) tracking and intelligence platform that aggregates, enriches, and prioritizes vulnerabilities from 14+ data sources using Firecrawl-powered web scraping and deep crawling.

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## 🎯 Overview

The CVE Intelligence System automatically collects vulnerability data from official databases, exploit repositories, social media, security research blogs, and news sites. It uses intelligent aggregation to deduplicate and merge data, then applies a priority scoring algorithm to surface the most critical and trending vulnerabilities.

### Key Features

- **14 Specialized Collectors** - Official sources, exploit DBs, social media, research blogs
- **Deep Crawl Technology** - Scrapes full pages from search results for comprehensive data
- **Multi-Platform Social Tracking** - Twitter, Reddit, HackerNews, YouTube, LinkedIn, Mastodon
- **Priority Scoring** - Weighted algorithm considering CVSS, KEV, exploits, and social buzz
- **Viral Velocity Detection** - Identifies fast-spreading CVE discussions
- **Daily Intelligence Reports** - Automated reports with critical, trending, and KEV CVEs

---

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATOR                                 │
│                    (CVEIntelligenceOrchestrator)                    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   COLLECTORS    │     │   AGGREGATOR    │     │  REPORT GEN     │
│   (14 sources)  │────▶│  (Dedup/Merge)  │────▶│  (Daily/Search) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
          │                         │
          ▼                         ▼
┌─────────────────┐     ┌─────────────────┐
│  FIRECRAWL API  │     │ PRIORITY SCORER │
│ (Search/Scrape) │     │   (Weighted)    │
└─────────────────┘     └─────────────────┘
```

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Orchestrator** | `orchestrator.py` | Coordinates collection, enrichment, and reporting |
| **Collectors** | `collectors/*.py` | 14 specialized data collectors |
| **Aggregator** | `aggregator.py` | Deduplicates and merges CVE records |
| **Priority Scorer** | `aggregator.py` | Calculates priority scores |
| **Firecrawl Client** | `firecrawl_client.py` | Web scraping and search API |
| **Models** | `models.py` | Data structures and schemas |

---

## 🔌 Data Sources & Collectors

### Official Sources (2 collectors)

| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| **NVDCollector** | NVD REST API | CVE details, CVSS scores, CWE, references |
| **CISAKEVCollector** | CISA KEV Catalog | Known exploited vulnerabilities list |

### Exploit Databases (3 collectors)

| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| **ExploitDBCollector** | Exploit-DB | Public exploits, PoC code |
| **GitHubAdvisoryCollector** | GitHub Advisory DB | Security advisories for packages |
| **GitHubPoCCollector** | GitHub Search | Proof-of-concept repositories |

### Social & Trending (3 collectors)

| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| **RedditCollector** | Security subreddits | Community discussions, trending CVEs |
| **TrendingCollector** | CVEmon, aggregators | Trending vulnerability signals |
| **NewsCollector** | Security news sites | TheHackerNews, BleepingComputer, etc. |

### Extended Sources (6 collectors)

| Collector | Sources | Data Retrieved |
|-----------|---------|----------------|
| **MailingListCollector** | Full Disclosure, oss-security, Debian, Ubuntu | Mailing list archives |
| **SocialMediaCollector** | Twitter, Reddit, HN, YouTube, LinkedIn, Mastodon, Medium | Multi-platform mentions |
| **ResearchBlogCollector** | Project Zero, Trail of Bits, MSRC, Talos | Research analysis |
| **OSINTAggregatorCollector** | Vulners, OpenCVE, VulDB, Snyk | Aggregated intel |
| **VendorAdvisoryCollector** | Microsoft, Cisco, Oracle, Adobe, VMware | Vendor advisories |
| **SocialBuzzCollector** | Cross-platform trending | Viral velocity, buzz tracking |

---

## 🔍 Data Scraping Methods

### 1. Firecrawl Search API
```python
# Search for CVE mentions across the web
result = await firecrawl_search("CVE 2026 critical vulnerability", limit=15)
```

### 2. Firecrawl Scrape API
```python
# Scrape full page content
result = await firecrawl_scrape(url, formats=["markdown"])
```

### 3. Deep Crawl (Search → Scrape)
The system takes URLs from search results and scrapes full page content to extract additional CVE data:

```python
# 1. Search returns URLs
search_results = await firecrawl_search("CVE exploit", limit=10)
urls = [item["url"] for item in search_results]

# 2. Deep crawl each URL for more CVEs
for url in urls[:15]:
    page_content = await firecrawl_scrape(url)
    additional_cves = extract_cve_ids(page_content)
```

### 4. NVD REST API
```python
# Official CVE data with CVSS scores
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234
```

### 5. GitHub API
```python
# Security advisories
GET https://api.github.com/advisories?cve_id=CVE-2024-1234

# PoC repositories
GET https://api.github.com/search/repositories?q=CVE-2024-1234
```

---

## 📊 Data Schema

### CVERecord (Primary Data Model)

```python
@dataclass
class CVERecord:
    # Identification
    cve_id: str                           # "CVE-2024-1234"
    description: Optional[str]            # Vulnerability description
    
    # Timestamps
    published: Optional[datetime]         # Publication date
    modified: Optional[datetime]          # Last modified date
    
    # Affected Components
    affected_products: List[str]          # ["Windows 10", "Windows 11"]
    affected_vendors: List[str]           # ["Microsoft"]
    cwe_ids: List[str]                    # ["CWE-79", "CWE-89"]
    
    # Severity Scoring
    cvss_scores: List[CVSSScore]          # Multiple CVSS versions
    epss_score: Optional[float]           # Exploit prediction score
    
    # Exploitation Status
    in_cisa_kev: bool                     # In CISA KEV catalog
    kev_date_added: Optional[datetime]    # When added to KEV
    exploits: List[Exploit]               # Known exploits
    
    # Intelligence Data
    references: List[Reference]           # External references
    social_mentions: List[SocialMention]  # Social media mentions
    
    # Scoring & Metadata
    sources_collected: List[str]          # ["nvd", "github", "news"]
    trending_score: int                   # 0-100 trending indicator
    priority_score: int                   # Calculated priority
    last_updated: Optional[datetime]
```

### Supporting Data Models

```python
@dataclass
class CVSSScore:
    version: str          # "2.0", "3.0", "3.1", "4.0"
    score: float          # 0.0 - 10.0
    vector: str           # CVSS vector string
    severity: str         # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    source: str           # "nvd", "vendor"

@dataclass
class Exploit:
    source: str           # "exploit-db", "github-poc", "packet-storm"
    url: str              # Link to exploit
    title: str            # Exploit title
    published: datetime   # Publication date
    verified: bool        # Is verified/tested

@dataclass
class Reference:
    url: str              # Reference URL
    source: str           # "nvd", "vendor", "news"
    type: str             # "advisory", "exploit", "article", "patch"
    title: str            # Reference title

@dataclass
class SocialMention:
    platform: str         # "twitter", "reddit", "hackernews", "youtube"
    url: str              # Post/article URL
    content: str          # Post content/title
    author: str           # Author username
    timestamp: datetime   # Post timestamp
    engagement: int       # Likes, upvotes, etc.
```

### Output JSON Structure

```json
{
  "cve_id": "CVE-2026-24858",
  "description": "Authentication bypass vulnerability in Fortinet...",
  "published": "2026-01-28T00:00:00",
  "modified": "2026-01-30T12:00:00",
  "affected_products": ["FortiOS", "FortiProxy"],
  "affected_vendors": ["Fortinet"],
  "cwe_ids": ["CWE-288"],
  "cvss_scores": [
    {
      "version": "3.1",
      "score": 9.8,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity": "CRITICAL",
      "source": "nvd"
    }
  ],
  "highest_cvss": 9.8,
  "severity": "critical",
  "in_cisa_kev": true,
  "kev_date_added": "2026-01-29T00:00:00",
  "has_exploit": true,
  "exploits": [
    {
      "source": "github-poc",
      "url": "https://github.com/user/CVE-2026-24858",
      "title": "PoC for CVE-2026-24858",
      "verified": false
    }
  ],
  "references": [
    {
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-24858",
      "source": "nvd",
      "type": "advisory"
    }
  ],
  "social_mentions": [
    {
      "platform": "twitter",
      "url": "https://twitter.com/...",
      "content": "Critical Fortinet CVE...",
      "engagement": 150
    }
  ],
  "sources_collected": ["nvd", "cisa_kev", "github_poc", "news", "social_buzz"],
  "trending_score": 85,
  "priority_score": 340,
  "last_updated": "2026-01-31T08:00:00"
}
```

---

## ⚖️ Priority Scoring Algorithm

### Scoring Weights

| Signal | Weight | Description |
|--------|--------|-------------|
| **CISA KEV** | 100 | In Known Exploited Vulnerabilities catalog |
| **Exploit Available** | 50 | Public exploit code exists |
| **Trending Social** | 50 | High social media activity |
| **Viral Velocity** | 40 | Fast-spreading across platforms |
| **Multi-Platform** | 30 | Mentioned on 4+ platforms |
| **News Coverage** | 25 | Covered by security news |
| **High CVSS** | 25-50 | CVSS ≥ 7.0 (25) or ≥ 9.0 (50) |
| **Recent** | 20 | Published in last 7 days |
| **Influencer Mention** | 15 | Research blog coverage |
| **Vendor Advisory** | 15 | Has vendor advisory |
| **Forum Discussion** | 10 | Active forum threads |
| **GitHub PoC** | 10 | GitHub proof-of-concept |

### Scoring Example

```
CVE-2026-24858:
  + 100 (CISA KEV)
  +  50 (Exploit available)
  +  50 (Trending on Twitter)
  +  40 (Viral velocity - 4 platforms)
  +  50 (CVSS 9.8 - Critical)
  +  25 (News coverage)
  +  20 (Published 3 days ago)
  +  15 (Vendor advisory)
  ─────────────────────────
  = 350 priority score
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Create `.env` file:
```env
FIRECRAWL_API_KEY=fc-your-api-key
GITHUB_TOKEN=ghp_your-token
NVD_API_KEY=your-nvd-api-key  # Optional, increases rate limits
```

### 3. Run the Pipeline

```bash
# Full daily pipeline
python run_cve_intel.py

# Collect from last 3 days
python run_cve_intel.py --days 3

# Search for specific CVE
python run_cve_intel.py --search CVE-2024-1234

# Show trending CVEs
python run_cve_intel.py --trending
```

---

## 📁 Output Files

```
cve_data/
├── cve_store.json           # Full CVE database (all collected CVEs)
├── cve_report_20260131.json # Daily report with top CVEs
└── cache/                   # Collector cache files
    ├── nvd/
    ├── exploit_db/
    └── ...
```

### Daily Report Structure

```json
{
  "date": "2026-01-31T00:00:00",
  "total_new_cves": 1218,
  "critical_cves": [...],     // CVSS ≥ 9.0
  "trending_cves": [...],     // High social engagement
  "newly_exploited": [...],   // New exploits found
  "kev_additions": [...],     // In CISA KEV
  "all_cves": [...]           // Complete list
}
```

---

## 🖥️ CLI Reference

```bash
# Full pipeline (collect, enrich, score, report)
python run_cve_intel.py

# Specify date range
python run_cve_intel.py --days 7

# Collection only
python run_cve_intel.py --collect

# Generate report only
python run_cve_intel.py --report

# Search specific CVE
python run_cve_intel.py --search CVE-2024-1234

# Show trending CVEs
python run_cve_intel.py --trending
```

---

## 🔧 Python API

```python
from cve_intelligence.orchestrator import CVEIntelligenceOrchestrator
from cve_intelligence.firecrawl_client import CVESearcher

# Run full pipeline
orchestrator = CVEIntelligenceOrchestrator()
report = await orchestrator.run_daily_pipeline(days_back=7)

# Access results
print(f"Total CVEs: {report.total_new_cves}")
for cve in report.critical_cves[:5]:
    print(f"{cve.cve_id}: {cve.highest_cvss} - {cve.description[:100]}")

# Search for specific CVE
searcher = CVESearcher()
results = await searcher.search_cve("CVE-2024-1234")
```

---

## 📦 Project Structure

```
cve_intelligence/
├── __init__.py
├── config.py               # Configuration and weights
├── models.py               # Data models (CVERecord, etc.)
├── orchestrator.py         # Main pipeline coordinator
├── aggregator.py           # Deduplication and scoring
├── firecrawl_client.py     # Firecrawl API client
├── cli.py                  # Command-line interface
└── collectors/
    ├── base.py             # BaseCollector class
    ├── official.py         # NVD, CISA KEV
    ├── exploits.py         # Exploit-DB, GitHub
    ├── social.py           # Reddit, Trending, News
    └── extended_sources.py # Mailing lists, blogs, OSINT, buzz
```

---

## 🔐 API Keys Required

| Service | Environment Variable | Purpose |
|---------|---------------------|---------|
| **Firecrawl** | `FIRECRAWL_API_KEY` | Web scraping and search |
| **GitHub** | `GITHUB_TOKEN` | Advisory and PoC search |
| **NVD** | `NVD_API_KEY` | Higher rate limits (optional) |

---

## 📈 Performance

- **CVEs Collected**: 1000+ per day
- **Sources**: 14 collectors
- **Deep Crawl**: Scrapes 100+ pages per run
- **Processing Time**: ~5-10 minutes for full pipeline

---

## License

MIT License

## References

- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Firecrawl Documentation](https://docs.firecrawl.dev/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

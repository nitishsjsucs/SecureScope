# SecureScope

**AI-Powered CVE Intelligence & Vulnerability Tracking Platform**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=next.js&logoColor=white)](https://nextjs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/atlas)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SecureScope is a comprehensive cybersecurity platform that combines automated CVE intelligence gathering from 17+ data sources with a modern vulnerability tracking dashboard. It enables security teams to monitor software dependencies, detect critical vulnerabilities in real-time, and generate prioritized threat reports — all powered by AI-driven analysis using Firecrawl web scraping and OpenAI.

---

## Key Features

### CVE Intelligence Engine (Python Backend)
- **17 Specialized Collectors** — Aggregates CVE data from NVD, CISA KEV, Exploit-DB, GitHub Advisories, Reddit, HackerNews, Twitter, security research blogs, CERT feeds, and vendor PSIRTs.
- **Deep Crawl Technology** — Uses Firecrawl to search and scrape full page content for comprehensive vulnerability data extraction.
- **Priority Scoring Algorithm** — Weighted scoring considering CVSS severity, KEV inclusion, exploit availability, and social media buzz.
- **Viral Velocity Detection** — Identifies rapidly spreading CVE discussions across platforms for early warning.
- **Automated Daily Reports** — Generates intelligence reports with critical, trending, and newly exploited CVEs.

### Vulnerability Tracker Dashboard (Next.js Frontend)
- **GitHub Repository Analysis** — Paste any GitHub repo URL to automatically detect and track all dependencies (direct + transitive).
- **AI-Powered Dependency Detection** — Uses OpenAI to analyze README files and identify dependencies across npm, pip, Go, Cargo, Maven, NuGet, and more.
- **CVE Alerting** — Receive notifications when new CVEs affect your tracked dependencies.
- **Multi-Package Manager Support** — Tracks npm, pip, Go, Cargo, Gem, Maven, Gradle, Composer, and NuGet packages.
- **CVE Database Import** — Imports CVE data from the opencve-kb repository with source provenance tracking (MITRE, NVD, VulnRichment, Red Hat).

### OpenCVE Integration
- **Self-Hosted CVE Monitoring** — Integrated OpenCVE instance for local vulnerability database management.
- **Email Monitoring** — Categorizes incoming security emails (CVE updates, advisories, threat intel, newsletters).

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                        SecureScope Platform                         │
├────────────────────────┬──────────────────────────────────────────┤
│   CVE Intelligence     │         Vulnerability Tracker            │
│   Engine (Python)      │         Dashboard (Next.js)              │
│                        │                                          │
│  ┌─────────────────┐   │   ┌──────────────────────────────────┐  │
│  │  Orchestrator    │   │   │  GitHub Repo Analyzer            │  │
│  │  17 Collectors   │   │   │  AI Dependency Detection         │  │
│  │  Aggregator      │   │   │  CVE Matching & Alerts           │  │
│  │  Priority Scorer │   │   │  Product Dashboard               │  │
│  └────────┬────────┘   │   └──────────────┬───────────────────┘  │
│           │             │                  │                      │
│  ┌────────▼────────┐   │   ┌──────────────▼───────────────────┐  │
│  │  Firecrawl API  │   │   │  MongoDB Atlas                   │  │
│  │  (Search/Scrape) │   │   │  (CVEs, Products, Dependencies) │  │
│  └─────────────────┘   │   └──────────────────────────────────┘  │
├────────────────────────┴──────────────────────────────────────────┤
│                    OpenCVE (Self-Hosted)                           │
│              Local CVE Database & Monitoring                      │
└───────────────────────────────────────────────────────────────────┘
```

---

## Data Sources

### Official Sources
| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| NVDCollector | NVD REST API | CVE details, CVSS scores, CWE, references |
| CISAKEVCollector | CISA KEV Catalog | Known exploited vulnerabilities |

### Exploit Databases
| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| ExploitDBCollector | Exploit-DB | Public exploits, PoC code |
| GitHubAdvisoryCollector | GitHub Advisory DB | Package security advisories |
| GitHubPoCCollector | GitHub Search | Proof-of-concept repositories |

### Social & Trending
| Collector | Source | Data Retrieved |
|-----------|--------|----------------|
| RedditCollector | Security subreddits | Community discussions |
| TrendingCollector | CVEmon, aggregators | Trending vulnerability signals |
| NewsCollector | TheHackerNews, BleepingComputer | Breaking security news |
| SocialBuzzCollector | Cross-platform | Viral velocity tracking |

### Extended Sources
| Collector | Sources | Data Retrieved |
|-----------|---------|----------------|
| MailingListCollector | Full Disclosure, oss-security | Mailing list archives |
| SocialMediaCollector | Twitter, Reddit, HN, YouTube, LinkedIn, Mastodon | Multi-platform mentions |
| ResearchBlogCollector | Project Zero, Trail of Bits, MSRC | Security research analysis |
| VendorAdvisoryCollector | Microsoft, Cisco, Oracle, Adobe, VMware | Vendor security advisories |
| CERTFeedCollector | CISA, CERT-EU, JPCERT | CERT advisories |
| VendorPSIRTCollector | Microsoft, Cisco, Red Hat | Vendor PSIRT bulletins |

---

## Project Structure

```
SecureScope/
├── firecrawl/                      # CVE Intelligence Engine
│   ├── orchestrator.py             # Main pipeline coordinator
│   ├── collectors/                 # 17 specialized data collectors
│   ├── aggregator.py               # Deduplication & priority scoring
│   ├── firecrawl_client.py         # Firecrawl API wrapper
│   ├── models.py                   # CVERecord, DailyReport schemas
│   └── config.py                   # API keys and configuration
├── vulntracker-ui/                 # Next.js Dashboard
│   ├── app/
│   │   ├── api/products/           # Product & analysis API routes
│   │   ├── products/               # Product pages (new, detail)
│   │   └── page.tsx                # Home dashboard
│   ├── lib/
│   │   ├── types.ts                # TypeScript type definitions
│   │   └── mongodb.ts              # MongoDB Atlas connection
│   └── scripts/
│       └── import_cves.py          # CVE database import script
├── opencve/                        # Self-hosted OpenCVE instance
│   └── web/app/models.py           # CVE database models
└── incident_report_generator/      # Incident report generation module
```

---

## Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Intelligence Engine** | Python 3.9+, asyncio, Firecrawl API |
| **Frontend** | Next.js 15, React, TypeScript, Tailwind CSS, shadcn/ui |
| **Database** | MongoDB Atlas |
| **AI/ML** | OpenAI GPT (dependency analysis), LLM-based CVE enrichment |
| **CVE Sources** | NVD API, CISA KEV, GitHub Advisory, Exploit-DB |
| **Web Scraping** | Firecrawl (search + deep crawl) |
| **CVE Platform** | OpenCVE (self-hosted) |

---

## Getting Started

### Prerequisites
- Python 3.9+
- Node.js 18+
- MongoDB Atlas account
- Firecrawl API key
- GitHub token (for advisory/PoC collection)

### Intelligence Engine Setup
```bash
cd firecrawl
pip install -r requirements.txt

# Configure API keys
export FIRECRAWL_API_KEY=your_key
export GITHUB_TOKEN=your_token
export NVD_API_KEY=your_key

# Run the daily pipeline
python -m firecrawl.orchestrator
```

### Dashboard Setup
```bash
cd vulntracker-ui
npm install

# Configure environment
cp .env.example .env.local
# Set MONGODB_URI, OPENAI_API_KEY

npm run dev
```

### CVE Database Import
```bash
cd vulntracker-ui/scripts
python import_cves.py          # Incremental import
python import_cves.py --full   # Full re-import
```

---

## My Contributions

- **CVE Intelligence Orchestrator** — Designed and built the async pipeline that coordinates 17 collectors, runs them in parallel groups, and generates daily intelligence reports with priority scoring.
- **Deep Crawl Pipeline** — Implemented the search-then-scrape deep crawl strategy using Firecrawl, enabling extraction of CVE data from full page content beyond initial search results.
- **Priority Scoring Algorithm** — Developed the weighted scoring system that considers CVSS severity, CISA KEV inclusion, exploit availability, social buzz velocity, and recency for vulnerability prioritization.
- **AI Dependency Analyzer** — Built the OpenAI-powered multi-layer dependency analysis that detects direct and transitive dependencies across 10+ package managers from GitHub repository READMEs.
- **CVE Import Pipeline** — Implemented the incremental CVE import system with source provenance tracking from the opencve-kb repository into MongoDB Atlas.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

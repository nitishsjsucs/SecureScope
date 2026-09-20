# SecureScope

**AI-Powered CVE Intelligence & Vulnerability Tracking Platform**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=next.js&logoColor=white)](https://nextjs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/atlas)
[![Own code: MIT](https://img.shields.io/badge/Own%20code-MIT-blue.svg)](LICENSE)
[![Vendored: OpenCVE BUSL-1.1](https://img.shields.io/badge/Vendored-OpenCVE%20BUSL--1.1-orange.svg)](opencve/LICENSE)

SecureScope is a cybersecurity platform that combines automated CVE intelligence gathering from 17+ data sources with a vulnerability tracking dashboard. It lets you monitor software dependencies, detect critical vulnerabilities as they are published, and generate prioritized threat reports, using Firecrawl for web retrieval and OpenAI for analysis.

> ### Built on OpenCVE
>
> This repository is **not** a greenfield project. The `opencve/` directory — 480 of 639 tracked files — is a vendored and locally modified copy of [**OpenCVE**](https://github.com/opencve/opencve), (c) 2020 Opencve.io, used as the self-hosted CVE database and web UI that the rest of SecureScope is built around.
>
> **OpenCVE is licensed under the [Business Source License 1.1](opencve/LICENSE), which is source-available, not open source.** Non-production use is granted outright. Production use is granted only under the Additional Use Grant, which excludes running it as a commercial *Security Monitoring and Alerting Service* for third parties. On **2030-01-13** that version converts to Apache-2.0.
>
> The original SecureScope code — `firecrawl/`, `cve_scorer/`, `incident_report_generator/`, `vulntracker-ui/` — is MIT licensed. See [`LICENSE`](LICENSE) for the split, [`NOTICE`](NOTICE) for all third-party components, and [`opencve/NOTICE`](opencve/NOTICE) for the exact list of local modifications to the vendored copy.

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

### OpenCVE Integration (vendored upstream, `opencve/`)
OpenCVE itself is third-party software — see [Built on OpenCVE](#built-on-opencve) above. What SecureScope adds to the vendored copy:
- **Read API for the dashboard** — a `sort` parameter on the CVE endpoints (by `updated_at`, `created_at`, or best-available CVSS score across v4.0/v3.1/v3.0/v2.0), and `metrics` + `vendors` returned in the list serializer so the dashboard renders severity without an N+1 fetch.
- **CORS + local stack** — `django-cors-headers` wired up for the Next.js frontend on `localhost:3000`, plus a dev `docker-compose` stack.
- **Local theming** — the OpenCVE skin replaced with a lighter custom theme.
- **Email Monitoring** — categorizes incoming security emails (CVE updates, advisories, threat intel, newsletters). Implemented in `vulntracker-ui/`, not in the vendored copy.

> Note: the vendored copy currently sets `AllowAny` on OpenCVE's read-only API view sets so the local dashboard can query it without auth. Restore upstream's permission classes before exposing an instance publicly.

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

Legend: **[own]** = written for this project (MIT) · **[vendored]** = third-party code copied in, under its own license.

```
SecureScope/
├── firecrawl/                      # [own] CVE Intelligence Engine
│                                   #   (a client for the Firecrawl API —
│                                   #    NOT a copy of the Firecrawl project)
│   ├── orchestrator.py             # Main pipeline coordinator
│   ├── collectors/                 # 17 specialized data collectors
│   ├── aggregator.py               # Deduplication & priority scoring
│   ├── firecrawl_client.py         # Firecrawl API wrapper
│   ├── models.py                   # CVERecord, DailyReport schemas
│   └── config.py                   # API keys and configuration
├── vulntracker-ui/                 # [own] Next.js Dashboard
│                                   #   components/ui/ = shadcn/ui (MIT)
│   ├── app/
│   │   ├── api/products/           # Product & analysis API routes
│   │   ├── products/               # Product pages (new, detail)
│   │   └── page.tsx                # Home dashboard
│   ├── lib/
│   │   ├── types.ts                # TypeScript type definitions
│   │   └── mongodb.ts              # MongoDB Atlas connection
│   └── scripts/
│       └── import_cves.py          # CVE database import script
├── opencve/                        # [vendored] OpenCVE, BUSL-1.1
│                                   #   480 of 639 files. (c) 2020 Opencve.io
│                                   #   see opencve/LICENSE and opencve/NOTICE
│   ├── web/                        #   Django app (upstream)
│   └── scheduler/                  #   Airflow DAGs (upstream)
├── cve_scorer/                     # [own] CVE scoring / ensemble ranking
└── incident_report_generator/      # [own] Incident report generation module
```

### Provenance at a glance

| Path | Origin | License | Tracked files |
|------|--------|---------|---------------|
| `opencve/` | [opencve/opencve](https://github.com/opencve/opencve) | BUSL-1.1 | 480 |
| `vulntracker-ui/` | this project (`components/ui/` from shadcn/ui, MIT) | MIT | 101 |
| `firecrawl/` | this project | MIT | 29 |
| `incident_report_generator/` | this project | MIT | 16 |
| `cve_scorer/` | this project | MIT | 10 |

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
- **OpenCVE Integration Layer** — Patched the vendored OpenCVE instance to serve the dashboard: CVSS-aware sorting across CVSS v4.0/v3.1/v3.0/v2.0 on the CVE API, an expanded list serializer, CORS wiring, and a dev `docker-compose` stack. Itemised in [`opencve/NOTICE`](opencve/NOTICE).

Everything above sits on top of OpenCVE rather than replacing it; the vendored `opencve/` tree is upstream's work, not mine.

---

## License

This repository is **dual-licensed by directory**. There is no single license for the whole tree.

| Scope | License |
|-------|---------|
| `firecrawl/`, `cve_scorer/`, `incident_report_generator/`, `vulntracker-ui/` | MIT — see [`LICENSE`](LICENSE) |
| `opencve/` (vendored, modified copy of OpenCVE) | Business Source License 1.1 — see [`opencve/LICENSE`](opencve/LICENSE) |
| `vulntracker-ui/components/ui/` | MIT (shadcn/ui) |

**Before you deploy or redistribute this:** BUSL-1.1 is not an open source license. It grants non-production use outright; production use is allowed only under the Additional Use Grant, which excludes offering the software as a commercial *Security Monitoring and Alerting Service* to third parties. Derivative works of `opencve/` remain under BUSL-1.1 until the 2030-01-13 Change Date, when that version converts to Apache-2.0. Commercial licensing: <https://www.opencve.io/>.

Full third-party inventory: [`NOTICE`](NOTICE). Local changes to the vendored OpenCVE copy: [`opencve/NOTICE`](opencve/NOTICE).

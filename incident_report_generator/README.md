# Incident Report Generator

Auto-generates professional PDF incident reports from security data. Designed for easy reading by management and security leadership.

## Features

- **Professional PDF format** with standardized sections
- **Auto-fill capability** from Reducto extraction results
- **CVE intelligence enrichment** for severity scoring
- **Automatic severity determination** based on IOCs
- **Timeline generation** from analysis data

## Installation

```bash
pip install reportlab
```

## Usage

### Generate Blank Form
```bash
python -m incident_report_generator blank
python -m incident_report_generator blank --classification INTERNAL
```

### Fill from JSON Data
```bash
python -m incident_report_generator fill incident_data.json
```

### Auto-fill from Extraction Results
```bash
# Basic auto-fill
python -m incident_report_generator auto ../reducto_log_extractor/demo_results.json

# With CVE enrichment
python -m incident_report_generator auto ../reducto_log_extractor/demo_results.json --include-cve

# Custom title and output
python -m incident_report_generator auto results.json --title "Q1 Threat Analysis" -o report.pdf
```

## Report Sections

1. **Incident Overview** - Title, dates, severity, status
2. **Affected Systems & Impact** - Systems, networks, business impact
3. **Threat Intelligence** - Threat actor, attack vector, CVEs, MITRE ATT&CK
4. **Indicators of Compromise** - IPs, domains, URLs, file hashes
5. **Incident Timeline** - Chronological events
6. **Response Actions** - Containment, eradication, recovery
7. **Recommendations** - Security recommendations
8. **Approval & Distribution** - Signatures and distribution list

## JSON Data Format

```json
{
  "report_id": "IR-20260131-001",
  "classification": "CONFIDENTIAL",
  "incident_title": "Ransomware Attack Investigation",
  "incident_date": "2026-01-31",
  "severity": "CRITICAL",
  "status": "Investigating",
  "malicious_ips": ["192.0.2.100", "203.0.113.42"],
  "malicious_domains": ["evil-domain.com"],
  "file_hashes": ["sha256:abc123..."],
  "cves_exploited": ["CVE-2026-1234"],
  "mitre_techniques": ["T1486", "T1059.001"],
  "recommendations": ["Block identified IPs", "Patch CVEs"]
}
```

## Output

Reports are saved to `./output/` directory by default.

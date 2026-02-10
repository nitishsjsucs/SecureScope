#!/usr/bin/env python3
"""
Automatic Incident Report Filler

Takes extracted IOC data and CVE intelligence to auto-fill incident reports.
Works with Reducto extraction results and CVE store data.

Usage:
    python auto_filler.py --from-extraction results.json
    python auto_filler.py --from-extraction results.json --include-cve
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field

from .form_generator import IncidentReportGenerator, IncidentData


@dataclass
class ExtractionResult:
    """Container for extracted IOCs (compatible with Reducto extractor)"""
    ips: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    cves: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    source_file: str = ""
    pages_processed: int = 0
    extraction_time: float = 0.0


class AutoReportFiller:
    """Automated incident report generation from security data"""
    
    def __init__(self):
        """Initialize the auto-filler"""
        self.extraction_results: List[ExtractionResult] = []
        self.cve_data: Dict[str, Any] = {}
    
    def load_extraction_json(self, json_path: str) -> List[ExtractionResult]:
        """Load extraction results from JSON file"""
        with open(json_path, 'r', encoding='utf-8') as f:
            json_results = json.load(f)
        
        results = []
        for item in json_results:
            result = ExtractionResult(
                source_file=item.get('source_file', ''),
                pages_processed=item.get('pages_processed', 0),
                extraction_time=item.get('extraction_time_seconds', 0.0)
            )
            indicators = item.get('indicators', {})
            result.ips = set(indicators.get('ips', []))
            result.hashes = set(indicators.get('hashes', []))
            result.urls = set(indicators.get('urls', []))
            result.domains = set(indicators.get('domains', []))
            result.cves = set(indicators.get('cves', []))
            result.mitre_techniques = set(indicators.get('mitre_techniques', []))
            results.append(result)
        
        self.extraction_results = results
        return results
    
    def load_cve_intelligence(self, cve_store_path: str):
        """Load CVE intelligence data for enrichment"""
        with open(cve_store_path, 'r', encoding='utf-8') as f:
            self.cve_data = json.load(f)
    
    def aggregate_results(self) -> Dict[str, Any]:
        """Aggregate all extraction results into unified data"""
        all_ips = set()
        all_hashes = set()
        all_urls = set()
        all_domains = set()
        all_cves = set()
        all_mitre = set()
        source_files = []
        total_pages = 0
        total_time = 0.0
        
        for result in self.extraction_results:
            all_ips.update(result.ips)
            all_hashes.update(result.hashes)
            all_urls.update(result.urls)
            all_domains.update(result.domains)
            all_cves.update(result.cves)
            all_mitre.update(result.mitre_techniques)
            source_files.append(result.source_file)
            total_pages += result.pages_processed
            total_time += result.extraction_time
        
        return {
            'ips': sorted(list(all_ips)),
            'hashes': sorted(list(all_hashes)),
            'urls': sorted(list(all_urls)),
            'domains': sorted(list(all_domains)),
            'cves': sorted(list(all_cves)),
            'mitre_techniques': sorted(list(all_mitre)),
            'source_files': source_files,
            'total_pages': total_pages,
            'total_time': total_time
        }
    
    def determine_severity(self, aggregated: Dict[str, Any]) -> str:
        """Determine incident severity based on IOCs"""
        score = 0
        
        # Check for critical indicators
        if any(self.cve_data.get(cve, {}).get('in_cisa_kev') for cve in aggregated['cves']):
            score += 40  # KEV CVE = Critical
        
        if any(self.cve_data.get(cve, {}).get('has_exploit') for cve in aggregated['cves']):
            score += 30  # Known exploit
        
        # Volume-based scoring
        if len(aggregated['ips']) > 20:
            score += 20
        elif len(aggregated['ips']) > 10:
            score += 10
        
        if len(aggregated['cves']) > 5:
            score += 20
        elif len(aggregated['cves']) > 0:
            score += 10
        
        if len(aggregated['hashes']) > 10:
            score += 15
        
        if aggregated['mitre_techniques']:
            score += 15
        
        if score >= 60:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_timeline(self, aggregated: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate incident timeline from analysis"""
        now = datetime.now()
        timeline = []
        
        for i, source in enumerate(aggregated['source_files'][:5]):
            timeline.append({
                'timestamp': now.strftime("%Y-%m-%d %H:%M"),
                'event': f"Analyzed: {Path(source).name}",
                'source': "Reducto Extraction"
            })
        
        for cve in aggregated['cves'][:5]:
            cve_info = self.cve_data.get(cve, {})
            if cve_info.get('published'):
                timeline.append({
                    'timestamp': cve_info['published'][:10],
                    'event': f"CVE Published: {cve}",
                    'source': "NVD"
                })
        
        return timeline[:15]
    
    def generate_recommendations(self, aggregated: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if aggregated['ips']:
            recommendations.append(
                f"Block {len(aggregated['ips'])} malicious IP addresses at perimeter firewall"
            )
        
        if aggregated['domains']:
            recommendations.append(
                f"Add {len(aggregated['domains'])} malicious domains to DNS blacklist"
            )
        
        if aggregated['urls']:
            recommendations.append("Update web proxy to block identified malicious URLs")
        
        if aggregated['hashes']:
            recommendations.append(
                f"Deploy {len(aggregated['hashes'])} file hash IOCs to endpoint detection"
            )
        
        if aggregated['cves']:
            kev_cves = [cve for cve in aggregated['cves'] 
                       if self.cve_data.get(cve, {}).get('in_cisa_kev')]
            if kev_cves:
                recommendations.append(
                    f"URGENT: Patch {len(kev_cves)} CISA KEV vulnerabilities immediately"
                )
            recommendations.append(f"Prioritize patching for {len(aggregated['cves'])} CVEs")
        
        if aggregated['mitre_techniques']:
            recommendations.append(
                f"Review detection rules for {len(aggregated['mitre_techniques'])} MITRE ATT&CK techniques"
            )
        
        recommendations.extend([
            "Conduct threat hunting using identified IOCs",
            "Update SIEM correlation rules with new indicators",
            "Brief SOC team on identified threat patterns"
        ])
        
        return recommendations
    
    def create_incident_data(
        self, 
        title: Optional[str] = None,
        classification: str = "CONFIDENTIAL"
    ) -> IncidentData:
        """Create IncidentData from aggregated results"""
        aggregated = self.aggregate_results()
        timestamp = datetime.now()
        
        return IncidentData(
            report_id=f"IR-{timestamp.strftime('%Y%m%d')}-{timestamp.strftime('%H%M%S')}",
            report_date=timestamp.strftime("%Y-%m-%d"),
            classification=classification,
            incident_title=title or "Security Incident - Automated IOC Analysis Report",
            incident_date=timestamp.strftime("%Y-%m-%d"),
            incident_time=timestamp.strftime("%H:%M"),
            detection_date=timestamp.strftime("%Y-%m-%d"),
            severity=self.determine_severity(aggregated),
            status="Investigating",
            affected_systems=["Systems under analysis - pending confirmation"],
            affected_networks=["Network segments under review"],
            business_impact="Impact assessment in progress",
            threat_actor="Unknown - analysis ongoing",
            attack_vector="Multiple vectors identified from IOC analysis",
            cves_exploited=aggregated['cves'],
            mitre_techniques=aggregated['mitre_techniques'],
            malicious_ips=aggregated['ips'],
            malicious_domains=aggregated['domains'],
            malicious_urls=aggregated['urls'],
            file_hashes=aggregated['hashes'],
            timeline_events=self.generate_timeline(aggregated),
            containment_actions=[
                "Network monitoring enhanced for identified IOCs",
                "Firewall rules updated to block known malicious IPs",
                "DNS blacklist updated with malicious domains"
            ],
            eradication_actions=[
                "Scanning systems for identified file hashes",
                "Reviewing logs for historical IOC matches"
            ],
            recovery_actions=[
                "Patch deployment scheduled for identified CVEs",
                "System hardening in progress"
            ],
            recommendations=self.generate_recommendations(aggregated),
            prepared_by="Automated Security Analysis System",
            distribution_list=["SOC Team", "Security Management", "IT Operations"],
            source_files=aggregated['source_files'],
            pages_analyzed=aggregated['total_pages']
        )
    
    def generate_report(
        self,
        output_path: str,
        title: Optional[str] = None,
        classification: str = "CONFIDENTIAL"
    ) -> tuple:
        """Generate the final incident report PDF"""
        incident_data = self.create_incident_data(title=title, classification=classification)
        generator = IncidentReportGenerator(output_path)
        result_path = generator.generate(incident_data)
        return result_path, incident_data


def main():
    parser = argparse.ArgumentParser(description='Auto-fill incident reports from extraction data')
    
    parser.add_argument('--from-extraction', metavar='JSON_FILE', required=True,
                       help='Path to extraction results JSON')
    parser.add_argument('--include-cve', action='store_true',
                       help='Include CVE intelligence enrichment')
    parser.add_argument('--cve-store', metavar='JSON_FILE',
                       help='Path to CVE store JSON (default: ../cve_data/cve_store.json)')
    parser.add_argument('--title', help='Custom report title')
    parser.add_argument('--classification', choices=['CONFIDENTIAL', 'INTERNAL', 'PUBLIC'],
                       default='CONFIDENTIAL')
    parser.add_argument('-o', '--output', help='Output PDF path')
    
    args = parser.parse_args()
    
    script_dir = Path(__file__).parent
    output_dir = script_dir / "output"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    filler = AutoReportFiller()
    
    # Load extraction data
    print(f"Loading extraction results from {args.from_extraction}")
    filler.load_extraction_json(args.from_extraction)
    
    # Load CVE data if requested
    if args.include_cve:
        cve_store = args.cve_store or str(script_dir.parent / "cve_data" / "cve_store.json")
        if Path(cve_store).exists():
            filler.load_cve_intelligence(cve_store)
            print(f"Loaded CVE intelligence from {cve_store}")
        else:
            print(f"Warning: CVE store not found at {cve_store}")
    
    # Generate output path
    output_path = args.output or str(output_dir / f"incident_report_{timestamp}.pdf")
    
    # Generate report
    print("\nGenerating incident report...")
    result_path, incident_data = filler.generate_report(
        output_path,
        title=args.title,
        classification=args.classification
    )
    
    # Print summary
    print(f"\n{'='*50}")
    print("INCIDENT REPORT GENERATED")
    print(f"{'='*50}")
    print(f"Report ID:      {incident_data.report_id}")
    print(f"Classification: {incident_data.classification}")
    print(f"Severity:       {incident_data.severity}")
    print(f"Output:         {result_path}")
    print(f"{'-'*50}")
    print(f"IOC Summary:")
    print(f"  - IPs:     {len(incident_data.malicious_ips)}")
    print(f"  - Domains: {len(incident_data.malicious_domains)}")
    print(f"  - URLs:    {len(incident_data.malicious_urls)}")
    print(f"  - Hashes:  {len(incident_data.file_hashes)}")
    print(f"  - CVEs:    {len(incident_data.cves_exploited)}")
    print(f"  - MITRE:   {len(incident_data.mitre_techniques)}")
    print(f"{'='*50}\n")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Security Incident Report PDF Form Generator

Generates professional PDF incident report forms with a standardized format
for easy reading by management and security leadership.

Usage:
    python form_generator.py --generate-blank              # Create blank form
    python form_generator.py --fill data.json              # Fill from JSON
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
except ImportError:
    print("reportlab not installed. Run: pip install reportlab")
    exit(1)


@dataclass
class IncidentData:
    """Data structure for incident report fields"""
    # Header Information
    report_id: str = ""
    report_date: str = ""
    classification: str = "CONFIDENTIAL"
    
    # Incident Overview
    incident_title: str = ""
    incident_date: str = ""
    incident_time: str = ""
    detection_date: str = ""
    severity: str = ""  # Critical, High, Medium, Low
    status: str = ""    # Open, Investigating, Contained, Resolved
    
    # Affected Systems
    affected_systems: List[str] = field(default_factory=list)
    affected_networks: List[str] = field(default_factory=list)
    business_impact: str = ""
    
    # Threat Intelligence
    threat_actor: str = ""
    attack_vector: str = ""
    cves_exploited: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Indicators of Compromise
    malicious_ips: List[str] = field(default_factory=list)
    malicious_domains: List[str] = field(default_factory=list)
    malicious_urls: List[str] = field(default_factory=list)
    file_hashes: List[str] = field(default_factory=list)
    
    # Timeline
    timeline_events: List[Dict[str, str]] = field(default_factory=list)
    
    # Response Actions
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    prepared_by: str = ""
    reviewed_by: str = ""
    approved_by: str = ""
    distribution_list: List[str] = field(default_factory=list)
    
    # Source files analyzed
    source_files: List[str] = field(default_factory=list)
    pages_analyzed: int = 0


class IncidentReportGenerator:
    """Generates professional PDF incident reports"""
    
    # Color scheme
    HEADER_BG = colors.HexColor("#1a365d")      # Dark blue
    HEADER_TEXT = colors.white
    SECTION_BG = colors.HexColor("#2c5282")     # Medium blue
    SECTION_TEXT = colors.white
    CRITICAL_BG = colors.HexColor("#c53030")    # Red
    HIGH_BG = colors.HexColor("#dd6b20")        # Orange
    MEDIUM_BG = colors.HexColor("#d69e2e")      # Yellow
    LOW_BG = colors.HexColor("#38a169")         # Green
    TABLE_HEADER_BG = colors.HexColor("#e2e8f0")  # Light gray
    
    def __init__(self, output_path: str, page_size=letter):
        self.output_path = output_path
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        self.elements = []
    
    def _setup_styles(self):
        """Configure custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.HEADER_BG,
            spaceAfter=20,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.SECTION_BG,
            spaceBefore=15,
            spaceAfter=10,
            borderWidth=1,
            borderColor=self.SECTION_BG,
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=11,
            textColor=self.HEADER_BG,
            spaceBefore=10,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='FieldLabel',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.gray,
            spaceBefore=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='FieldValue',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=2,
            spaceAfter=8
        ))
        
        self.styles.add(ParagraphStyle(
            name='IOCItem',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            leftIndent=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER
        ))
    
    def _add_header(self, data: IncidentData):
        """Add report header with classification and ID"""
        classification_color = self.CRITICAL_BG if data.classification == "CONFIDENTIAL" else self.HIGH_BG
        
        header_data = [
            [Paragraph(f"<b>{data.classification}</b>", 
                      ParagraphStyle('ClassBanner', 
                                    parent=self.styles['Normal'],
                                    textColor=colors.white,
                                    alignment=TA_CENTER,
                                    fontSize=10))]
        ]
        header_table = Table(header_data, colWidths=[self.page_size[0] - 1.5*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), classification_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        self.elements.append(header_table)
        self.elements.append(Spacer(1, 20))
        
        self.elements.append(Paragraph("SECURITY INCIDENT REPORT", self.styles['ReportTitle']))
        
        meta_data = [
            ["Report ID:", data.report_id or "________________", 
             "Report Date:", data.report_date or datetime.now().strftime("%Y-%m-%d")],
            ["Severity:", data.severity or "________________",
             "Status:", data.status or "________________"]
        ]
        
        meta_table = Table(meta_data, colWidths=[1.2*inch, 2*inch, 1.2*inch, 2*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), self.HEADER_BG),
            ('TEXTCOLOR', (2, 0), (2, -1), self.HEADER_BG),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        self.elements.append(meta_table)
        self.elements.append(Spacer(1, 10))
        self.elements.append(HRFlowable(width="100%", thickness=2, color=self.HEADER_BG))
    
    def _add_section(self, title: str):
        """Add a section header"""
        self.elements.append(Spacer(1, 15))
        
        section_data = [[Paragraph(f"<b>{title}</b>", 
                                   ParagraphStyle('SectionTitle',
                                                 textColor=colors.white,
                                                 fontSize=12))]]
        section_table = Table(section_data, colWidths=[self.page_size[0] - 1.5*inch])
        section_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.SECTION_BG),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        self.elements.append(section_table)
        self.elements.append(Spacer(1, 10))
    
    def _add_field(self, label: str, value: str, blank_width: str = "90%"):
        """Add a labeled field"""
        self.elements.append(Paragraph(f"<b>{label}</b>", self.styles['FieldLabel']))
        if value:
            self.elements.append(Paragraph(value, self.styles['FieldValue']))
        else:
            self.elements.append(Paragraph("_" * 80, self.styles['FieldValue']))
    
    def _add_list_field(self, label: str, items: List[str], max_display: int = 10):
        """Add a field with a list of items"""
        self.elements.append(Paragraph(f"<b>{label}</b>", self.styles['FieldLabel']))
        
        if items:
            displayed_items = items[:max_display]
            for item in displayed_items:
                display_item = item[:80] + "..." if len(item) > 80 else item
                self.elements.append(Paragraph(f"• {display_item}", self.styles['IOCItem']))
            
            if len(items) > max_display:
                self.elements.append(Paragraph(
                    f"<i>... and {len(items) - max_display} more</i>", 
                    self.styles['FieldLabel']
                ))
        else:
            for _ in range(3):
                self.elements.append(Paragraph("• ________________________________", self.styles['IOCItem']))
        
        self.elements.append(Spacer(1, 5))
    
    def _add_ioc_table(self, title: str, iocs: List[str], ioc_type: str):
        """Add a table of IOCs"""
        self.elements.append(Paragraph(f"<b>{title}</b>", self.styles['SubSection']))
        
        if iocs:
            rows = [["#", ioc_type.upper()]]
            for i, ioc in enumerate(iocs[:20], 1):
                truncated = ioc[:60] + "..." if len(ioc) > 60 else ioc
                rows.append([str(i), truncated])
            
            table = Table(rows, colWidths=[0.5*inch, 5.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.TABLE_HEADER_BG),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('FONTNAME', (1, 1), (1, -1), 'Courier'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ]))
            self.elements.append(table)
            
            if len(iocs) > 20:
                self.elements.append(Paragraph(
                    f"<i>Showing 20 of {len(iocs)} total indicators</i>",
                    self.styles['FieldLabel']
                ))
        else:
            rows = [["#", ioc_type.upper()]]
            for i in range(5):
                rows.append([str(i+1), ""])
            
            table = Table(rows, colWidths=[0.5*inch, 5.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.TABLE_HEADER_BG),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            self.elements.append(table)
        
        self.elements.append(Spacer(1, 10))
    
    def _add_timeline_table(self, events: List[Dict[str, str]]):
        """Add timeline of events table"""
        self.elements.append(Paragraph("<b>Incident Timeline</b>", self.styles['SubSection']))
        
        rows = [["Date/Time", "Event", "Source"]]
        
        if events:
            for event in events[:15]:
                rows.append([
                    event.get('timestamp', ''),
                    event.get('event', ''),
                    event.get('source', '')
                ])
        else:
            for _ in range(5):
                rows.append(["", "", ""])
        
        table = Table(rows, colWidths=[1.5*inch, 3.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.TABLE_HEADER_BG),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        self.elements.append(table)
        self.elements.append(Spacer(1, 10))
    
    def _add_signature_block(self, data: IncidentData):
        """Add signature and approval section"""
        self._add_section("APPROVAL & DISTRIBUTION")
        
        sig_data = [
            ["Prepared By:", data.prepared_by or "________________", "Date:", "________________"],
            ["Reviewed By:", data.reviewed_by or "________________", "Date:", "________________"],
            ["Approved By:", data.approved_by or "________________", "Date:", "________________"],
        ]
        
        sig_table = Table(sig_data, colWidths=[1.2*inch, 2.5*inch, 0.8*inch, 2*inch])
        sig_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        self.elements.append(sig_table)
        
        self.elements.append(Paragraph("<b>Distribution List:</b>", self.styles['FieldLabel']))
        if data.distribution_list:
            self.elements.append(Paragraph(", ".join(data.distribution_list), self.styles['FieldValue']))
        else:
            self.elements.append(Paragraph("________________________________________________", self.styles['FieldValue']))
    
    def generate(self, data: IncidentData):
        """Generate the complete incident report PDF"""
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=self.page_size,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        
        self.elements = []
        
        # Header
        self._add_header(data)
        
        # Section 1: Incident Overview
        self._add_section("1. INCIDENT OVERVIEW")
        self._add_field("Incident Title:", data.incident_title)
        
        overview_data = [
            ["Incident Date:", data.incident_date or "________________",
             "Detection Date:", data.detection_date or "________________"],
            ["Incident Time:", data.incident_time or "________________",
             "Severity Level:", data.severity or "________________"],
        ]
        overview_table = Table(overview_data, colWidths=[1.3*inch, 2*inch, 1.3*inch, 2*inch])
        overview_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        self.elements.append(overview_table)
        
        # Section 2: Affected Systems
        self._add_section("2. AFFECTED SYSTEMS & IMPACT")
        self._add_list_field("Affected Systems:", data.affected_systems)
        self._add_list_field("Affected Networks:", data.affected_networks)
        self._add_field("Business Impact Assessment:", data.business_impact)
        
        # Section 3: Threat Intelligence
        self._add_section("3. THREAT INTELLIGENCE")
        self._add_field("Suspected Threat Actor:", data.threat_actor)
        self._add_field("Attack Vector:", data.attack_vector)
        self._add_list_field("CVEs Exploited:", data.cves_exploited)
        self._add_list_field("MITRE ATT&CK Techniques:", data.mitre_techniques)
        
        # Section 4: Indicators of Compromise
        self._add_section("4. INDICATORS OF COMPROMISE (IOCs)")
        self._add_ioc_table("Malicious IP Addresses", data.malicious_ips, "IP Address")
        self._add_ioc_table("Malicious Domains", data.malicious_domains, "Domain")
        self._add_ioc_table("Malicious URLs", data.malicious_urls, "URL")
        self._add_ioc_table("File Hashes", data.file_hashes, "Hash (SHA256/MD5)")
        
        # Page break before timeline
        self.elements.append(PageBreak())
        
        # Section 5: Timeline
        self._add_section("5. INCIDENT TIMELINE")
        self._add_timeline_table(data.timeline_events)
        
        # Section 6: Response Actions
        self._add_section("6. RESPONSE ACTIONS")
        self._add_list_field("Containment Actions Taken:", data.containment_actions)
        self._add_list_field("Eradication Actions:", data.eradication_actions)
        self._add_list_field("Recovery Actions:", data.recovery_actions)
        
        # Section 7: Recommendations
        self._add_section("7. RECOMMENDATIONS")
        self._add_list_field("Security Recommendations:", data.recommendations)
        
        # Section 8: Source Analysis Info
        if data.source_files:
            self._add_section("8. ANALYSIS SOURCES")
            self._add_list_field("Source Files Analyzed:", data.source_files)
            self._add_field("Total Pages Analyzed:", str(data.pages_analyzed) if data.pages_analyzed else "")
        
        # Signature block
        self._add_signature_block(data)
        
        # Footer note
        self.elements.append(Spacer(1, 30))
        self.elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            "This document contains sensitive security information.",
            self.styles['Footer']
        ))
        
        # Build PDF
        doc.build(self.elements)
        return self.output_path


def main():
    parser = argparse.ArgumentParser(
        description='Generate Security Incident Report PDFs'
    )
    
    parser.add_argument('--generate-blank', action='store_true', help='Generate blank form')
    parser.add_argument('--fill', metavar='JSON_FILE', help='Fill from JSON file')
    parser.add_argument('-o', '--output', help='Output PDF path', default=None)
    
    args = parser.parse_args()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    script_dir = Path(__file__).parent
    output_dir = script_dir / "output"
    output_dir.mkdir(exist_ok=True)
    
    if args.generate_blank:
        output_path = args.output or str(output_dir / f"incident_report_blank_{timestamp}.pdf")
        data = IncidentData(report_id=f"IR-{timestamp[:8]}-XXXX", classification="CONFIDENTIAL")
    elif args.fill:
        output_path = args.output or str(output_dir / f"incident_report_{timestamp}.pdf")
        with open(args.fill, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        data = IncidentData(**json_data)
    else:
        parser.print_help()
        exit(0)
    
    generator = IncidentReportGenerator(output_path)
    result_path = generator.generate(data)
    
    print(f"\n{'='*50}")
    print("INCIDENT REPORT GENERATED")
    print(f"{'='*50}")
    print(f"Output: {result_path}")
    print(f"Report ID: {data.report_id}")
    print(f"{'='*50}\n")


if __name__ == '__main__':
    main()

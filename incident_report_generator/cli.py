#!/usr/bin/env python3
"""
Incident Report Generator CLI

Main entry point for generating incident reports.

Usage:
    python -m incident_report_generator blank                     # Generate blank form
    python -m incident_report_generator fill data.json            # Fill from JSON
    python -m incident_report_generator auto results.json         # Auto-fill from extraction
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .form_generator import IncidentReportGenerator, IncidentData
from .auto_filler import AutoReportFiller


def cmd_blank(args):
    """Generate a blank incident report form"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    
    output_path = args.output or str(output_dir / f"incident_report_blank_{timestamp}.pdf")
    
    data = IncidentData(
        report_id=f"IR-{timestamp[:8]}-XXXX",
        classification=args.classification
    )
    
    generator = IncidentReportGenerator(output_path)
    result_path = generator.generate(data)
    
    print(f"\nBlank form generated: {result_path}\n")


def cmd_fill(args):
    """Fill report from JSON data"""
    import json
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    
    output_path = args.output or str(output_dir / f"incident_report_{timestamp}.pdf")
    
    with open(args.json_file, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
    
    data = IncidentData(**json_data)
    
    generator = IncidentReportGenerator(output_path)
    result_path = generator.generate(data)
    
    print(f"\nFilled report generated: {result_path}\n")


def cmd_auto(args):
    """Auto-fill from extraction results"""
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or str(output_dir / f"incident_report_auto_{timestamp}.pdf")
    
    filler = AutoReportFiller()
    filler.load_extraction_json(args.extraction_file)
    
    if args.include_cve:
        cve_store = args.cve_store or str(Path(__file__).parent.parent / "cve_data" / "cve_store.json")
        if Path(cve_store).exists():
            filler.load_cve_intelligence(cve_store)
            print(f"Loaded CVE intelligence")
    
    result_path, incident_data = filler.generate_report(
        output_path,
        title=args.title,
        classification=args.classification
    )
    
    print(f"\n{'='*50}")
    print(f"Report ID:  {incident_data.report_id}")
    print(f"Severity:   {incident_data.severity}")
    print(f"Output:     {result_path}")
    print(f"{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Incident Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Blank form command
    blank_parser = subparsers.add_parser('blank', help='Generate blank form')
    blank_parser.add_argument('-o', '--output', help='Output path')
    blank_parser.add_argument('--classification', default='CONFIDENTIAL',
                             choices=['CONFIDENTIAL', 'INTERNAL', 'PUBLIC'])
    blank_parser.set_defaults(func=cmd_blank)
    
    # Fill from JSON command
    fill_parser = subparsers.add_parser('fill', help='Fill from JSON')
    fill_parser.add_argument('json_file', help='JSON data file')
    fill_parser.add_argument('-o', '--output', help='Output path')
    fill_parser.set_defaults(func=cmd_fill)
    
    # Auto-fill command
    auto_parser = subparsers.add_parser('auto', help='Auto-fill from extraction')
    auto_parser.add_argument('extraction_file', help='Extraction results JSON')
    auto_parser.add_argument('--include-cve', action='store_true', help='Include CVE enrichment')
    auto_parser.add_argument('--cve-store', help='CVE store path')
    auto_parser.add_argument('--title', help='Custom title')
    auto_parser.add_argument('--classification', default='CONFIDENTIAL',
                            choices=['CONFIDENTIAL', 'INTERNAL', 'PUBLIC'])
    auto_parser.add_argument('-o', '--output', help='Output path')
    auto_parser.set_defaults(func=cmd_auto)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == '__main__':
    main()

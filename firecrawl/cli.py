"""
CVE Intelligence CLI Interface
"""
import asyncio
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich import box

from .orchestrator import CVEIntelligenceOrchestrator
from .aggregator import CVEAggregator, PriorityScorer
from .models import CVERecord, Severity
from .config import DATA_DIR

console = Console()


def print_cve_table(cves: list, title: str, max_rows: int = 20):
    """Print CVEs in a formatted table"""
    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("CVSS", justify="center", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Priority", justify="center", style="yellow")
    table.add_column("KEV", justify="center")
    table.add_column("Exploit", justify="center")
    table.add_column("Trending", justify="center")
    table.add_column("Description", max_width=50)
    
    severity_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.UNKNOWN: "dim"
    }
    
    for cve in cves[:max_rows]:
        cvss = cve.highest_cvss
        cvss_str = f"{cvss:.1f}" if cvss else "N/A"
        
        severity = cve.severity
        severity_style = severity_colors.get(severity, "dim")
        
        kev = "✓" if cve.in_cisa_kev else ""
        exploit = "✓" if cve.has_exploit else ""
        trending = str(cve.trending_score) if cve.trending_score > 0 else ""
        
        desc = cve.description[:100] + "..." if cve.description and len(cve.description) > 100 else (cve.description or "N/A")
        
        table.add_row(
            cve.cve_id,
            cvss_str,
            f"[{severity_style}]{severity.value.upper()}[/]",
            str(cve.priority_score),
            f"[green]{kev}[/]",
            f"[red]{exploit}[/]",
            f"[magenta]{trending}[/]",
            desc
        )
    
    console.print(table)
    
    if len(cves) > max_rows:
        console.print(f"[dim]... and {len(cves) - max_rows} more[/]")


def print_cve_detail(cve: CVERecord):
    """Print detailed CVE information"""
    console.print(Panel(f"[bold cyan]{cve.cve_id}[/]", expand=False))
    
    # Basic info
    console.print(f"\n[bold]Description:[/]")
    console.print(cve.description or "No description available")
    
    # Dates
    console.print(f"\n[bold]Published:[/] {cve.published or 'Unknown'}")
    console.print(f"[bold]Modified:[/] {cve.modified or 'Unknown'}")
    
    # Severity and scores
    console.print(f"\n[bold]Severity:[/] [{_severity_color(cve.severity)}]{cve.severity.value.upper()}[/]")
    
    if cve.cvss_scores:
        console.print(f"\n[bold]CVSS Scores:[/]")
        for score in cve.cvss_scores:
            console.print(f"  • v{score.version}: {score.score} ({score.source})")
            if score.vector:
                console.print(f"    [dim]{score.vector}[/]")
    
    if cve.epss_score:
        console.print(f"\n[bold]EPSS Score:[/] {cve.epss_score:.2%}")
    
    # Risk indicators
    console.print(f"\n[bold]Risk Indicators:[/]")
    console.print(f"  • CISA KEV: {'[green]Yes[/]' if cve.in_cisa_kev else '[dim]No[/]'}")
    console.print(f"  • Public Exploit: {'[red]Yes[/]' if cve.has_exploit else '[dim]No[/]'}")
    console.print(f"  • Priority Score: [yellow]{cve.priority_score}[/]")
    console.print(f"  • Trending Score: [magenta]{cve.trending_score}[/]")
    
    # Affected
    if cve.affected_vendors:
        console.print(f"\n[bold]Affected Vendors:[/] {', '.join(cve.affected_vendors[:10])}")
    if cve.affected_products:
        console.print(f"[bold]Affected Products:[/] {', '.join(cve.affected_products[:10])}")
    if cve.cwe_ids:
        console.print(f"[bold]CWE IDs:[/] {', '.join(cve.cwe_ids)}")
    
    # Exploits
    if cve.exploits:
        console.print(f"\n[bold red]Exploits ({len(cve.exploits)}):[/]")
        for exploit in cve.exploits[:5]:
            console.print(f"  • [{exploit.source}] {exploit.title or exploit.url}")
            console.print(f"    [dim]{exploit.url}[/]")
    
    # Social mentions
    if cve.social_mentions:
        console.print(f"\n[bold]Social Mentions ({len(cve.social_mentions)}):[/]")
        for mention in cve.social_mentions[:5]:
            console.print(f"  • [{mention.platform}] {mention.content or mention.url}")
            if mention.engagement:
                console.print(f"    [dim]Engagement: {mention.engagement}[/]")
    
    # References
    if cve.references:
        console.print(f"\n[bold]References ({len(cve.references)}):[/]")
        for ref in cve.references[:10]:
            console.print(f"  • [{ref.type}] {ref.title or ref.url}")
            console.print(f"    [dim]{ref.url}[/]")
    
    # Sources
    console.print(f"\n[bold]Data Sources:[/] {', '.join(cve.sources_collected)}")
    console.print(f"[bold]Last Updated:[/] {cve.last_updated}")


def _severity_color(severity: Severity) -> str:
    """Get color for severity"""
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.UNKNOWN: "dim"
    }
    return colors.get(severity, "dim")


def print_summary(report):
    """Print report summary"""
    console.print(Panel(
        f"[bold]CVE Intelligence Report[/]\n"
        f"Generated: {report.date}\n\n"
        f"Total New CVEs: [cyan]{report.total_new_cves}[/]\n"
        f"Critical CVEs: [red]{len(report.critical_cves)}[/]\n"
        f"Trending CVEs: [magenta]{len(report.trending_cves)}[/]\n"
        f"With Exploits: [yellow]{len(report.newly_exploited)}[/]\n"
        f"In CISA KEV: [green]{len(report.kev_additions)}[/]",
        title="Summary",
        expand=False
    ))


async def cmd_collect(args):
    """Run collection from all sources"""
    console.print("[bold]Starting CVE collection...[/]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting from all sources...", total=None)
        
        orchestrator = CVEIntelligenceOrchestrator()
        records = await orchestrator.collect_all(days_back=args.days)
        
        progress.update(task, description="Collection complete!")
    
    console.print(f"\n[green]Collected {len(records)} CVE records[/]")


async def cmd_enrich(args):
    """Enrich CVE records"""
    console.print("[bold]Enriching CVE records...[/]")
    
    orchestrator = CVEIntelligenceOrchestrator()
    orchestrator.aggregator.load()
    
    cve_ids = args.cve_ids.split(",") if args.cve_ids else None
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Enriching...", total=None)
        await orchestrator.enrich_cves(cve_ids=cve_ids, top_n=args.top)
        progress.update(task, description="Enrichment complete!")
    
    console.print("[green]Enrichment complete[/]")


async def cmd_report(args):
    """Generate and display report"""
    orchestrator = CVEIntelligenceOrchestrator()
    orchestrator.aggregator.load()
    
    report = orchestrator.generate_report(days_back=args.days)
    
    print_summary(report)
    
    if report.critical_cves:
        console.print()
        print_cve_table(report.critical_cves, "🔴 Critical CVEs", max_rows=args.limit)
    
    if report.kev_additions:
        console.print()
        print_cve_table(report.kev_additions, "⚠️ CISA Known Exploited Vulnerabilities", max_rows=args.limit)
    
    if report.trending_cves:
        console.print()
        print_cve_table(report.trending_cves, "📈 Trending CVEs", max_rows=args.limit)
    
    if report.newly_exploited:
        console.print()
        print_cve_table(report.newly_exploited, "💥 CVEs with Public Exploits", max_rows=args.limit)


async def cmd_run(args):
    """Run full daily pipeline"""
    console.print(Panel("[bold]CVE Intelligence Daily Pipeline[/]", expand=False))
    
    orchestrator = CVEIntelligenceOrchestrator()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running pipeline...", total=None)
        report = await orchestrator.run_daily_pipeline(days_back=args.days)
        progress.update(task, description="Pipeline complete!")
    
    console.print()
    print_summary(report)
    
    if args.show_top:
        console.print()
        print_cve_table(report.all_cves, "🎯 Top Priority CVEs", max_rows=args.show_top)


async def cmd_search(args):
    """Search for a specific CVE"""
    aggregator = CVEAggregator()
    aggregator.load()
    
    cve = aggregator.get_record(args.cve_id.upper())
    
    if cve:
        print_cve_detail(cve)
    else:
        console.print(f"[yellow]CVE {args.cve_id} not found in local database[/]")
        console.print("Run 'cve-intel collect' first or search online")


async def cmd_list(args):
    """List CVEs with filtering"""
    aggregator = CVEAggregator()
    aggregator.load()
    
    scorer = PriorityScorer()
    all_cves = scorer.score_all(aggregator.get_all_records())
    
    # Apply filters
    filtered = all_cves
    
    if args.severity:
        filtered = [c for c in filtered if c.severity.value == args.severity.lower()]
    
    if args.kev:
        filtered = [c for c in filtered if c.in_cisa_kev]
    
    if args.exploit:
        filtered = [c for c in filtered if c.has_exploit]
    
    if args.vendor:
        filtered = [c for c in filtered if any(args.vendor.lower() in v.lower() for v in c.affected_vendors)]
    
    title = "CVE List"
    if args.severity:
        title += f" (Severity: {args.severity})"
    if args.kev:
        title += " (In KEV)"
    if args.exploit:
        title += " (Has Exploit)"
    if args.vendor:
        title += f" (Vendor: {args.vendor})"
    
    print_cve_table(filtered, title, max_rows=args.limit)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="CVE Intelligence System - Track and prioritize CVEs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # collect command
    collect_parser = subparsers.add_parser("collect", help="Collect CVEs from all sources")
    collect_parser.add_argument("-d", "--days", type=int, default=7, help="Days to look back")
    
    # enrich command
    enrich_parser = subparsers.add_parser("enrich", help="Enrich CVE records with additional data")
    enrich_parser.add_argument("-c", "--cve-ids", help="Comma-separated CVE IDs to enrich")
    enrich_parser.add_argument("-t", "--top", type=int, default=50, help="Enrich top N CVEs by priority")
    
    # report command
    report_parser = subparsers.add_parser("report", help="Generate and display report")
    report_parser.add_argument("-d", "--days", type=int, default=1, help="Days to include in report")
    report_parser.add_argument("-l", "--limit", type=int, default=20, help="Max CVEs to show per category")
    
    # run command
    run_parser = subparsers.add_parser("run", help="Run full daily pipeline")
    run_parser.add_argument("-d", "--days", type=int, default=7, help="Days to look back")
    run_parser.add_argument("-s", "--show-top", type=int, default=20, help="Show top N CVEs after run")
    
    # search command
    search_parser = subparsers.add_parser("search", help="Search for a specific CVE")
    search_parser.add_argument("cve_id", help="CVE ID to search for")
    
    # list command
    list_parser = subparsers.add_parser("list", help="List CVEs with filtering")
    list_parser.add_argument("-s", "--severity", choices=["critical", "high", "medium", "low"], help="Filter by severity")
    list_parser.add_argument("-k", "--kev", action="store_true", help="Only show KEV entries")
    list_parser.add_argument("-e", "--exploit", action="store_true", help="Only show CVEs with exploits")
    list_parser.add_argument("-v", "--vendor", help="Filter by vendor name")
    list_parser.add_argument("-l", "--limit", type=int, default=50, help="Max CVEs to show")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to command handler
    commands = {
        "collect": cmd_collect,
        "enrich": cmd_enrich,
        "report": cmd_report,
        "run": cmd_run,
        "search": cmd_search,
        "list": cmd_list,
    }
    
    handler = commands.get(args.command)
    if handler:
        asyncio.run(handler(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

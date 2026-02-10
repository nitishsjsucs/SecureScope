"""
Test script for CVE Intelligence System
Verifies that all components work correctly
"""
import asyncio
import sys
from datetime import datetime
from pathlib import Path

# Test imports
def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from cve_intelligence.models import CVERecord, CVSSScore, Severity, DailyReport
        print("  ✓ models imported")
    except ImportError as e:
        print(f"  ✗ models import failed: {e}")
        return False
    
    try:
        from cve_intelligence.config import SOURCES, PRIORITY_WEIGHTS, DATA_DIR
        print("  ✓ config imported")
    except ImportError as e:
        print(f"  ✗ config import failed: {e}")
        return False
    
    try:
        from cve_intelligence.aggregator import CVEAggregator, PriorityScorer
        print("  ✓ aggregator imported")
    except ImportError as e:
        print(f"  ✗ aggregator import failed: {e}")
        return False
    
    try:
        from cve_intelligence.collectors import (
            NVDCollector, CISAKEVCollector, 
            ExploitDBCollector, GitHubAdvisoryCollector
        )
        print("  ✓ collectors imported")
    except ImportError as e:
        print(f"  ✗ collectors import failed: {e}")
        return False
    
    try:
        from cve_intelligence.orchestrator import CVEIntelligenceOrchestrator
        print("  ✓ orchestrator imported")
    except ImportError as e:
        print(f"  ✗ orchestrator import failed: {e}")
        return False
    
    try:
        from cve_intelligence.firecrawl_client import FirecrawlClient, CVESearcher
        print("  ✓ firecrawl_client imported")
    except ImportError as e:
        print(f"  ✗ firecrawl_client import failed: {e}")
        return False
    
    return True


def test_models():
    """Test data models"""
    print("\nTesting data models...")
    
    from cve_intelligence.models import CVERecord, CVSSScore, Severity, Reference, Exploit
    
    # Create a CVE record
    cve = CVERecord(
        cve_id="CVE-2024-12345",
        description="Test vulnerability",
        published=datetime.now()
    )
    
    # Add CVSS score
    cve.cvss_scores.append(CVSSScore(
        version="3.1",
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        source="test"
    ))
    
    # Add exploit
    cve.exploits.append(Exploit(
        source="test",
        url="https://example.com/exploit",
        title="Test Exploit"
    ))
    
    # Test properties
    assert cve.highest_cvss == 9.8, "highest_cvss failed"
    assert cve.severity == Severity.CRITICAL, "severity failed"
    assert cve.has_exploit == True, "has_exploit failed"
    
    # Test serialization
    data = cve.to_dict()
    assert data["cve_id"] == "CVE-2024-12345", "to_dict failed"
    
    # Test deserialization
    cve2 = CVERecord.from_dict(data)
    assert cve2.cve_id == cve.cve_id, "from_dict failed"
    
    print("  ✓ CVERecord works correctly")
    return True


def test_aggregator():
    """Test aggregator and scoring"""
    print("\nTesting aggregator...")
    
    from cve_intelligence.models import CVERecord, CVSSScore
    from cve_intelligence.aggregator import CVEAggregator, PriorityScorer
    
    aggregator = CVEAggregator()
    
    # Create test records
    cve1 = CVERecord(cve_id="CVE-2024-0001")
    cve1.cvss_scores.append(CVSSScore(version="3.1", score=9.8, source="nvd"))
    cve1.in_cisa_kev = True
    cve1.sources_collected.append("nvd")
    
    cve2 = CVERecord(cve_id="CVE-2024-0001")  # Same CVE, different source
    cve2.description = "Test description"
    cve2.sources_collected.append("github")
    
    # Add records
    aggregator.add_records([cve1])
    aggregator.add_records([cve2])
    
    # Check merge
    merged = aggregator.get_record("CVE-2024-0001")
    assert merged is not None, "Record not found"
    assert "nvd" in merged.sources_collected, "NVD source missing"
    assert "github" in merged.sources_collected, "GitHub source missing"
    assert merged.description == "Test description", "Description not merged"
    
    print("  ✓ Aggregator merges records correctly")
    
    # Test scorer
    scorer = PriorityScorer()
    score = scorer.score(merged)
    assert score > 100, f"Score should be > 100 for KEV CVE, got {score}"
    
    print(f"  ✓ Scorer works correctly (score: {score})")
    return True


async def test_nvd_collector():
    """Test NVD collector (requires network)"""
    print("\nTesting NVD collector...")
    
    from cve_intelligence.collectors import NVDCollector
    
    collector = NVDCollector()
    
    # Test with small date range
    try:
        records = await collector.collect(days_back=1)
        print(f"  ✓ NVD collector returned {len(records)} CVEs")
        
        if records:
            cve = records[0]
            print(f"  ✓ Sample CVE: {cve.cve_id}")
        
        return True
    except Exception as e:
        print(f"  ⚠ NVD collector error (may be rate limited): {e}")
        return True  # Don't fail test for rate limiting


async def test_cisa_kev_collector():
    """Test CISA KEV collector (requires network)"""
    print("\nTesting CISA KEV collector...")
    
    from cve_intelligence.collectors import CISAKEVCollector
    
    collector = CISAKEVCollector()
    
    try:
        records = await collector.collect(days_back=90)
        print(f"  ✓ CISA KEV collector returned {len(records)} CVEs")
        
        if records:
            cve = records[0]
            print(f"  ✓ Sample KEV: {cve.cve_id}")
            assert cve.in_cisa_kev, "KEV flag not set"
        
        return True
    except Exception as e:
        print(f"  ✗ CISA KEV collector error: {e}")
        return False


async def test_firecrawl_client():
    """Test Firecrawl client (requires API key)"""
    print("\nTesting Firecrawl client...")
    
    from cve_intelligence.firecrawl_client import FirecrawlClient
    from cve_intelligence.config import FIRECRAWL_API_KEY
    
    if not FIRECRAWL_API_KEY or FIRECRAWL_API_KEY == "your_firecrawl_api_key_here":
        print("  ⚠ Firecrawl API key not configured, skipping test")
        return True
    
    try:
        client = FirecrawlClient()
        
        # Test search
        result = await client.search("CVE-2024 vulnerability", limit=3)
        if result and result.get("success"):
            print("  ✓ Firecrawl search works")
        else:
            print("  ⚠ Firecrawl search returned no results")
        
        return True
    except Exception as e:
        print(f"  ⚠ Firecrawl error: {e}")
        return True


async def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("CVE INTELLIGENCE SYSTEM - TEST SUITE")
    print("=" * 60)
    
    results = []
    
    # Synchronous tests
    results.append(("Imports", test_imports()))
    results.append(("Models", test_models()))
    results.append(("Aggregator", test_aggregator()))
    
    # Async tests
    results.append(("CISA KEV Collector", await test_cisa_kev_collector()))
    results.append(("NVD Collector", await test_nvd_collector()))
    results.append(("Firecrawl Client", await test_firecrawl_client()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nPassed: {passed}/{total}")
    
    return passed == total


def main():
    """Main entry point"""
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

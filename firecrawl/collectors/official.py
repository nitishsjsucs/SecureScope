"""
Official CVE source collectors (NVD, CISA KEV, etc.)
"""
import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import httpx

from .base import BaseCollector
from ..models import CVERecord, CVSSScore, Reference
from ..config import SOURCES, NVD_API_KEY

logger = logging.getLogger(__name__)


class NVDCollector(BaseCollector):
    """Collector for NVD (National Vulnerability Database)"""
    
    name = "nvd"
    source_type = "official"
    
    def __init__(self, api_key: Optional[str] = None, nvd_api_key: Optional[str] = None):
        super().__init__(api_key)
        self.nvd_api_key = nvd_api_key or NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    async def collect(self, days_back: int = 7, **kwargs) -> List[CVERecord]:
        """Collect recent CVEs from NVD API"""
        logger.info(f"Collecting CVEs from NVD for last {days_back} days")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 100
        }
        
        records = []
        start_index = 0
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params["startIndex"] = start_index
                headers = {}
                if self.nvd_api_key:
                    headers["apiKey"] = self.nvd_api_key
                
                try:
                    response = await client.get(self.base_url, params=params, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                except Exception as e:
                    logger.error(f"NVD API error: {e}")
                    break
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    record = self._parse_nvd_cve(vuln.get("cve", {}))
                    if record:
                        records.append(record)
                
                total_results = data.get("totalResults", 0)
                start_index += len(vulnerabilities)
                
                if start_index >= total_results:
                    break
                
                # Rate limiting
                await asyncio.sleep(0.6 if not self.nvd_api_key else 0.1)
        
        logger.info(f"Collected {len(records)} CVEs from NVD")
        return records
    
    def _parse_nvd_cve(self, cve_data: Dict) -> Optional[CVERecord]:
        """Parse NVD CVE data into CVERecord"""
        try:
            cve_id = cve_data.get("id")
            if not cve_id:
                return None
            
            record = CVERecord(cve_id=cve_id)
            
            # Description
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    record.description = desc.get("value")
                    break
            
            # Dates
            if cve_data.get("published"):
                record.published = datetime.fromisoformat(
                    cve_data["published"].replace("Z", "+00:00")
                )
            if cve_data.get("lastModified"):
                record.modified = datetime.fromisoformat(
                    cve_data["lastModified"].replace("Z", "+00:00")
                )
            
            # CVSS Scores
            metrics = cve_data.get("metrics", {})
            
            # CVSS 3.1
            for cvss31 in metrics.get("cvssMetricV31", []):
                cvss_data = cvss31.get("cvssData", {})
                record.cvss_scores.append(CVSSScore(
                    version="3.1",
                    score=cvss_data.get("baseScore", 0),
                    vector=cvss_data.get("vectorString"),
                    severity=cvss_data.get("baseSeverity"),
                    source="nvd"
                ))
            
            # CVSS 3.0
            for cvss30 in metrics.get("cvssMetricV30", []):
                cvss_data = cvss30.get("cvssData", {})
                record.cvss_scores.append(CVSSScore(
                    version="3.0",
                    score=cvss_data.get("baseScore", 0),
                    vector=cvss_data.get("vectorString"),
                    severity=cvss_data.get("baseSeverity"),
                    source="nvd"
                ))
            
            # CVSS 2.0
            for cvss2 in metrics.get("cvssMetricV2", []):
                cvss_data = cvss2.get("cvssData", {})
                record.cvss_scores.append(CVSSScore(
                    version="2.0",
                    score=cvss_data.get("baseScore", 0),
                    vector=cvss_data.get("vectorString"),
                    severity=cvss2.get("baseSeverity"),
                    source="nvd"
                ))
            
            # CWE IDs
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_id = desc.get("value")
                    if cwe_id and cwe_id.startswith("CWE-"):
                        record.cwe_ids.append(cwe_id)
            
            # References
            for ref in cve_data.get("references", []):
                ref_type = "reference"
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    ref_type = "exploit"
                elif "Patch" in tags:
                    ref_type = "patch"
                elif "Vendor Advisory" in tags:
                    ref_type = "advisory"
                
                record.references.append(Reference(
                    url=ref.get("url", ""),
                    source="nvd",
                    type=ref_type
                ))
            
            # Affected configurations (simplified)
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                if vendor and vendor not in record.affected_vendors:
                                    record.affected_vendors.append(vendor)
                                if product and product not in record.affected_products:
                                    record.affected_products.append(product)
            
            record.sources_collected.append("nvd")
            record.last_updated = datetime.now()
            record.raw_data["nvd"] = cve_data
            
            return record
        
        except Exception as e:
            logger.error(f"Error parsing NVD CVE: {e}")
            return None
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Enrich a CVE record with NVD data"""
        cache_key = f"nvd_{cve.cve_id}"
        cached = self._get_cached(cache_key, max_age_hours=6)
        
        if cached:
            return self._merge_nvd_data(cve, cached)
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                params = {"cveId": cve.cve_id}
                headers = {}
                if self.nvd_api_key:
                    headers["apiKey"] = self.nvd_api_key
                
                response = await client.get(self.base_url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    self._set_cache(cache_key, cve_data)
                    return self._merge_nvd_data(cve, cve_data)
            
            except Exception as e:
                logger.error(f"Error enriching {cve.cve_id} from NVD: {e}")
        
        return cve
    
    def _merge_nvd_data(self, cve: CVERecord, nvd_data: Dict) -> CVERecord:
        """Merge NVD data into existing CVE record"""
        parsed = self._parse_nvd_cve(nvd_data)
        if not parsed:
            return cve
        
        # Merge description if missing
        if not cve.description:
            cve.description = parsed.description
        
        # Merge CVSS scores (avoid duplicates)
        existing_scores = {(s.version, s.source) for s in cve.cvss_scores}
        for score in parsed.cvss_scores:
            if (score.version, score.source) not in existing_scores:
                cve.cvss_scores.append(score)
        
        # Merge CWE IDs
        cve.cwe_ids = list(set(cve.cwe_ids + parsed.cwe_ids))
        
        # Merge references (avoid duplicate URLs)
        existing_urls = {r.url for r in cve.references}
        for ref in parsed.references:
            if ref.url not in existing_urls:
                cve.references.append(ref)
        
        # Merge affected products/vendors
        cve.affected_vendors = list(set(cve.affected_vendors + parsed.affected_vendors))
        cve.affected_products = list(set(cve.affected_products + parsed.affected_products))
        
        if "nvd" not in cve.sources_collected:
            cve.sources_collected.append("nvd")
        
        cve.raw_data["nvd"] = nvd_data
        
        return cve


class CISAKEVCollector(BaseCollector):
    """Collector for CISA Known Exploited Vulnerabilities Catalog"""
    
    name = "cisa_kev"
    source_type = "official"
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    async def collect(self, days_back: int = 30, **kwargs) -> List[CVERecord]:
        """Collect CVEs from CISA KEV catalog"""
        logger.info("Collecting CVEs from CISA KEV catalog")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(self.kev_url)
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                logger.error(f"CISA KEV API error: {e}")
                return []
        
        records = []
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        for vuln in data.get("vulnerabilities", []):
            try:
                date_added = datetime.strptime(vuln.get("dateAdded", ""), "%Y-%m-%d")
                if date_added < cutoff_date:
                    continue
                
                cve_id = vuln.get("cveID")
                if not cve_id:
                    continue
                
                record = CVERecord(
                    cve_id=cve_id,
                    description=vuln.get("shortDescription"),
                    in_cisa_kev=True,
                    kev_date_added=date_added
                )
                
                # Vendor and product
                vendor = vuln.get("vendorProject")
                product = vuln.get("product")
                if vendor:
                    record.affected_vendors.append(vendor)
                if product:
                    record.affected_products.append(product)
                
                record.sources_collected.append("cisa_kev")
                record.last_updated = datetime.now()
                record.raw_data["cisa_kev"] = vuln
                
                records.append(record)
            
            except Exception as e:
                logger.error(f"Error parsing CISA KEV entry: {e}")
        
        logger.info(f"Collected {len(records)} CVEs from CISA KEV")
        return records
    
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Check if CVE is in CISA KEV and add that information"""
        cache_key = "cisa_kev_catalog"
        cached = self._get_cached(cache_key, max_age_hours=6)
        
        if not cached:
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    response = await client.get(self.kev_url)
                    response.raise_for_status()
                    cached = response.json()
                    self._set_cache(cache_key, cached)
                except Exception as e:
                    logger.error(f"CISA KEV fetch error: {e}")
                    return cve
        
        for vuln in cached.get("vulnerabilities", []):
            if vuln.get("cveID") == cve.cve_id:
                cve.in_cisa_kev = True
                try:
                    cve.kev_date_added = datetime.strptime(vuln.get("dateAdded", ""), "%Y-%m-%d")
                except:
                    pass
                
                if "cisa_kev" not in cve.sources_collected:
                    cve.sources_collected.append("cisa_kev")
                
                cve.raw_data["cisa_kev"] = vuln
                break
        
        return cve

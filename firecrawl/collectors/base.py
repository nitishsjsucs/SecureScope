"""
Base collector class for CVE data sources
"""
import os
import json
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from ..models import CVERecord
from ..config import CACHE_DIR, FIRECRAWL_API_KEY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base class for all CVE data collectors"""
    
    name: str = "base"
    source_type: str = "unknown"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or FIRECRAWL_API_KEY
        self.cache_dir = CACHE_DIR / self.name
        self.cache_dir.mkdir(exist_ok=True)
        
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"
    
    def _get_cached(self, key: str, max_age_hours: int = 1) -> Optional[Dict]:
        """Get cached data if not expired"""
        cache_path = self._get_cache_path(key)
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            cached_time = datetime.fromisoformat(data.get("_cached_at", "2000-01-01"))
            if datetime.now() - cached_time > timedelta(hours=max_age_hours):
                return None
            
            return data.get("data")
        except Exception as e:
            logger.warning(f"Cache read error for {key}: {e}")
            return None
    
    def _set_cache(self, key: str, data: Any):
        """Cache data with timestamp"""
        cache_path = self._get_cache_path(key)
        try:
            with open(cache_path, 'w') as f:
                json.dump({
                    "_cached_at": datetime.now().isoformat(),
                    "data": data
                }, f)
        except Exception as e:
            logger.warning(f"Cache write error for {key}: {e}")
    
    @abstractmethod
    async def collect(self, **kwargs) -> List[CVERecord]:
        """Collect CVE data from the source"""
        pass
    
    @abstractmethod
    async def enrich(self, cve: CVERecord) -> CVERecord:
        """Enrich an existing CVE record with data from this source"""
        pass
    
    def parse_cve_id(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        import re
        pattern = r'CVE-\d{4}-\d{4,}'
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

"""
MongoDB client for fetching unscored CVEs from vulntracker database.
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

try:
    from pymongo import MongoClient
    from pymongo.collection import Collection
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False


class MongoDBClient:
    """Client for interacting with MongoDB CVE database."""
    
    def __init__(
        self,
        uri: Optional[str] = None,
        database: str = "vulntracker",
        collection: str = "cves"
    ):
        """Initialize MongoDB client."""
        if not HAS_PYMONGO:
            raise ImportError("pymongo is required. Install with: pip install pymongo")
        
        self.uri = uri or os.getenv("MONGODB_URI")
        if not self.uri:
            raise ValueError("MONGODB_URI is required")
        
        self.database_name = database
        self.collection_name = collection
        self.client = MongoClient(self.uri)
        self.db = self.client[database]
        self.collection: Collection = self.db[collection]
    
    def get_unscored_cves(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch CVEs that don't have CVSS scores yet, sorted by most recent."""
        query = {
            "$or": [
                {"cvss_score": {"$exists": False}},
                {"cvss_score": None},
                {"cvss_score": 0},
                {"metrics.cvssMetricV40": {"$exists": False}},
                {"metrics.cvssMetricV31": {"$exists": False}},
            ]
        }
        
        # Sort by created_at descending to get latest CVEs first
        cursor = self.collection.find(query).sort("created_at", -1).limit(limit)
        return list(cursor)
    
    def get_recent_unscored_cves(self, days: int = 7, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch recently published CVEs without scores."""
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        query = {
            "$and": [
                {
                    "$or": [
                        {"cvss_score": {"$exists": False}},
                        {"cvss_score": None},
                        {"cvss_score": 0},
                        {"metrics.cvssMetricV40": {"$exists": False}},
                    ]
                },
                {
                    "$or": [
                        {"published": {"$gte": cutoff_date}},
                        {"datePublished": {"$gte": cutoff_date.isoformat()}},
                    ]
                }
            ]
        }
        
        cursor = self.collection.find(query).sort("published", -1).limit(limit)
        return list(cursor)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by its ID."""
        return self.collection.find_one({"cve_id": cve_id}) or \
               self.collection.find_one({"id": cve_id}) or \
               self.collection.find_one({"_id": cve_id})
    
    def update_cve_score(
        self,
        cve_id: str,
        cvss_score: float,
        cvss_vector: str,
        severity: str,
        ai_predicted: bool = True,
        model_used: str = "ensemble",
        confidence: float = 0.0,
        gpt_score: Optional[float] = None,
        finetuned_score: Optional[float] = None,
    ) -> bool:
        """Update a CVE with AI-predicted score."""
        update_data = {
            "$set": {
                "ai_cvss_score": cvss_score,
                "ai_cvss_vector": cvss_vector,
                "ai_severity": severity,
                "ai_predicted": ai_predicted,
                "ai_model_used": model_used,
                "ai_confidence": confidence,
                "ai_scored_at": datetime.utcnow(),
                "ai_gpt_score": gpt_score,
                "ai_finetuned_score": finetuned_score,
            }
        }
        
        result = self.collection.update_one(
            {"$or": [{"cve_id": cve_id}, {"id": cve_id}]},
            update_data
        )
        
        return result.modified_count > 0
    
    def get_ai_scored_cves(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get CVEs that have been scored by AI."""
        query = {"ai_predicted": True}
        cursor = self.collection.find(query).sort("ai_scored_at", -1).limit(limit)
        return list(cursor)
    
    def count_unscored(self) -> int:
        """Count total unscored CVEs."""
        query = {
            "$or": [
                {"cvss_score": {"$exists": False}},
                {"cvss_score": None},
                {"cvss_score": 0},
            ]
        }
        return self.collection.count_documents(query)
    
    def count_ai_scored(self) -> int:
        """Count AI-scored CVEs."""
        return self.collection.count_documents({"ai_predicted": True})
    
    def insert_ai_scored_cve(
        self,
        cve_data: Dict[str, Any],
        target_collection: str = "ai_scored_cves"
    ) -> bool:
        """Insert a scored CVE into a separate collection."""
        target = self.db[target_collection]
        try:
            # Use upsert to avoid duplicates
            cve_id = cve_data.get("cve_id") or cve_data.get("_id")
            result = target.update_one(
                {"_id": cve_id},
                {"$set": cve_data},
                upsert=True
            )
            return result.acknowledged
        except Exception as e:
            print(f"Error inserting to {target_collection}: {e}")
            return False
    
    def get_ai_scored_collection(self, collection_name: str = "ai_scored_cves"):
        """Get or create the AI scored CVEs collection."""
        return self.db[collection_name]
    
    def close(self):
        """Close the MongoDB connection."""
        self.client.close()


if __name__ == "__main__":
    client = MongoDBClient()
    print(f"Connected to MongoDB")
    print(f"Unscored CVEs: {client.count_unscored()}")
    
    unscored = client.get_unscored_cves(limit=5)
    print(f"\nSample unscored CVEs:")
    for cve in unscored:
        cve_id = cve.get("cve_id") or cve.get("id") or cve.get("_id")
        print(f"  - {cve_id}")
    
    client.close()

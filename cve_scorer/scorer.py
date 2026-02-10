"""
Main CVE Scorer - Orchestrates the entire scoring pipeline.
"""

import os
import sys
import argparse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from .mongo_client import MongoDBClient
from .ensemble import EnsembleScorer, EnsembleResult


@dataclass
class ScoringResult:
    """Result of scoring operation."""
    cve_id: str
    final_score: float
    final_vector: str
    severity: str
    confidence: float
    gpt_score: float
    finetuned_score: float
    method: str
    ai_predicted: bool
    scored_at: str
    success: bool
    error: Optional[str] = None


class CVEScorer:
    """Main orchestrator for CVE scoring pipeline."""
    
    def __init__(
        self,
        mongodb_uri: Optional[str] = None,
        database: str = "vulntracker",
        collection: str = "cves",
        gpt_model: str = "gpt-5.2-pro-2025-12-11",
        finetuned_model: Optional[str] = None,
        gpt_weight: float = 0.4,
        finetuned_weight: float = 0.6,
    ):
        """
        Initialize CVE Scorer.
        
        Args:
            mongodb_uri: MongoDB connection string
            database: Database name
            collection: Collection name
            gpt_model: GPT model to use
            finetuned_model: Fine-tuned model ID
            gpt_weight: Weight for GPT predictions
            finetuned_weight: Weight for fine-tuned predictions
        """
        self.mongo_client = MongoDBClient(
            uri=mongodb_uri,
            database=database,
            collection=collection
        )
        
        self.ensemble_scorer = EnsembleScorer(
            gpt_weight=gpt_weight,
            finetuned_weight=finetuned_weight,
            gpt_model=gpt_model,
            finetuned_model=finetuned_model
        )
    
    def _get_cve_id(self, cve: Dict[str, Any]) -> str:
        """Extract CVE ID from document."""
        return cve.get("cve_id") or cve.get("id") or str(cve.get("_id", "unknown"))
    
    def score_single(self, cve: Dict[str, Any], update_db: bool = True) -> ScoringResult:
        """
        Score a single CVE.
        
        Args:
            cve: CVE document
            update_db: Whether to update the database with the score
            
        Returns:
            ScoringResult
        """
        cve_id = self._get_cve_id(cve)
        
        try:
            # Get ensemble prediction
            result = self.ensemble_scorer.score(cve)
            
            scoring_result = ScoringResult(
                cve_id=cve_id,
                final_score=result.final_score,
                final_vector=result.final_vector,
                severity=result.final_severity,
                confidence=result.confidence,
                gpt_score=result.gpt_prediction.score,
                finetuned_score=result.finetuned_prediction.score,
                method=result.method,
                ai_predicted=True,
                scored_at=datetime.utcnow().isoformat(),
                success=True
            )
            
            # Update database if requested
            if update_db:
                self.mongo_client.update_cve_score(
                    cve_id=cve_id,
                    cvss_score=result.final_score,
                    cvss_vector=result.final_vector,
                    severity=result.final_severity,
                    ai_predicted=True,
                    model_used=result.method,
                    confidence=result.confidence,
                    gpt_score=result.gpt_prediction.score,
                    finetuned_score=result.finetuned_prediction.score,
                )
            
            return scoring_result
            
        except Exception as e:
            return ScoringResult(
                cve_id=cve_id,
                final_score=0,
                final_vector="",
                severity="Unknown",
                confidence=0,
                gpt_score=0,
                finetuned_score=0,
                method="error",
                ai_predicted=False,
                scored_at=datetime.utcnow().isoformat(),
                success=False,
                error=str(e)
            )
    
    def score_unscored(
        self,
        limit: int = 100,
        update_db: bool = True,
        verbose: bool = True
    ) -> List[ScoringResult]:
        """
        Score all unscored CVEs from the database.
        
        Args:
            limit: Maximum number of CVEs to score
            update_db: Whether to update the database
            verbose: Print progress
            
        Returns:
            List of ScoringResult
        """
        if verbose:
            print(f"Fetching unscored CVEs (limit: {limit})...")
        
        unscored_cves = self.mongo_client.get_unscored_cves(limit=limit)
        
        if verbose:
            print(f"Found {len(unscored_cves)} unscored CVEs")
        
        results = []
        for i, cve in enumerate(unscored_cves):
            cve_id = self._get_cve_id(cve)
            
            if verbose:
                print(f"  [{i+1}/{len(unscored_cves)}] Scoring {cve_id}...", end=" ")
            
            result = self.score_single(cve, update_db=update_db)
            results.append(result)
            
            if verbose:
                if result.success:
                    print(f"✓ {result.final_score} ({result.severity})")
                else:
                    print(f"✗ Error: {result.error}")
        
        return results
    
    def score_recent(
        self,
        days: int = 7,
        limit: int = 100,
        update_db: bool = True,
        verbose: bool = True
    ) -> List[ScoringResult]:
        """
        Score recently published unscored CVEs.
        
        Args:
            days: Number of days to look back
            limit: Maximum number of CVEs
            update_db: Whether to update database
            verbose: Print progress
            
        Returns:
            List of ScoringResult
        """
        if verbose:
            print(f"Fetching recent unscored CVEs (last {days} days, limit: {limit})...")
        
        recent_cves = self.mongo_client.get_recent_unscored_cves(days=days, limit=limit)
        
        if verbose:
            print(f"Found {len(recent_cves)} recent unscored CVEs")
        
        results = []
        for i, cve in enumerate(recent_cves):
            cve_id = self._get_cve_id(cve)
            
            if verbose:
                print(f"  [{i+1}/{len(recent_cves)}] Scoring {cve_id}...", end=" ")
            
            result = self.score_single(cve, update_db=update_db)
            results.append(result)
            
            if verbose:
                if result.success:
                    print(f"✓ {result.final_score} ({result.severity})")
                else:
                    print(f"✗ Error: {result.error}")
        
        return results
    
    def score_by_id(self, cve_id: str, update_db: bool = True) -> Optional[ScoringResult]:
        """Score a specific CVE by ID."""
        cve = self.mongo_client.get_cve_by_id(cve_id)
        if not cve:
            return None
        return self.score_single(cve, update_db=update_db)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scoring statistics."""
        return {
            "total_unscored": self.mongo_client.count_unscored(),
            "total_ai_scored": self.mongo_client.count_ai_scored(),
        }
    
    def score_and_store_new_collection(
        self,
        limit: int = 50,
        target_collection: str = "ai_scored_cves",
        verbose: bool = True
    ) -> List[ScoringResult]:
        """
        Score CVEs and store in a new collection.
        
        Args:
            limit: Number of CVEs to score
            target_collection: Name of new collection to store results
            verbose: Print progress
            
        Returns:
            List of ScoringResult
        """
        if verbose:
            print(f"Fetching {limit} latest unscored CVEs...")
        
        # Get recent unscored CVEs sorted by date
        unscored_cves = self.mongo_client.get_unscored_cves(limit=limit)
        
        if verbose:
            print(f"Found {len(unscored_cves)} unscored CVEs")
            print(f"Scoring and storing to '{target_collection}' collection...\n")
        
        results = []
        for i, cve in enumerate(unscored_cves):
            cve_id = self._get_cve_id(cve)
            
            if verbose:
                print(f"  [{i+1}/{len(unscored_cves)}] Scoring {cve_id}...", end=" ", flush=True)
            
            result = self.score_single(cve, update_db=False)
            results.append(result)
            
            if result.success:
                # Build the document for the new collection
                scored_doc = {
                    "_id": cve_id,
                    "cve_id": cve_id,
                    "description": cve.get("description", ""),
                    "vendors": cve.get("vendors", []),
                    "weaknesses": cve.get("weaknesses", []),
                    "original_created_at": cve.get("created_at"),
                    "original_updated_at": cve.get("updated_at"),
                    # AI Scoring fields
                    "ai_cvss_score": result.final_score,
                    "ai_cvss_vector": result.final_vector,
                    "ai_severity": result.severity,
                    "ai_confidence": result.confidence,
                    "ai_gpt_score": result.gpt_score,
                    "ai_finetuned_score": result.finetuned_score,
                    "ai_method": result.method,
                    "ai_predicted": True,
                    "ai_scored_at": datetime.utcnow(),
                }
                
                # Insert into new collection
                self.mongo_client.insert_ai_scored_cve(scored_doc, target_collection)
                
                if verbose:
                    print(f"✓ {result.final_score} ({result.severity})")
            else:
                if verbose:
                    print(f"✗ Error: {result.error}")
        
        return results
    
    def print_summary(self, results: List[ScoringResult]):
        """Print scoring summary."""
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        print("\n" + "=" * 60)
        print("  CVE SCORING SUMMARY")
        print("=" * 60)
        print(f"  Total processed:    {len(results)}")
        print(f"  Successful:         {len(successful)}")
        print(f"  Failed:             {len(failed)}")
        
        if successful:
            avg_score = sum(r.final_score for r in successful) / len(successful)
            avg_confidence = sum(r.confidence for r in successful) / len(successful)
            
            severity_counts = {}
            for r in successful:
                severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
            
            print(f"\n  Average Score:      {avg_score:.1f}")
            print(f"  Average Confidence: {avg_confidence:.2f}")
            print(f"\n  Severity Distribution:")
            for severity, count in sorted(severity_counts.items()):
                print(f"    {severity}: {count}")
        
        if failed:
            print(f"\n  Failed CVEs:")
            for r in failed[:5]:
                print(f"    - {r.cve_id}: {r.error}")
        
        print("=" * 60)
    
    def close(self):
        """Close connections."""
        self.mongo_client.close()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="CVE CVSS Scorer using AI models")
    parser.add_argument("--limit", type=int, default=10, help="Number of CVEs to score")
    parser.add_argument("--days", type=int, default=7, help="Days to look back for recent CVEs")
    parser.add_argument("--recent", action="store_true", help="Score only recent CVEs")
    parser.add_argument("--cve-id", type=str, help="Score a specific CVE by ID")
    parser.add_argument("--dry-run", action="store_true", help="Don't update database")
    parser.add_argument("--stats", action="store_true", help="Show statistics only")
    parser.add_argument("--gpt-model", type=str, default="gpt-5.2-pro-2025-12-11", help="GPT model to use")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    
    args = parser.parse_args()
    
    scorer = CVEScorer(gpt_model=args.gpt_model)
    
    try:
        if args.stats:
            stats = scorer.get_stats()
            print(f"Unscored CVEs: {stats['total_unscored']}")
            print(f"AI-scored CVEs: {stats['total_ai_scored']}")
            return
        
        if args.cve_id:
            result = scorer.score_by_id(args.cve_id, update_db=not args.dry_run)
            if result:
                print(f"\n{result.cve_id}:")
                print(f"  Score: {result.final_score}")
                print(f"  Vector: {result.final_vector}")
                print(f"  Severity: {result.severity}")
                print(f"  Confidence: {result.confidence}")
                print(f"  GPT Score: {result.gpt_score}")
                print(f"  Fine-tuned Score: {result.finetuned_score}")
                print(f"  Method: {result.method}")
            else:
                print(f"CVE not found: {args.cve_id}")
            return
        
        if args.recent:
            results = scorer.score_recent(
                days=args.days,
                limit=args.limit,
                update_db=not args.dry_run,
                verbose=not args.quiet
            )
        else:
            results = scorer.score_unscored(
                limit=args.limit,
                update_db=not args.dry_run,
                verbose=not args.quiet
            )
        
        scorer.print_summary(results)
        
    finally:
        scorer.close()


if __name__ == "__main__":
    main()

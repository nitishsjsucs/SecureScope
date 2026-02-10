"""
Ensemble scorer combining GPT-5.2 Pro and fine-tuned model predictions.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from .gpt_scorer import GPTScorer, FineTunedScorer, CVSSPrediction, get_severity


@dataclass
class EnsembleResult:
    """Combined result from ensemble scoring."""
    final_score: float
    final_vector: str
    final_severity: str
    confidence: float
    gpt_prediction: CVSSPrediction
    finetuned_prediction: CVSSPrediction
    method: str
    reasoning: str


class EnsembleScorer:
    """Combines predictions from GPT-5.2 Pro and fine-tuned model."""
    
    def __init__(
        self,
        gpt_weight: float = 0.4,
        finetuned_weight: float = 0.6,
        gpt_model: str = "gpt-5.2-pro",
        finetuned_model: Optional[str] = None
    ):
        """
        Initialize ensemble scorer.
        
        Args:
            gpt_weight: Weight for GPT-5.2 Pro predictions (0-1)
            finetuned_weight: Weight for fine-tuned model predictions (0-1)
            gpt_model: GPT model to use
            finetuned_model: Fine-tuned model ID
        """
        self.gpt_weight = gpt_weight
        self.finetuned_weight = finetuned_weight
        
        self.gpt_scorer = GPTScorer(model=gpt_model)
        self.finetuned_scorer = FineTunedScorer(model=finetuned_model)
    
    def _weighted_average(
        self,
        gpt_score: float,
        gpt_confidence: float,
        ft_score: float,
        ft_confidence: float
    ) -> tuple[float, float]:
        """Calculate confidence-weighted average score."""
        # Adjust weights by confidence
        gpt_effective_weight = self.gpt_weight * gpt_confidence
        ft_effective_weight = self.finetuned_weight * ft_confidence
        
        total_weight = gpt_effective_weight + ft_effective_weight
        
        if total_weight == 0:
            return (gpt_score + ft_score) / 2, 0.5
        
        final_score = (
            (gpt_score * gpt_effective_weight) + 
            (ft_score * ft_effective_weight)
        ) / total_weight
        
        # Combined confidence
        final_confidence = min(1.0, (gpt_confidence + ft_confidence) / 2 * 1.1)
        
        return round(final_score, 1), round(final_confidence, 2)
    
    def _select_best_vector(
        self,
        gpt_vector: str,
        gpt_confidence: float,
        ft_vector: str,
        ft_confidence: float
    ) -> str:
        """Select the best vector string based on confidence and validity."""
        # Prefer fine-tuned model's vector (trained specifically for CVSS 4.0)
        if ft_vector and ft_vector.startswith("CVSS:4.0/"):
            return ft_vector
        elif gpt_vector and gpt_vector.startswith("CVSS:4.0/"):
            return gpt_vector
        elif ft_vector:
            return ft_vector
        return gpt_vector
    
    def _resolve_disagreement(
        self,
        gpt_pred: CVSSPrediction,
        ft_pred: CVSSPrediction
    ) -> tuple[float, str, str]:
        """
        Resolve significant disagreements between models.
        
        If scores differ by more than 2 points, apply additional logic.
        """
        score_diff = abs(gpt_pred.score - ft_pred.score)
        
        if score_diff <= 2.0:
            # Normal case: use weighted average
            final_score, confidence = self._weighted_average(
                gpt_pred.score, gpt_pred.confidence,
                ft_pred.score, ft_pred.confidence
            )
            method = "weighted_average"
        else:
            # Significant disagreement: favor fine-tuned model but reduce confidence
            # Fine-tuned model is trained specifically on CVSS 4.0 data
            final_score = ft_pred.score * 0.7 + gpt_pred.score * 0.3
            final_score = round(final_score, 1)
            confidence = 0.6  # Lower confidence due to disagreement
            method = "disagreement_resolution"
        
        reasoning = f"GPT: {gpt_pred.score} (conf: {gpt_pred.confidence}), " \
                   f"FT: {ft_pred.score} (conf: {ft_pred.confidence}), " \
                   f"Diff: {score_diff:.1f}, Method: {method}"
        
        return final_score, method, reasoning
    
    def score(self, cve: Dict[str, Any]) -> EnsembleResult:
        """
        Score a CVE using both models and combine results.
        
        Args:
            cve: CVE data dictionary
            
        Returns:
            EnsembleResult with combined prediction
        """
        # Get predictions from both models
        gpt_pred = self.gpt_scorer.score(cve)
        ft_pred = self.finetuned_scorer.score(cve)
        
        # Handle cases where one model failed
        if gpt_pred.score == 0 and gpt_pred.confidence == 0:
            # GPT failed, use fine-tuned only
            return EnsembleResult(
                final_score=ft_pred.score,
                final_vector=ft_pred.vector,
                final_severity=ft_pred.severity,
                confidence=ft_pred.confidence * 0.9,
                gpt_prediction=gpt_pred,
                finetuned_prediction=ft_pred,
                method="finetuned_only",
                reasoning="GPT scorer failed, using fine-tuned model only"
            )
        
        if ft_pred.score == 0 and ft_pred.confidence == 0:
            # Fine-tuned failed, use GPT only
            return EnsembleResult(
                final_score=gpt_pred.score,
                final_vector=gpt_pred.vector,
                final_severity=gpt_pred.severity,
                confidence=gpt_pred.confidence * 0.9,
                gpt_prediction=gpt_pred,
                finetuned_prediction=ft_pred,
                method="gpt_only",
                reasoning="Fine-tuned scorer failed, using GPT only"
            )
        
        # Resolve any disagreements and get final score
        final_score, method, reasoning = self._resolve_disagreement(gpt_pred, ft_pred)
        
        # Select best vector
        final_vector = self._select_best_vector(
            gpt_pred.vector, gpt_pred.confidence,
            ft_pred.vector, ft_pred.confidence
        )
        
        # Calculate combined confidence
        _, combined_confidence = self._weighted_average(
            gpt_pred.score, gpt_pred.confidence,
            ft_pred.score, ft_pred.confidence
        )
        
        return EnsembleResult(
            final_score=final_score,
            final_vector=final_vector,
            final_severity=get_severity(final_score),
            confidence=combined_confidence,
            gpt_prediction=gpt_pred,
            finetuned_prediction=ft_pred,
            method=method,
            reasoning=reasoning
        )
    
    def score_batch(self, cves: List[Dict[str, Any]]) -> List[EnsembleResult]:
        """Score multiple CVEs."""
        results = []
        for cve in cves:
            result = self.score(cve)
            results.append(result)
        return results


if __name__ == "__main__":
    # Test ensemble scorer
    test_cve = {
        "cve_id": "CVE-2024-TEST",
        "description": "SQL injection vulnerability in the login form allows attackers to bypass authentication."
    }
    
    print("Testing Ensemble Scorer...")
    try:
        scorer = EnsembleScorer()
        result = scorer.score(test_cve)
        
        print(f"\nFinal Score: {result.final_score}")
        print(f"Final Vector: {result.final_vector}")
        print(f"Final Severity: {result.final_severity}")
        print(f"Confidence: {result.confidence}")
        print(f"Method: {result.method}")
        print(f"\nGPT Prediction: {result.gpt_prediction.score}")
        print(f"Fine-tuned Prediction: {result.finetuned_prediction.score}")
        print(f"\nReasoning: {result.reasoning}")
    except Exception as e:
        print(f"Error: {e}")

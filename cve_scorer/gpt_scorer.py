"""
GPT-based CVSS scorers using GPT-5.2 Pro and fine-tuned models.
"""

import os
import json
import re
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


@dataclass
class CVSSPrediction:
    """CVSS prediction result."""
    score: float
    vector: str
    severity: str
    confidence: float
    reasoning: str
    model: str
    raw_response: str


def get_severity(score: float) -> str:
    """Get severity label from CVSS score."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "None"


class GPTScorer:
    """CVSS scorer using GPT-5.2 Pro model."""
    
    SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in CVSS (Common Vulnerability Scoring System) scoring.
    
Given a CVE description and any available context, you must predict the CVSS 4.0 score and vector string.

CVSS 4.0 Vector Format:
CVSS:4.0/AV:[N|A|L|P]/AC:[L|H]/AT:[N|P]/PR:[N|L|H]/UI:[N|P|A]/VC:[H|L|N]/VI:[H|L|N]/VA:[H|L|N]/SC:[H|L|N]/SI:[H|L|N]/SA:[H|L|N]

Where:
- AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
- AC (Attack Complexity): L=Low, H=High
- AT (Attack Requirements): N=None, P=Present
- PR (Privileges Required): N=None, L=Low, H=High
- UI (User Interaction): N=None, P=Passive, A=Active
- VC (Confidentiality Impact to Vulnerable System): H=High, L=Low, N=None
- VI (Integrity Impact to Vulnerable System): H=High, L=Low, N=None
- VA (Availability Impact to Vulnerable System): H=High, L=Low, N=None
- SC (Confidentiality Impact to Subsequent Systems): H=High, L=Low, N=None
- SI (Integrity Impact to Subsequent Systems): H=High, L=Low, N=None
- SA (Availability Impact to Subsequent Systems): H=High, L=Low, N=None

You MUST respond in this exact JSON format:
{
    "score": <float 0.0-10.0>,
    "vector": "<CVSS 4.0 vector string>",
    "severity": "<None|Low|Medium|High|Critical>",
    "confidence": <float 0.0-1.0>,
    "reasoning": "<brief explanation>"
}"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-5.2-pro-2025-12-11"):
        """Initialize GPT scorer."""
        if not HAS_OPENAI:
            raise ImportError("openai is required. Install with: pip install openai")
        
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required")
        
        self.client = OpenAI(api_key=self.api_key)
        self.model = model
    
    def _build_prompt(self, cve: Dict[str, Any]) -> str:
        """Build the scoring prompt from CVE data."""
        cve_id = cve.get("cve_id") or cve.get("id") or cve.get("_id") or "Unknown"
        
        # Extract description - handle both string and nested formats
        description = ""
        desc_field = cve.get("description") or cve.get("descriptions")
        if isinstance(desc_field, str):
            description = desc_field
        elif isinstance(desc_field, list):
            for desc in desc_field:
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
                elif isinstance(desc, str):
                    description = desc
                    break
        
        # Extract weaknesses - handle string or list format
        weaknesses_field = cve.get("weaknesses", [])
        cwe_ids = []
        if isinstance(weaknesses_field, str):
            # Parse string like "['CWE-79', 'CWE-89']"
            import re
            cwe_ids = re.findall(r'CWE-\d+', weaknesses_field)
        elif isinstance(weaknesses_field, list):
            for w in weaknesses_field:
                if isinstance(w, str) and w.startswith("CWE-"):
                    cwe_ids.append(w)
                elif isinstance(w, dict):
                    for desc in w.get("description", []):
                        if isinstance(desc, dict) and desc.get("value", "").startswith("CWE-"):
                            cwe_ids.append(desc["value"])
        
        # Extract vendors
        vendors_field = cve.get("vendors", [])
        vendors = []
        if isinstance(vendors_field, str):
            import re
            vendors = re.findall(r"'([^']+)'", vendors_field)[:3]
        elif isinstance(vendors_field, list):
            vendors = vendors_field[:3]
        
        prompt = f"""CVE ID: {cve_id}

Description:
{description}

"""
        if cwe_ids:
            prompt += f"CWE IDs: {', '.join(cwe_ids)}\n\n"
        
        if vendors:
            prompt += f"Affected Vendors: {', '.join(vendors)}\n\n"
        
        prompt += "Based on this information, predict the CVSS 4.0 score."
        
        return prompt
    
    def _parse_response(self, response: str, model: str) -> CVSSPrediction:
        """Parse the model response into a CVSSPrediction."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)
            
            score = float(data.get("score", 0))
            vector = data.get("vector", "")
            severity = data.get("severity", get_severity(score))
            confidence = float(data.get("confidence", 0.5))
            reasoning = data.get("reasoning", "")
            
            return CVSSPrediction(
                score=score,
                vector=vector,
                severity=severity,
                confidence=confidence,
                reasoning=reasoning,
                model=model,
                raw_response=response
            )
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Fallback: try to extract score from text
            score_match = re.search(r'(\d+\.?\d*)\s*/\s*10|score[:\s]+(\d+\.?\d*)', response.lower())
            if score_match:
                score = float(score_match.group(1) or score_match.group(2))
            else:
                score = 5.0  # Default medium score
            
            return CVSSPrediction(
                score=score,
                vector="",
                severity=get_severity(score),
                confidence=0.3,
                reasoning=f"Parsed from unstructured response: {str(e)}",
                model=model,
                raw_response=response
            )
    
    def score(self, cve: Dict[str, Any]) -> CVSSPrediction:
        """Score a CVE using GPT-5.2 Pro via Responses API."""
        prompt = self._build_prompt(cve)
        full_prompt = f"{self.SYSTEM_PROMPT}\n\n{prompt}"
        
        try:
            # GPT-5.2 Pro uses Responses API, not Chat Completions
            if "gpt-5" in self.model or "5.2" in self.model:
                response = self.client.responses.create(
                    model=self.model,
                    input=full_prompt,
                )
                content = response.output_text
            else:
                # Fallback to chat completions for other models
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=500,
                )
                content = response.choices[0].message.content
            
            return self._parse_response(content, self.model)
            
        except Exception as e:
            return CVSSPrediction(
                score=0,
                vector="",
                severity="Unknown",
                confidence=0,
                reasoning=f"Error: {str(e)}",
                model=self.model,
                raw_response=""
            )


class FineTunedScorer:
    """CVSS scorer using fine-tuned GPT-4o model for CVSS 4.0."""
    
    SYSTEM_PROMPT = """You are a CVSS 4.0 scoring model. Given a CVE description, output the CVSS 4.0 vector string and score.

Respond in JSON format:
{
    "score": <float>,
    "vector": "<CVSS 4.0 vector>",
    "severity": "<severity level>"
}"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        """Initialize fine-tuned scorer."""
        if not HAS_OPENAI:
            raise ImportError("openai is required. Install with: pip install openai")
        
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required")
        
        self.client = OpenAI(api_key=self.api_key)
        self.model = model or os.getenv("CVSS_FINETUNED_MODEL", "ft:gpt-4o-2024-08-06:aadish:cvss40-10k:D1qzO3gJ")
    
    def _build_prompt(self, cve: Dict[str, Any]) -> str:
        """Build prompt matching the fine-tuning format."""
        cve_id = cve.get("cve_id") or cve.get("id") or cve.get("_id") or "Unknown"
        
        # Extract description - handle both string and nested formats
        description = ""
        desc_field = cve.get("description") or cve.get("descriptions")
        if isinstance(desc_field, str):
            description = desc_field
        elif isinstance(desc_field, list):
            for desc in desc_field:
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
                elif isinstance(desc, str):
                    description = desc
                    break
        
        return f"CVE: {cve_id}\nDescription: {description}\n\nPredict the CVSS 4.0 score:"
    
    def _parse_response(self, response: str) -> CVSSPrediction:
        """Parse the fine-tuned model response."""
        try:
            # The fine-tuned model should output structured data
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)
            
            score = float(data.get("score", 0))
            vector = data.get("vector", "")
            severity = data.get("severity", get_severity(score))
            
            return CVSSPrediction(
                score=score,
                vector=vector,
                severity=severity,
                confidence=0.85,  # Fine-tuned model has higher confidence
                reasoning="Fine-tuned CVSS 4.0 prediction",
                model=self.model,
                raw_response=response
            )
        except (json.JSONDecodeError, ValueError) as e:
            # Try to extract vector string directly
            vector_match = re.search(r'CVSS:4\.0/[A-Z:/]+', response)
            score_match = re.search(r'(\d+\.?\d*)', response)
            
            vector = vector_match.group() if vector_match else ""
            score = float(score_match.group(1)) if score_match else 5.0
            
            return CVSSPrediction(
                score=score,
                vector=vector,
                severity=get_severity(score),
                confidence=0.5,
                reasoning=f"Extracted from response: {str(e)}",
                model=self.model,
                raw_response=response
            )
    
    def score(self, cve: Dict[str, Any]) -> CVSSPrediction:
        """Score a CVE using fine-tuned model."""
        prompt = self._build_prompt(cve)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0,  # Deterministic for fine-tuned model
                max_tokens=200,
            )
            
            content = response.choices[0].message.content
            return self._parse_response(content)
            
        except Exception as e:
            return CVSSPrediction(
                score=0,
                vector="",
                severity="Unknown",
                confidence=0,
                reasoning=f"Error: {str(e)}",
                model=self.model,
                raw_response=""
            )


if __name__ == "__main__":
    # Test the scorers
    test_cve = {
        "cve_id": "CVE-2024-TEST",
        "description": "A buffer overflow vulnerability in the authentication module allows remote attackers to execute arbitrary code via crafted input."
    }
    
    print("Testing GPT-5.2 Pro Scorer...")
    try:
        gpt_scorer = GPTScorer()
        result = gpt_scorer.score(test_cve)
        print(f"  Score: {result.score}")
        print(f"  Vector: {result.vector}")
        print(f"  Severity: {result.severity}")
        print(f"  Confidence: {result.confidence}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print("\nTesting Fine-tuned Scorer...")
    try:
        ft_scorer = FineTunedScorer()
        result = ft_scorer.score(test_cve)
        print(f"  Score: {result.score}")
        print(f"  Vector: {result.vector}")
        print(f"  Severity: {result.severity}")
        print(f"  Confidence: {result.confidence}")
    except Exception as e:
        print(f"  Error: {e}")

import json
import logging
import re
from typing import Dict, Any, Optional
from backend.core.finding import VerifiedVulnerability, StaticFinding, CodeContext

logger = logging.getLogger(__name__)

class LLMReasoner:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.model = "qwen2.5-coder:1.5b"
        
    def _build_prompt(self, finding: StaticFinding, context: CodeContext, kb_context: Optional[Dict[str, Any]]) -> str:
        kb_text = "No additional context available."
        if kb_context:
            if isinstance(kb_context, list) and len(kb_context) > 0:
                kb_context = kb_context[0] # Extract top match
            if isinstance(kb_context, dict):
                kb_text = f"Title: {kb_context.get('name', 'Unknown')}\nDescription: {kb_context.get('description', '')}\nMitigation: {kb_context.get('mitigation', '')}"
        return f"""You are an expert Solidity smart contract security auditor.
Analyze the following function for vulnerabilities based on the provided static analysis finding and security knowledge.

### STATIC ANALYSIS FINDING:
Vulnerability: {finding.category}
Lines: {finding.line_start} - {finding.line_end}
Evidence: {finding.message}

### FUNCTION CONTEXT (Code to analyze):
{context.function_source}

### RETRIEVED SECURITY KNOWLEDGE:
{kb_text}

### STRICT CODE-GROUNDING DIRECTIVE:
Every attack scenario MUST be grounded exclusively in the supplied FUNCTION CONTEXT.

Do not invent:
- functions
- contracts
- variables
- parameters
- state variables
- authorization mechanisms
- calls
- code paths

Before describing an attack, verify that every referenced function, variable, parameter, and call exists in the supplied source.
If the source does not provide enough information to establish a specific attack path, state that instead of inventing one.
If an attack path cannot be established directly from the supplied code, provide a cautious generic explanation rather than inventing code elements. When possible, construct the attack scenario using only functions, parameters, state variables, and control flow actually present in the supplied source.

### INSTRUCTIONS:
Return a valid JSON object ONLY.
Required JSON schema:
{{
  "is_vulnerable": true/false,
  "vulnerability": "<Name of Vulnerability>",
  "severity": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "confidence": <float>,
  "affected_lines": [<line_numbers>],
  "evidence": [
    {{
      "function": "<actual_function_name_from_context>",
      "lines": [<line_numbers>]
    }}
  ],
  "explanation": "<Detailed reason why it is or is not vulnerable>",
  "attack_scenario": "<Step-by-step exploit workflow strictly using the evidence>",
  "recommendation": "<Concrete mitigation steps>",
  "fixed_code": "<Corrected Solidity code snippet>"
}}
"""

    async def verify_finding(self, finding: StaticFinding, context: CodeContext, kb_context: Optional[Dict[str, Any]] = None) -> VerifiedVulnerability:
        prompt = self._build_prompt(finding, context, kb_context)
        
        # Rule-based fallback if Ollama is unavailable
        try:
            import httpx
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                response.raise_for_status()
                json_str = response.json()["response"]
                
                # Sanitize trailing commas
                json_str = re.sub(r',\s*\}', '}', json_str)
                json_str = re.sub(r',\s*\]', ']', json_str)
                
                data = json.loads(json_str)
                
                # Safely extract lines or fallback to finding
                affected_lines = data.get("affected_lines", [])
                if not affected_lines:
                    affected_lines = list(range(finding.line_start, finding.line_end + 1))
                    
                return VerifiedVulnerability(
                    finding_id=finding.id,
                    vulnerability=data.get("vulnerability", finding.category),
                    severity=data.get("severity", "Medium"),
                    confidence=data.get("confidence", 0.5),
                    affected_lines=affected_lines,
                    evidence=data.get("evidence", [{"function": context.function_name, "lines": affected_lines}]),
                    explanation=data.get("explanation", ""),
                    static_evidence=finding.message,
                    attack_scenario=data.get("attack_scenario", ""),
                    recommendation=data.get("recommendation", ""),
                    original_code=context.function_source,
                    fixed_code=data.get("fixed_code"),
                    fallback_used=False,
                    fallback_reason=None
                )
        except Exception as e:
            logger.warning(f"LLM verification failed ({str(e)}), falling back to rule-based expert system.")
            
            kb_dict = kb_context[0] if isinstance(kb_context, list) and len(kb_context) > 0 else (kb_context if isinstance(kb_context, dict) else {})
            
            # Rule-based Fallback
            return VerifiedVulnerability(
                finding_id=finding.id,
                is_vulnerable=True,
                vulnerability=finding.category,
                severity="High",
                confidence=1.0,
                affected_lines=list(range(finding.line_start, finding.line_end + 1)),
                evidence=[{"function": context.function_name, "lines": list(range(finding.line_start, finding.line_end + 1))}],
                explanation=kb_dict.get("description", "Vulnerability detected via static analysis.") if kb_dict else "Detected by rule engine.",
                static_evidence=finding.message,
                attack_scenario="Attacker exploits vulnerable pattern based on static evidence.",
                recommendation=kb_dict.get("mitigation", "Review contract logic.") if kb_dict else "Secure the contract.",
                original_code=context.function_source,
                fixed_code="// Fallback applied: ReentrancyGuard missing",
                fallback_used=True,
                fallback_reason=f"LLM verification failed: {str(e)}"
            )

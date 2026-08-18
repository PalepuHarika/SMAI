import os
import json
import httpx
import re
from typing import List, Dict, Any, Optional
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability

class LLMReasoner:
    """
    LLM reasoning engine that validates static analyzer findings against code context
    and retrieved security knowledge, returning structured, auditable vulnerability evaluations.
    """

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:latest"):
        self.ollama_url = os.getenv("OLLAMA_URL", ollama_url)
        self.model = os.getenv("LLM_MODEL", model)

    async def verify_finding(
        self,
        finding: StaticFinding,
        context: CodeContext,
        knowledge: List[Dict[str, Any]]
    ) -> VerifiedVulnerability:
        prompt = self._build_prompt(finding, context, knowledge)
        
        # Try local Ollama endpoint first
        llm_response = await self._call_ollama(prompt)
        
        if llm_response:
            parsed = self._parse_and_validate(llm_response, finding, context, knowledge)
            if parsed:
                return parsed

        # Robust Fallback Expert Rule Engine if Ollama is offline or returns invalid response
        return self._rule_based_fallback(finding, context, knowledge)

    def _build_prompt(self, finding: StaticFinding, context: CodeContext, knowledge: List[Dict[str, Any]]) -> str:
        kb_lines = [
            f"- [{k.get('id')}] {k.get('name')}: {k.get('description')} Mitigation: {k.get('mitigation')}"
            for k in knowledge
        ]
        kb_text = chr(10).join(kb_lines)
        mods = ', '.join(context.modifiers) if context.modifiers else 'None'
        svars = ', '.join(context.state_variables) if context.state_variables else 'None'
        ext_calls = ', '.join(context.external_calls) if context.external_calls else 'None'

        return f"""You are an expert Solidity smart contract security auditor.
Analyze the following static analysis finding, code context, and security reference material to determine if a real vulnerability exists.

### STATIC FINDING:
- Category: {finding.category}
- Detector Message: {finding.message}
- Lines: {finding.line_start} - {finding.line_end}
- Snippet: {finding.snippet}

### FUNCTION CONTEXT ({context.contract_name}.{context.function_name}):
- Modifiers: {mods}
- State Variables: {svars}
- External Calls: {ext_calls}



### RETRIEVED SECURITY KNOWLEDGE:
{kb_text}

### CRITICAL GROUNDING CONSTRAINTS:
1. Do NOT hallucinate generic textbook examples (e.g., do not use generic function names like "attack()" or "transferOwnership()" unless they actually appear in the snippet).
2. The "attack_scenario" MUST exclusively reference the exact function name, arguments, and state variables found in the provided FUNCTION CONTEXT.
3. Your explanation and exploit workflow must be strictly tied to the provided Solidity code logic.

### INSTRUCTIONS:
Return a valid JSON object ONLY.
Required JSON schema:
{{
  "is_vulnerable": true/false,
  "vulnerability": "<Name of Vulnerability>",
  "severity": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "confidence": <float between 0.0 and 1.0>,
  "affected_lines": [<line_numbers>],
  "explanation": "<Detailed reason why it is or is not vulnerable>",
  "attack_scenario": "<Step-by-step exploit workflow>",
  "recommendation": "<Concrete mitigation steps>",
  "fixed_code": "<Corrected Solidity code snippet>"
}}
"""

    async def _call_ollama(self, prompt: str) -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    return data.get("response")
        except Exception:
            return None
        return None

    def _parse_and_validate(
        self,
        raw_text: str,
        finding: StaticFinding,
        context: CodeContext,
        knowledge: List[Dict[str, Any]]
    ) -> Optional[VerifiedVulnerability]:
        try:
            json_str = raw_text.strip()
            match = re.search(r'\{.*\}', json_str, re.DOTALL)
            if match:
                json_str = match.group(0)

            # Sanitize trailing commas
            json_str = re.sub(r',\s*\}', '}', json_str)
            json_str = re.sub(r',\s*\]', ']', json_str)
            
            data = json.loads(json_str)

            valid_severities = ["Critical", "High", "Medium", "Low", "Informational"]
            sev = str(data.get("severity", "Medium")).capitalize()
            if sev not in valid_severities:
                sev = "Medium"

            conf = float(data.get("confidence", 0.8))
            conf = max(0.0, min(1.0, conf))

            affected_lines = data.get("affected_lines", [finding.line_start])
            if not isinstance(affected_lines, list):
                affected_lines = [finding.line_start]

            return VerifiedVulnerability(
                finding_id=finding.id,
                is_vulnerable=bool(data.get("is_vulnerable", True)),
                vulnerability=str(data.get("vulnerability", finding.category.replace('-', ' ').title())),
                severity=sev,
                confidence=conf,
                affected_lines=affected_lines,
                explanation=str(data.get("explanation", finding.message)),
                attack_scenario=str(data.get("attack_scenario", "An attacker can trigger this vulnerability to manipulate contract state or drain funds.")),
                recommendation=str(data.get("recommendation", "Implement standard security guards and follow CEI pattern.")),
                fixed_code=str(data.get("fixed_code", context.function_source)),
                static_evidence=finding.message,
                original_code=context.function_source,
                retrieved_knowledge=knowledge
            )
        except Exception:
            return None

    def _rule_based_fallback(
        self,
        finding: StaticFinding,
        context: CodeContext,
        knowledge: List[Dict[str, Any]]
    ) -> VerifiedVulnerability:
        primary_kb = knowledge[0] if knowledge else {}
        vuln_name = primary_kb.get("name", finding.category.replace('-', ' ').title())
        severity = primary_kb.get("severity", "High")
        explanation = f"{vuln_name} identified in function '{context.function_name}'. {finding.message}"
        attack_scenario = primary_kb.get("exploit_pattern", "Attacker exploits state sequence to execute malicious callbacks or unauthorized state transitions.")
        recommendation = primary_kb.get("mitigation", "Apply Checks-Effects-Interactions pattern and enforce access control.")
        
        fixed_code = primary_kb.get("example_fixed", context.function_source)

        return VerifiedVulnerability(
            finding_id=finding.id,
            is_vulnerable=True,
            vulnerability=vuln_name,
            severity=severity,
            confidence=finding.confidence,
            affected_lines=list(range(finding.line_start, finding.line_end + 1)),
            explanation=explanation,
            attack_scenario=attack_scenario,
            recommendation=recommendation,
            fixed_code=fixed_code,
            static_evidence=finding.message,
                original_code=context.function_source,
            retrieved_knowledge=knowledge
        )

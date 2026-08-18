import json
import logging
from typing import Optional, List, Dict, Any
from pydantic import ValidationError

import httpx
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability

logger = logging.getLogger(__name__)

class LLMReasoner:
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:latest", prompt_mode: str = "P1"):
        self.ollama_url = ollama_url
        self.model = model
        self.prompt_mode = prompt_mode
        self.client = httpx.AsyncClient(base_url=self.ollama_url, timeout=120.0)

    async def verify_finding(self, finding: StaticFinding, context: CodeContext, kb_context: Optional[str] = None) -> VerifiedVulnerability:
        schema = VerifiedVulnerability.model_json_schema()
        schema.pop("title", None)
        schema.pop("description", None)
        schema["properties"].pop("fallback_used", None)
        schema["properties"].pop("fallback_reason", None)
        schema["properties"].pop("static_confidence", None)
        if "fallback_used" in schema.get("required", []):
            schema["required"].remove("fallback_used")
        if "fallback_reason" in schema.get("required", []):
            schema["required"].remove("fallback_reason")
        if "static_confidence" in schema.get("required", []):
            schema["required"].remove("static_confidence")

        # P0: Minimal Baseline Prompt
        prompt_p0 = f"""You are a smart contract auditor.
Review the following vulnerability reported by a static analyzer.
Vulnerability: {finding.category}
Message: {finding.message}

Code Context:
{context.function_source}

RAG Context (if any):
{kb_context or 'None'}

Is this a real vulnerability? Return JSON matching the schema."""

        # P1: Current Source-Grounding Prompt
        prompt_p1 = f"""You are an expert Smart Contract Security Auditor.
You must verify if the following potential vulnerability reported by a static analyzer is a TRUE POSITIVE or FALSE POSITIVE.

Hypothesis (From Static Analyzer):
- Category: {finding.category}
- Message: {finding.message}
- Line: {finding.line_start}

Source Code Context:
```solidity
{context.function_source}
```

RAG Knowledge Base Context (if available):
{kb_context or 'No external context available.'}

VERIFICATION DIRECTIVES:
1. DO NOT TRUST THE STATIC ANALYZER. It often flags keywords without understanding semantics.
2. If `tx.origin` is used, WHERE is it used?
   - `tx.origin == admin` or `require(tx.origin == ...)` is SWC-115 (True Positive).
   - `tx.origin` used only for logging, event emission, informational purposes, or data recording is NOT SWC-115 by itself.

Think carefully about the code. If it is a False Positive, set `is_vulnerable` to false.
Return valid JSON matching the schema exactly. Do not output anything else.
"""
        
        system_prompt = prompt_p1 if self.prompt_mode == "P1" else prompt_p0

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a smart contract auditor that outputs strictly valid JSON matching the requested schema."},
                {"role": "user", "content": system_prompt}
            ],
            "format": schema,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "repeat_penalty": 1.1,
                "num_predict": 1024
            }
        }

        fallback_reason = ""
        try:
            response = await self.client.post("/api/chat", json=payload)
            response.raise_for_status()
            result_json = response.json()
            raw_content = result_json.get("message", {}).get("content", "")
            
            parsed_data = json.loads(raw_content)
            
            if "confidence" in parsed_data:
                conf = parsed_data["confidence"]
                if isinstance(conf, (int, float)):
                    if conf > 1.0:
                        parsed_data["confidence"] = conf / 100.0

            parsed_data["fallback_used"] = False
            parsed_data["finding_id"] = finding.id
            parsed_data["static_confidence"] = finding.confidence
            
            return VerifiedVulnerability(**parsed_data)
            
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            fallback_reason = f"API/Connection Error: {str(e)}"
            logger.error(f"LLM verification failed ({fallback_reason}), falling back to rule-based expert system.")
        except json.JSONDecodeError as e:
            fallback_reason = f"JSON Parsing Error: {str(e)}"
            logger.error(f"LLM verification failed ({fallback_reason}), falling back to rule-based expert system.")
        except ValidationError as e:
            fallback_reason = f"Pydantic Validation Error: {str(e)}"
            logger.error(f"LLM verification failed ({fallback_reason}), falling back to rule-based expert system.")
        except Exception as e:
            fallback_reason = f"Unexpected Error: {str(e)}"
            logger.error(f"LLM verification failed ({fallback_reason}), falling back to rule-based expert system.")

        return VerifiedVulnerability(
            finding_id=finding.id,
            is_vulnerable=True,
            vulnerability=finding.category,
            severity="High",
            confidence=finding.confidence,
            static_confidence=finding.confidence,
            affected_lines=[finding.line_start],
            evidence=[],
            explanation=f"Fallback triggered due to LLM failure. Static analyzer warning: {finding.message}",
            attack_scenario="Attacker exploits vulnerable pattern based on static evidence.",
            recommendation="Review the affected lines manually.",
            original_code=context.function_source,
            fixed_code="Manual review required.",
            fallback_used=True,
            fallback_reason=fallback_reason,
            raw_response=None
        )

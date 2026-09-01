import json
import logging
import re
from typing import Optional, List, Dict, Any
from pydantic import ValidationError

import httpx
from backend.core.finding import StaticFinding, CodeContext, VerifiedVulnerability

logger = logging.getLogger(__name__)

def _clean_json_str(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return content.strip()

def validate_solidity_syntax(code: str) -> bool:
    if not code or not code.strip() or code == "N/A":
        return False
    brace_balance = 0
    paren_balance = 0
    in_string = False
    quote_char = ''
    i = 0
    while i < len(code):
        ch = code[i]
        if not in_string and (ch == '"' or ch == "'"):
            in_string = True
            quote_char = ch
        elif in_string and ch == quote_char and (i == 0 or code[i-1] != '\\'):
            in_string = False
        elif not in_string:
            if ch == '{':
                brace_balance += 1
            elif ch == '}':
                brace_balance -= 1
            elif ch == '(':
                paren_balance += 1
            elif ch == ')':
                paren_balance -= 1
        i += 1
    return brace_balance == 0 and paren_balance == 0

def rescan_fix(fixed_code: str, category: str) -> bool:
    try:
        from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
        analyzer = SolidityStaticAnalyzer()
        findings = analyzer.analyze(fixed_code)
        return not any(f.category == category for f in findings)
    except Exception:
        return False

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
        for key in [
            "fallback_used", "fallback_reason", "static_confidence", "model_used",
            "raw_response", "contract", "function", "swc_id", "fix_verified", "verification_status"
        ]:
            schema["properties"].pop(key, None)
            if key in schema.get("required", []):
                schema["required"].remove(key)

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
        raw_content = ""
        max_attempts = 2

        for attempt in range(max_attempts):
            try:
                response = await self.client.post("/api/chat", json=payload)
                response.raise_for_status()
                result_json = response.json()
                raw_content = result_json.get("message", {}).get("content", "")
                cleaned = _clean_json_str(raw_content)
                parsed_data = json.loads(cleaned)
                
                if "confidence" in parsed_data:
                    conf = parsed_data["confidence"]
                    if isinstance(conf, (int, float)):
                        if conf > 1.0:
                            parsed_data["confidence"] = min(1.0, conf / 100.0)
                        elif conf < 0.0:
                            parsed_data["confidence"] = 0.0

                parsed_data["finding_id"] = finding.id
                parsed_data["fallback_used"] = False
                parsed_data["static_confidence"] = finding.confidence
                parsed_data["contract"] = finding.contract
                parsed_data["function"] = finding.function
                parsed_data["swc_id"] = finding.swc_id
                parsed_data["static_evidence"] = finding.snippet

                is_vuln = bool(parsed_data.get("is_vulnerable", False))
                parsed_data["verification_status"] = "CONFIRMED" if is_vuln else "REJECTED"

                fixed_sol = parsed_data.get("fixed_code", "")
                if fixed_sol and fixed_sol != "N/A" and validate_solidity_syntax(fixed_sol):
                    parsed_data["fix_verified"] = rescan_fix(fixed_sol, finding.category)
                else:
                    parsed_data["fix_verified"] = False

                return VerifiedVulnerability(**parsed_data)

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                fallback_reason = f"API/Connection Error: {str(e)}"
                logger.warning(f"LLM verification connection failed ({fallback_reason}).")
                break
            except (json.JSONDecodeError, ValidationError) as e:
                fallback_reason = f"JSON/Schema Validation Error: {str(e)}"
                logger.warning(f"Attempt {attempt + 1} validation failed ({fallback_reason}).")
                if attempt < max_attempts - 1:
                    payload["messages"].append({"role": "user", "content": f"Correction required: Your output was invalid ({str(e)}). Output strictly valid JSON matching the schema."})
            except Exception as e:
                fallback_reason = f"Unexpected Error: {str(e)}"
                logger.error(f"Unexpected error in LLM verification: {fallback_reason}")
                break

        # Controlled Fallback: Mark UNVERIFIED, do not falsely confirm vulnerabilities
        return VerifiedVulnerability(
            finding_id=finding.id,
            is_vulnerable=False,
            verification_status="UNVERIFIED",
            vulnerability=finding.category,
            severity=finding.severity or "Medium",
            confidence=0.5,
            static_confidence=finding.confidence,
            affected_lines=[finding.line_start],
            evidence=[],
            explanation=f"Static analyzer flagged this candidate, but AI verification was unavailable ({fallback_reason}). This finding remains unverified.",
            attack_scenario="AI verification was not completed; no attack scenario could be confirmed from source evidence.",
            recommendation="Review the affected lines manually.",
            original_code=context.function_source,
            fixed_code="",
            fallback_used=True,
            fallback_reason=fallback_reason,
            contract=finding.contract,
            function=finding.function,
            swc_id=finding.swc_id,
            fix_verified=False,
            static_evidence=finding.snippet,
            raw_response=raw_content if raw_content else None
        )

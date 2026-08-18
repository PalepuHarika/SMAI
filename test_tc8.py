import asyncio
import json
import httpx
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.core.finding import VerifiedVulnerability

async def main():
    analyzer = SolidityStaticAnalyzer()
    with open("contracts/test_suite/TC8_TxOriginFalsePositive.sol", "r") as f:
        code = f.read()
    
    findings = analyzer.analyze(code, "TC8_TxOriginFalsePositive.sol")
    finding = findings[0]
    
    prompt = f"""You are a strict Smart Contract Security Auditor.

### CONTEXT:
Vulnerability Type: {finding.category}
Static Analysis Message: {finding.message}
Knowledge Base:
No specific knowledge base entry.

### SOURCE CODE:
```solidity
{code}
```

### 1. VULNERABILITY MUST BE PROVEN FROM CODE
Do not classify a vulnerability merely because a suspicious API, keyword, opcode, or variable appears.
Identify the EXACT operation in the supplied source that creates the vulnerability.
For tx.origin:
- `tx.origin` used for authorization/authentication/access control can support SWC-115.
- `tx.origin` used only for logging, event emission, informational purposes, or data recording is NOT SWC-115 by itself.

### 2. STATIC EVIDENCE IS A HYPOTHESIS
Treat the static analyzer finding as a hypothesis to verify, not as proof.
You MUST be willing to return `"is_vulnerable": false` when the static analyzer is wrong.

### 3. NEGATIVE VERIFICATION
Before returning true, answer internally:
- What exact instruction/operation is vulnerable?
- What security property is violated?
- Where is authorization/access control actually performed?
- Does the supplied code contain that operation?
- Can the claimed attack path affect contract state, authorization, funds, or control flow using the supplied code?
If the answer to any of these is no, return false.

### 4. ATTACK SCENARIO MUST FOLLOW ACTUAL CONTROL FLOW
Never invent an authorization check.
If an exploit path cannot be established from this code, explain that an exploit path cannot be established from this code.

### 5. RETRIEVED KNOWLEDGE IS NOT CONTRACT EVIDENCE
The knowledge-base description may explain what vulnerabilities generally look like. It does NOT prove that the submitted contract implements that pattern.

### 6. REQUIRE EVIDENCE OF THE VULNERABLE OPERATION
For every finding, evidence must identify:
- function
- relevant source lines
- exact operation/expression
- why that operation satisfies the vulnerability condition
For example, for tx-origin:
GOOD: `require(tx.origin == owner)`
BAD: `emit UserAction(tx.origin)`

### INSTRUCTIONS:
Evaluate if this is a genuine vulnerability or a false positive based on the code.
Return a valid JSON object matching the requested schema. Ensure confidence is a number (it will be normalized to 0.0-1.0).
"""

    model = "qwen2.5-coder:1.5b"
    schema = VerifiedVulnerability.model_json_schema()
    for field in ["finding_id", "original_code", "static_evidence", "fallback_used", "fallback_reason", "model_used", "raw_response", "static_confidence"]:
        schema["properties"].pop(field, None)
        if field in schema.get("required", []):
            schema["required"].remove(field)
            
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": schema,
    }
    
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post("http://localhost:11434/api/generate", json=payload)
            data = resp.json()
            raw_response = data.get("response", "")
            
            print("HTTP STATUS:", resp.status_code)
            print("RAW RESPONSE:")
            print(raw_response)
            
            parsed = json.loads(raw_response)
            if "confidence" in parsed:
                try:
                    conf = float(parsed["confidence"])
                    if conf > 1.0:
                        parsed["confidence"] = conf / 100.0
                except ValueError:
                    parsed["confidence"] = 1.0
                    
            print("\nPARSED RESPONSE:")
            print(json.dumps(parsed, indent=2))
            
            verified = VerifiedVulnerability(
                finding_id=finding.id,
                original_code=code,
                static_evidence=finding.message,
                static_confidence=finding.confidence,
                **parsed
            )
            print("\nVALIDATED PYDANTIC OBJECT:")
            print(verified.model_dump_json(indent=2))
            
            print("\nKEY METRICS:")
            print(f"fallback_used: {verified.fallback_used}")
            print(f"is_vulnerable: {verified.is_vulnerable}")
            print(f"confidence: {verified.confidence}")
            print(f"evidence: {verified.evidence}")
            print(f"attack_scenario: {verified.attack_scenario}")
            
    except Exception as e:
        print(f"Failed - {e}")
        
if __name__ == "__main__":
    asyncio.run(main())

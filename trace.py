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

### STRICT CODE-GROUNDING DIRECTIVE:
Every attack scenario MUST be grounded in the supplied contract.
Do not invent:
- functions
- contracts
- variables
- parameters
- code paths

Before describing an attack, verify that every referenced function, variable, parameter, and call exists in the supplied source.
If the source does not provide enough information to establish a specific attack path, state that instead of inventing one.
If an attack path cannot be established directly from the supplied code, provide a cautious generic explanation rather than inventing code elements. When possible, construct the attack scenario using only functions, parameters, state variables, and control flow actually present in the supplied source.

### INSTRUCTIONS:
Evaluate if this is a genuine vulnerability or a false positive based on the code.
Return a valid JSON object matching the requested schema.
"""

    model = "qwen2.5-coder:latest"
    schema = VerifiedVulnerability.model_json_schema()
    for field in ["finding_id", "original_code", "static_evidence", "fallback_used", "fallback_reason", "model_used", "raw_response"]:
        schema["properties"].pop(field, None)
        if field in schema.get("required", []):
            schema["required"].remove(field)
            
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": schema,
        "options": {
            "temperature": 0.1
        }
    }
    
    print(f"ACTUAL MODEL:\nConfigured in reasoner: {model}\nSent in HTTP request: {payload['model']}\n")
    
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post("http://localhost:11434/api/generate", json=payload)
            print(f"HTTP STATUS:\n{resp.status_code}\n")
            
            data = resp.json()
            raw_response = data.get("response", "")
            print(f"RAW RESPONSE:\n{raw_response}\n")
            
            try:
                parsed = json.loads(raw_response)
                print(f"PARSED JSON:\n{json.dumps(parsed, indent=2)}\n")
            except Exception as e:
                print(f"PARSED JSON:\nFailed - {e}\n")
                parsed = None
                
            if parsed:
                try:
                    verified = VerifiedVulnerability(
                        finding_id=finding.id,
                        original_code=code,
                        static_evidence=finding.message,
                        **parsed
                    )
                    print(f"PYDANTIC RESULT:\nSuccess\n")
                    print("FALLBACK:\nFalse\n")
                except Exception as e:
                    print(f"PYDANTIC RESULT:\nFailed - {e}\n")
                    print("FALLBACK:\nTrue\n")
            else:
                print("PYDANTIC RESULT:\nSkipped due to JSON error\n")
                print("FALLBACK:\nTrue\n")
                
    except Exception as e:
        print(f"HTTP STATUS:\nFailed - {e}\n")
        
    print("ROOT CAUSE:\nPreviously, when `format=schema` was not used, the prompt generated markdown wrapped JSON like ```json ... ```, and our `reasoner.py` stripping logic `clean_json.split('```')[1]` incorrectly split on backticks *inside* the generated JSON payload (e.g. ```solidity inside the `recommendation` string), causing `json.loads` to crash because it was trying to parse the text *between* those backticks instead of the actual JSON object. Additionally, once `format=schema` was introduced, Ollama faithfully output `confidence` as a number (e.g. `1`), but our initial Pydantic schema required `le=1.0`. These two issues masked the fact that Qwen 2.5 Coder 7B *did* output `is_vulnerable`, but fundamentally failed to detect that the contract was a false positive, hallucinating an attack scenario instead.")
        
if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import json
import logging
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.llm.reasoner import LLMReasoner

logging.basicConfig(level=logging.INFO)

async def test_single(contract_name: str, expected_vuln: bool):
    print(f"\n==========================================")
    print(f"TESTING CONTRACT: {contract_name}")
    print(f"Expected is_vulnerable: {expected_vuln}")
    print(f"==========================================")
    
    analyzer = SolidityStaticAnalyzer()
    extractor = CodeContextExtractor()
    reasoner = LLMReasoner(model="qwen2.5-coder:1.5b")
    
    with open(f"contracts/test_suite/{contract_name}", "r") as f:
        code = f.read()
        
    findings = analyzer.analyze(code, contract_name)
    if not findings:
        print("FAIL: Static analyzer did not find any findings to verify.")
        return False
        
    finding = findings[0]
    context = extractor.extract(code, finding)
    
    print("Sending request to Ollama...")
    verified = await reasoner.verify_finding(finding, context, None)
    
    print("\nVERIFICATION RESULT:")
    print(f"is_vulnerable: {verified.is_vulnerable}")
    print(f"fallback_used: {verified.fallback_used}")
    print(f"fallback_reason: {verified.fallback_reason}")
    print(f"vulnerability: {verified.vulnerability}")
    print(f"severity: {verified.severity}")
    print(f"confidence: {verified.confidence}")
    print(f"explanation: {verified.explanation}")
    print(f"attack_scenario: {verified.attack_scenario}")
    
    # Assertions
    if verified.fallback_used:
        print("FAIL: Fallback was used!")
        return False
    if verified.is_vulnerable != expected_vuln:
        print(f"FAIL: is_vulnerable is {verified.is_vulnerable}, expected {expected_vuln}")
        return False
        
    print("SUCCESS: Test passed!")
    return True

async def main():
    # 1. Test TC8 (False Positive)
    success = await test_single("TC8_TxOriginFalsePositive.sol", False)
    if not success:
        return
        
    # 2. Test TC1 (True Positive)
    await test_single("TC1_TxOriginAuth.sol", True)

if __name__ == "__main__":
    asyncio.run(main())

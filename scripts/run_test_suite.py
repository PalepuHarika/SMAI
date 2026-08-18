import sys
import os
import json
import asyncio
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.pipeline import SecurityPipeline

TARGET_TESTS = [
    "TC1_TxOriginAuth.sol",
    "TC3_ReentrancyVault.sol",
    "TC4_DangerousDelegatecall.sol",
    "TC8_TxOriginFalsePositive.sol",
    "TC12_CleanContract.sol",
    "TC13_Decoy.sol",
    "TC14_MultiFunction.sol",
    "TC15_Hallucination.sol"
]

async def main():
    pipeline = SecurityPipeline()
    suite_dir = Path("contracts/test_suite")
    results = {}
    
    print("========================================")
    print("🚀 SMART CONTRACT SCANNER LLM BASELINE")
    print("========================================")

    for contract_file in sorted(suite_dir.glob("*.sol")):
        if contract_file.name not in TARGET_TESTS:
            continue
            
        print(f"[*] Scanning {contract_file.name}...")
        with open(contract_file, "r") as f:
            source = f.read()
        
        try:
            report = await pipeline.scan(source, contract_file.name)
            results[contract_file.name] = {
                "is_vulnerable": report.is_vulnerable,
                "total_findings": report.total_findings,
                "findings": [f.model_dump() for f in report.findings]
            }
        except Exception as e:
            print(f"[!] Error scanning {contract_file.name}: {e}")
            results[contract_file.name] = {"error": str(e)}
            
        # Add a 5 second throttle so Ollama doesn't OOM
        print(f"    Throttling Ollama for 5 seconds...")
        await asyncio.sleep(5)
            
    report_file = "test_suite_results.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print("========================================")
    
    print("\n--- LLM BASELINE SUMMARY ---")
    print(f"{'Test Contract':<30} | {'Findings':<10} | {'Max Severity':<15} | {'Fallback?':<15}")
    print("-" * 80)
    for name in TARGET_TESTS:
        data = results.get(name, {})
        if not data:
            continue
            
        if "error" in data:
            print(f"{name:<30} | {'ERROR':<10} | {'N/A':<15} | {'N/A':<15}")
            continue
            
        findings = data.get("findings", [])
        num_findings = len(findings)
        
        severities = [f.get("severity", "Low") for f in findings]
        max_sev = "Safe"
        if "Critical" in severities: max_sev = "Critical"
        elif "High" in severities: max_sev = "High"
        elif "Medium" in severities: max_sev = "Medium"
        elif "Low" in severities: max_sev = "Low"
        elif "Informational" in severities: max_sev = "Informational"
        
        # Check if ANY finding used the fallback
        fallback_used = any(f.get("fallback_used", False) for f in findings)
        fb_status = "⚠️ YES (FAIL)" if fallback_used else "✅ LLM PASS"
        if num_findings == 0:
            fb_status = "-"
            
        print(f"{name:<30} | {num_findings:<10} | {max_sev:<15} | {fb_status:<15}")

if __name__ == "__main__":
    asyncio.run(main())

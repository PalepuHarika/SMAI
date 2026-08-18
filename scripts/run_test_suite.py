import sys
import os
import json
import asyncio
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.pipeline import SecurityPipeline

async def main():
    pipeline = SecurityPipeline()
    suite_dir = Path("contracts/test_suite")
    results = {}
    
    print("========================================")
    print("🚀 SMART CONTRACT SCANNER TEST SUITE")
    print("========================================")
    
    if not suite_dir.exists():
        print(f"Directory {suite_dir} not found.")
        return

    for contract_file in sorted(suite_dir.glob("*.sol")):
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
            
    # Write output report
    report_file = "test_suite_results.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print("========================================")
    print(f"✅ Test suite complete. Output saved to {report_file}")
    
    # Analyze and print matrix
    print("\n--- TEST MATRIX SUMMARY ---")
    print(f"{'Test Contract':<30} | {'Findings':<10} | {'Max Severity':<15}")
    print("-" * 60)
    for name, data in results.items():
        if "error" in data:
            print(f"{name:<30} | {'ERROR':<10} | {'N/A':<15}")
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
            
        print(f"{name:<30} | {num_findings:<10} | {max_sev:<15}")

if __name__ == "__main__":
    asyncio.run(main())

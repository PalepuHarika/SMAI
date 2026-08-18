import sys
import os
import json
import asyncio
from pathlib import Path
from backend.pipeline import SecurityPipeline

# Ground truth mapping for the 8-contract baseline
GROUND_TRUTH = {
    "TC1_TxOriginAuth.sol": True,
    "TC3_ReentrancyVault.sol": True,
    "TC4_DangerousDelegatecall.sol": True,
    "TC13_Decoy.sol": False, # String decoy
    "TC8_TxOriginFalsePositive.sol": False, # Event log only
    "TC14_MultiFunction.sol": True,
    "TC15_Hallucination.sol": True,
    "TC12_CleanContract.sol": False # Analyzer finds 0, so LLM not called
}

async def run_suite(pipeline, mode):
    print(f"\n--- Running Suite in Mode {mode} ---")
    test_dir = Path("contracts/test_suite")
    # Order sequentially
    targets = [
        "TC8_TxOriginFalsePositive.sol",
        "TC13_Decoy.sol",
        "TC1_TxOriginAuth.sol",
        "TC3_ReentrancyVault.sol",
        "TC4_DangerousDelegatecall.sol",
        "TC14_MultiFunction.sol",
        "TC15_Hallucination.sol",
        "TC12_CleanContract.sol"
    ]
    
    results = {}
    for filename in targets:
        filepath = test_dir / filename
        if not filepath.exists():
            continue
            
        print(f"[*] Scanning {filename} (Mode {mode})...")
        with open(filepath, "r") as f:
            code = f.read()
            
        try:
            report = await pipeline.scan(code, filename, mode=mode)
            findings_data = []
            for finding in report.findings:
                findings_data.append({
                    "vulnerability": finding.vulnerability,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "static_confidence": finding.static_confidence,
                    "is_vulnerable": finding.is_vulnerable,
                    "fallback_used": getattr(finding, "fallback_used", False),
                    "fallback_reason": getattr(finding, "fallback_reason", None),
                    "model_used": getattr(finding, "model_used", None),
                    "raw_response": getattr(finding, "raw_response", None),
                    "evidence": getattr(finding, "evidence", []),
                    "attack_scenario": getattr(finding, "attack_scenario", "N/A"),
                })
            results[filename] = {
                "total_findings": report.total_findings,
                "is_vulnerable": report.is_vulnerable,
                "findings": findings_data
            }
        except Exception as e:
            print(f"Error on {filename}: {e}")
            results[filename] = {"error": str(e)}
            
        # Throttle between LLM calls to prevent OOM / overheating
        if mode in ["B", "C"]:
            await asyncio.sleep(5)
            
    return results

def generate_markdown(results_dict):
    md = "# Smart Contract Scanner Evaluation Report\n\n"
    md += "This report compares three modes of operation across the 8-contract baseline test suite.\n\n"
    
    modes = ["A", "B", "C"]
    mode_names = {"A": "Static Only", "B": "Static + LLM", "C": "Static + RAG + LLM"}
    
    md += "## Summary of Modes\n\n"
    md += "| Contract | Expected | Mode A (Static) | Mode B (LLM) | Mode C (RAG+LLM) |\n"
    md += "|---|---|---|---|---|\n"
    
    for test, expected in GROUND_TRUTH.items():
        row = [f"`{test}`", "🚨 Vuln" if expected else "✅ Safe"]
        for m in modes:
            r = results_dict[m].get(test, {})
            if "error" in r:
                row.append("⚠️ Error")
            elif r.get("total_findings", 0) > 0:
                row.append("🚨 Vuln")
            else:
                row.append("✅ Safe")
        md += "| " + " | ".join(row) + " |\n"
        
    for m in modes:
        md += f"\n## Mode {m}: {mode_names[m]}\n\n"
        res = results_dict[m]
        
        fp_total, fp_rejected = 0, 0
        fn = 0
        correct = 0
        
        for test, expected in GROUND_TRUTH.items():
            if test not in res: continue
            
            r = res[test]
            is_vuln = r.get("total_findings", 0) > 0
            
            if is_vuln == expected: correct += 1
            if not expected:
                fp_total += 1
                if not is_vuln: fp_rejected += 1
            if expected and not is_vuln:
                fn += 1
                
        md += f"**Correctness:** {correct}/8\n"
        md += f"**False Positive Rejection:** {fp_rejected}/{fp_total}\n"
        md += f"**False Negatives (Missed Vulns):** {fn}/5\n\n"
        
        # Details
        for test, r in res.items():
            if r.get("total_findings", 0) == 0: continue
            md += f"### {test}\n"
            for i, f in enumerate(r["findings"]):
                md += f"**Finding {i+1}**\n"
                md += f"- **Model:** {f.get('model_used')}\n"
                md += f"- **Fallback:** {f.get('fallback_used')} ({f.get('fallback_reason')})\n"
                md += f"- **Confidence:** LLM={f.get('confidence')} | Static={f.get('static_confidence')}\n"
                md += f"- **Scenario:** {f.get('attack_scenario')}\n"
                md += f"- **Raw Response:**\n```json\n{f.get('raw_response', '')}\n```\n\n"
                
    with open("/home/penjarla-revanth/.gemini/antigravity/brain/77bacd9e-2d2b-46e0-be80-1c8e77cd429d/evaluation_report.md", "w") as f:
        f.write(md)
    print("Generated evaluation_report.md")

async def main():
    pipeline = SecurityPipeline()
    results = {}
    
    # Run Modes
    for mode in ["A", "B", "C"]:
        res = await run_suite(pipeline, mode)
        results[mode] = res
        
    generate_markdown(results)

if __name__ == "__main__":
    asyncio.run(main())

import json
import os
import time
import asyncio
import subprocess
import httpx
from pathlib import Path
from backend.pipeline import SecurityPipeline
from backend.llm.reasoner import LLMReasoner

def wait_for_ollama():
    for _ in range(30):
        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            if r.status_code == 200:
                time.sleep(2)
                return True
        except:
            time.sleep(1)
    return False

async def run_experiment():
    with open("ground_truth.json", "r") as f:
        ground_truth = json.load(f)

    test_dir = Path("contracts/test_suite")
    contracts = sorted(ground_truth.keys())
    
    eval_results = []
    
<<<<<<< HEAD
    model = "qwen2.5-coder:latest"
=======
    models = ["qwen2.5-coder:1.5b", "qwen2.5-coder:latest"]
>>>>>>> 1b46d91 (feat: add scientific evaluation and accuracy dashboard)
    mode = "C"
    prompt = "P0"
    
    for model in models:
        print(f"\n=== Running MODE {mode} with {model} ({prompt}) ===")
        reasoner = LLMReasoner(model=model, prompt_mode=prompt)
        pipeline = SecurityPipeline(reasoner=reasoner)
        
        for contract in contracts:
            subprocess.run(["docker", "start", "scanner_ollama"], capture_output=True)
            wait_for_ollama()
            
            code = (test_dir / contract).read_text()
            t0 = time.time()
            try:
                report = await pipeline.scan(code, contract, mode=mode)
                t1 = time.time()
                
                if len(report.findings) > 0 and report.findings[0].fallback_used:
                    reason = getattr(report.findings[0], "fallback_reason", "")
                    if reason and ("Server disconnected" in reason or "connection attempts failed" in reason or "500" in reason):
                        print(f"Container crashed during {contract}. Restarting...")
                        subprocess.run(["docker", "restart", "scanner_ollama"], capture_output=True)
                        wait_for_ollama()

                for finding in report.findings:
                    eval_results.append({
                        "dataset": "Internal Diagnostic Suite",
                        "contract": contract, "mode": mode, "model": model, "prompt": prompt, "inference_time": t1 - t0,
                        "is_vulnerable": finding.is_vulnerable, "vulnerability": finding.vulnerability,
                        "severity": finding.severity, "confidence": finding.confidence,
                        "fallback_used": finding.fallback_used, "fallback_reason": getattr(finding, "fallback_reason", None),
                        "raw_response": getattr(finding, "raw_response", None),
                        "attack_scenario": getattr(finding, "attack_scenario", None),
                        "evidence": getattr(finding, "evidence", [])
                    })
                if report.total_findings == 0:
                    eval_results.append({
                        "dataset": "Internal Diagnostic Suite",
                        "contract": contract, "mode": mode, "model": model, "prompt": prompt, "inference_time": t1 - t0,
                        "is_vulnerable": False, "fallback_used": False, "raw_response": None
                    })
            except Exception as e:
                print(f"Pipeline crashed for {contract}: {e}")
                eval_results.append({
                    "dataset": "Internal Diagnostic Suite",
                    "contract": contract, "mode": mode, "model": model, "prompt": prompt, "inference_time": time.time() - t0,
                    "is_vulnerable": None, "fallback_used": True, "fallback_reason": f"Pipeline crash: {str(e)}"
                })
                
    with open("results/raw_p0_results.json", "w") as f:
        json.dump(eval_results, f, indent=2)
    print("Saved results/raw_p0_results.json")

if __name__ == "__main__":
    asyncio.run(run_experiment())

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
    print("Waiting for Ollama to boot...")
    for _ in range(30):
        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            if r.status_code == 200:
                print("Ollama is up!")
                time.sleep(2) # Give llama-server an extra second to bind
                return True
        except:
            time.sleep(1)
    print("Ollama failed to boot.")
    return False

async def run_experiment():
    with open("ground_truth.json", "r") as f:
        ground_truth = json.load(f)

    test_dir = Path("contracts/test_suite")
    contracts = sorted(ground_truth.keys())
    
    os.makedirs("results/baseline", exist_ok=True)
    os.makedirs("results/model_comparison", exist_ok=True)
    os.makedirs("results/rag_ablation", exist_ok=True)
    
    eval_results = []
    
    # 1. Mode A (Static)
    print("\n=== Running MODE A (Static Only) ===")
    pipeline_a = SecurityPipeline()
    for contract in contracts:
        code = (test_dir / contract).read_text()
        t0 = time.time()
        try:
            report = await pipeline_a.scan(code, contract, mode="A")
            t1 = time.time()
            for finding in report.findings:
                eval_results.append({
                    "contract": contract, "mode": "A", "model": "static", "inference_time": t1 - t0,
                    "is_vulnerable": finding.is_vulnerable, "vulnerability": finding.vulnerability,
                    "severity": finding.severity, "confidence": finding.confidence,
                    "fallback_used": finding.fallback_used, "fallback_reason": getattr(finding, "fallback_reason", None),
                    "raw_response": None, "attack_scenario": getattr(finding, "attack_scenario", None),
                    "evidence": getattr(finding, "evidence", [])
                })
            if report.total_findings == 0:
                eval_results.append({
                    "contract": contract, "mode": "A", "model": "static", "inference_time": t1 - t0,
                    "is_vulnerable": False, "fallback_used": False, "raw_response": None
                })
        except Exception as e:
            pass

    # 2. Mode B and C for Models
    models = ["qwen2.5-coder:latest"]
    modes = ["B", "C"]
    
    for model in models:
        for mode in modes:
            print(f"\n=== Running MODE {mode} with {model} ===")
            reasoner = LLMReasoner(model=model)
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
                            "contract": contract, "mode": mode, "model": model, "inference_time": t1 - t0,
                            "is_vulnerable": finding.is_vulnerable, "vulnerability": finding.vulnerability,
                            "severity": finding.severity, "confidence": finding.confidence,
                            "fallback_used": finding.fallback_used, "fallback_reason": getattr(finding, "fallback_reason", None),
                            "raw_response": getattr(finding, "raw_response", None),
                            "attack_scenario": getattr(finding, "attack_scenario", None),
                            "evidence": getattr(finding, "evidence", [])
                        })
                    if report.total_findings == 0:
                        eval_results.append({
                            "contract": contract, "mode": mode, "model": model, "inference_time": t1 - t0,
                            "is_vulnerable": False, "fallback_used": False, "raw_response": None
                        })
                except Exception as e:
                    print(f"Pipeline crashed for {contract}: {e}")
                    eval_results.append({
                        "contract": contract, "mode": mode, "model": model, "inference_time": time.time() - t0,
                        "is_vulnerable": None, "fallback_used": True, "fallback_reason": f"Pipeline crash: {str(e)}"
                    })
                    
    with open("results/raw_evaluation_results.json", "w") as f:
        json.dump(eval_results, f, indent=2)
    print("Saved results/raw_evaluation_results.json")

if __name__ == "__main__":
    asyncio.run(run_experiment())

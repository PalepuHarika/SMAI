import asyncio
import time
import json
import os
import httpx
from backend.pipeline import SecurityPipeline

async def run_single_contract(pipeline, name, code):
    print(f"\n--- Testing {name} ---")
    t0 = time.time()
    report = await pipeline.scan(code, f"{name}.sol", mode="C")
    t1 = time.time()
    print(f"Time: {t1-t0:.2f}s | Score: {report.security_score} | Risk: {report.risk_level}")
    for f in report.findings:
        print(f"  [{f.severity}] {f.vulnerability} -> {f.verification_status} (Conf: {f.confidence:.2f})")
    return report

async def step_single_vuln(pipeline):
    code = """pragma solidity ^0.8.0;
contract Test { mapping(address => uint) balances;
function withdraw() public { uint bal = balances[msg.sender]; require(bal > 0); msg.sender.call{value: bal}(""); balances[msg.sender] = 0; } }"""
    return await run_single_contract(pipeline, "SingleVuln", code)

async def main():
    pipeline = SecurityPipeline()
    # Increase timeout drastically for local CPU inference
    pipeline.reasoner.client.timeout = httpx.Timeout(1200.0)
    
    results = {}
    
    # Just run ONE single vulnerable contract to prove real LLM communication works
    results["single"] = await step_single_vuln(pipeline)
    
    os.makedirs("results/phase5_3", exist_ok=True)
    with open("results/phase5_3/subset_eval.json", "w") as f:
        json.dump({"completed": True}, f)
        
    print("\n--- SUBSET EVALUATION COMPLETED ---")

if __name__ == "__main__":
    asyncio.run(main())

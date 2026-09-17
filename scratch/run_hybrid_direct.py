import asyncio
import time
from backend.pipeline import SecurityPipeline

async def test_hybrid_direct():
    with open("contracts/ReentrancyVault.sol", "r") as f:
        source_code = f.read()

    pipeline = SecurityPipeline()
    start_time = time.time()
    report = await pipeline.scan(source_code, "ReentrancyVault.sol", mode="hybrid")
    elapsed = time.time() - start_time

    print(f"Status: COMPLETED ({elapsed:.1f}s)")
    print(f"Total Findings: {report.total_findings}")
    print(f"Security Score: {report.security_score}")
    print(f"Risk Level: {report.risk_level}")

    for f in report.findings:
        print(f"  [{f.vulnerability}] SWC={f.swc_id} | Sev={f.severity} | Vuln={f.is_vulnerable} | Status={f.verification_status} | Conf={round(f.confidence,3)} | Fallback={f.fallback_used} | RAG_items={len(f.retrieved_knowledge or [])}")

if __name__ == "__main__":
    asyncio.run(test_hybrid_direct())

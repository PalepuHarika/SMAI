import asyncio
import time
import json
from backend.pipeline import SecurityPipeline

async def test_all_modes_direct():
    with open("contracts/ReentrancyVault.sol", "r") as f:
        source_code = f.read()

    modes = [
        ("RAG ONLY", "rag"),
        ("AI ONLY", "ai"),
        ("RAG + AI (HYBRID)", "hybrid")
    ]

    for label, mode_val in modes:
        print(f"\n==========================================")
        print(f" TESTING MODE: {label} (mode='{mode_val}')")
        print(f"==========================================")

        pipeline = SecurityPipeline()
        start_time = time.time()
        
        try:
            report = await pipeline.scan(source_code, "ReentrancyVault.sol", mode=mode_val)
            elapsed = time.time() - start_time

            print(f"Status: SUCCESS (Completed in {elapsed:.1f}s)")
            print(f"Security Score: {report.security_score}")
            print(f"Risk Level: {report.risk_level}")
            print(f"Total Findings: {report.total_findings}")

            for idx, f in enumerate(report.findings):
                print(f"\n  --- Finding {idx+1} ---")
                print(f"  Category: {f.vulnerability} (SWC: {f.swc_id})")
                print(f"  Severity: {f.severity}")
                print(f"  Verification Status: {f.verification_status}")
                print(f"  Is Vulnerable: {f.is_vulnerable}")
                print(f"  Model Used: {f.model_used}")
                print(f"  Confidence: {f.confidence}")
                print(f"  Fallback Used: {f.fallback_used}")

                rag_items = f.retrieved_knowledge or []
                print(f"  RAG Used / Items Count: {len(rag_items) > 0} ({len(rag_items)} items)")
                if rag_items:
                    print(f"  RAG Top Context: {rag_items[0].get('id', 'N/A')} - {rag_items[0].get('vulnerability', '')}")
                
                print(f"  Explanation Snippet: {f.explanation[:100]}...")

        except Exception as e:
            print(f"ERROR running mode '{mode_val}': {repr(e)}")

if __name__ == "__main__":
    asyncio.run(test_all_modes_direct())

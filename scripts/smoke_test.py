import asyncio
import time
import json
from backend.pipeline import SecurityPipeline

async def main():
    pipeline = SecurityPipeline()
    print("OLLAMA_URL:", pipeline.reasoner.ollama_url)
    code = """
pragma solidity ^0.8.0;
contract Test {
    mapping(address => uint) balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        msg.sender.call{value: bal}("");
        balances[msg.sender] = 0;
    }
}
"""
    t0 = time.time()
    report = await pipeline.scan(code, "Test.sol")
    t1 = time.time()
    print(f"Scan complete in {t1 - t0:.2f}s")
    print("Findings:")
    for f in report.findings:
        print(f"  - {f.vulnerability} | {f.verification_status} | Conf: {f.confidence:.2f}")

if __name__ == "__main__":
    asyncio.run(main())

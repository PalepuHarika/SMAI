import time
import asyncio
from backend.pipeline import SecurityPipeline

src = """
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    function exploit() public {
        (bool s, ) = msg.sender.call("");
        require(tx.origin == owner);
    }
}
"""

async def run_benchmark():
    pipeline = SecurityPipeline()
    
    # Mock LLM to simulate exactly 1 second delay
    async def mock_verify(finding, context, knowledge):
        await asyncio.sleep(1.0)
        from backend.core.finding import VerifiedVulnerability
        return VerifiedVulnerability(
            finding_id=finding.id,
            is_vulnerable=True,
            verification_status="CONFIRMED",
            vulnerability=finding.category,
            severity=finding.severity or "High",
            confidence=0.9,
            affected_lines=[1],
            evidence=[],
            explanation="Test", attack_scenario="", recommendation="", original_code="", fixed_code="",
            fallback_used=False, contract=finding.contract, function=finding.function, swc_id=finding.swc_id
        )
    
    pipeline.reasoner.verify_finding = mock_verify

    start = time.time()
    report = await pipeline.scan(src, "Vault.sol", mode="C")
    end = time.time()
    
    print(f"Total findings verified: {report.total_findings}")
    print(f"Time taken: {end - start:.2f}s")
    
if __name__ == "__main__":
    asyncio.run(run_benchmark())

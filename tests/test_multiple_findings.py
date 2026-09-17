import pytest
import asyncio
from backend.pipeline import SecurityPipeline

@pytest.mark.asyncio
async def test_multiple_findings_isolation():
    pipeline = SecurityPipeline()
    src = """
    pragma solidity ^0.8.0;
    contract MultiBug {
        address public owner;
        function exploit() public {
            (bool s, ) = msg.sender.call("");
            require(tx.origin == owner);
        }
    }
    """
    report = await pipeline.scan(src, "MultiBug.sol", mode="A")
    
    assert report.total_findings >= 3
    found_vulns = [f.vulnerability for f in report.findings]
    
    assert any("unchecked-call" in v for v in found_vulns)
    assert any("tx-origin" in v for v in found_vulns)
    assert any("floating-pragma" in v for v in found_vulns)

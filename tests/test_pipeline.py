import pytest
import asyncio
from backend.pipeline import SecurityPipeline

@pytest.mark.asyncio
async def test_end_to_end_pipeline():
    pipeline = SecurityPipeline()
    with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/ReentrancyVault.sol') as f:
        src = f.read()
    
    report = await pipeline.scan(src, 'ReentrancyVault.sol')
    assert report.is_vulnerable is True
    assert report.total_findings >= 1
    assert any(f.vulnerability == 'Reentrancy' for f in report.findings)
    assert report.severity_counts['High'] >= 1

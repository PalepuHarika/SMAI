import pytest
import asyncio
from pathlib import Path
from backend.pipeline import SecurityPipeline

@pytest.mark.asyncio
async def test_end_to_end_pipeline():
    pipeline = SecurityPipeline()
    contract_path = Path(__file__).parent.parent / "contracts" / "ReentrancyVault.sol"
    with open(contract_path) as f:
        src = f.read()
    
    # Test Mode A (Static-only pipeline)
    report_a = await pipeline.scan(src, 'ReentrancyVault.sol', mode="A")
    assert report_a.is_vulnerable is True
    assert report_a.total_findings >= 1
    assert any("reentrancy" in f.vulnerability.lower() for f in report_a.findings)
    assert report_a.severity_counts['High'] >= 1
    assert report_a.security_score is not None
    assert 0 <= report_a.security_score <= 100
    assert report_a.risk_level in ["Low Risk", "Moderate Risk", "High Risk", "Critical Risk"]
    assert report_a.findings[0].verification_status == "CONFIRMED"
    assert report_a.findings[0].function == "withdraw"

@pytest.mark.asyncio
async def test_pipeline_llm_fallback_unverified():
    # Test Mode C when Ollama is simulated unavailable/dummy
    pipeline = SecurityPipeline()
    contract_path = Path(__file__).parent.parent / "contracts" / "ReentrancyVault.sol"
    with open(contract_path) as f:
        src = f.read()

    report_c = await pipeline.scan(src, 'ReentrancyVault.sol', mode="C")
    assert report_c.security_score is not None
    assert len(report_c.findings) >= 1
    # When Ollama is offline, finding must be marked UNVERIFIED (never falsely confirmed)
    for f in report_c.findings:
        if f.fallback_used:
            assert f.verification_status == "UNVERIFIED"
            assert f.is_vulnerable is False

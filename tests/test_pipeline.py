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
            # Confidence must be calibrated, never 1.0
            assert 0.0 < f.confidence < 1.0

def test_fix_verification_logic():
    """
    Regression test: Fix verification must validate syntax and rescan with static analyzer.
    """
    from backend.llm.reasoner import validate_solidity_syntax, rescan_fix

    # 1. Syntax validator
    assert validate_solidity_syntax("contract Safe { function test() public {} }") is True
    assert validate_solidity_syntax("contract Broken { function test() public {") is False
    assert validate_solidity_syntax("") is False

    # 2. Rescan fix eliminates vulnerability
    safe_fix = """
    pragma solidity ^0.8.0;
    contract ReentrancyVaultFixed {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount, "Insufficient");
            balances[msg.sender] -= amount; // state updated BEFORE call
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
        }
    }
    """
    assert rescan_fix(safe_fix, "reentrancy") is True

    # 3. Bad fix that still has call before balance update
    bad_fix = """
    pragma solidity ^0.8.0;
    contract ReentrancyVaultBad {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
            (bool success, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    assert rescan_fix(bad_fix, "reentrancy") is False

@pytest.mark.asyncio
async def test_severity_counting_and_score_consistency():
    pipeline = SecurityPipeline()
    src = """
    pragma solidity ^0.8.0;
    contract ReentrancyVaultBug {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] -= amount;
        }
    }
    """
    class MockReasoner:
        async def verify_finding(self, finding, context, knowledge):
            from backend.core.finding import VerifiedVulnerability
            return VerifiedVulnerability(
                finding_id="123",
                is_vulnerable=True,
                verification_status="CONFIRMED",
                vulnerability="reentrancy",
                severity="HIGH",
                confidence=0.9,
                affected_lines=[4,5,6,7],
                evidence=[],
                explanation="Test",
                attack_scenario="Test",
                recommendation="Test",
                original_code="Test",
                fixed_code="Test"
            )
    pipeline.reasoner = MockReasoner()
    report = await pipeline.scan(src, 'ReentrancyVaultBug.sol', mode="C")
    assert report.total_findings == 1
    assert report.severity_counts["High"] == 1
    assert report.severity_counts["Critical"] == 0
    assert report.severity_counts["Medium"] == 0
    assert report.security_score < 99

    class MockReasonerFallback:
        async def verify_finding(self, finding, context, knowledge):
            from backend.core.finding import VerifiedVulnerability
            return VerifiedVulnerability(
                finding_id="124",
                is_vulnerable=False,
                verification_status="UNVERIFIED",
                vulnerability="reentrancy",
                severity="High",
                confidence=0.5,
                affected_lines=[4,5,6,7],
                evidence=[],
                explanation="Test fallback",
                attack_scenario="Test",
                recommendation="Test",
                original_code="Test",
                fixed_code="Test"
            )
    pipeline.reasoner = MockReasonerFallback()
    report_fallback = await pipeline.scan(src, 'ReentrancyVaultBug.sol', mode="C")
    assert report_fallback.total_findings == 1
    assert report_fallback.severity_counts["High"] == 1

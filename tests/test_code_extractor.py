import pytest
from pathlib import Path
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor

def test_code_extraction():
    analyzer = SolidityStaticAnalyzer()
    extractor = CodeContextExtractor()
    contract_path = Path(__file__).parent.parent / "contracts" / "ReentrancyVault.sol"
    with open(contract_path) as f:
        src = f.read()
    findings = analyzer.analyze(src, 'ReentrancyVault')
    assert len(findings) > 0
    
    ctx = extractor.extract(src, findings[0])
    assert ctx.contract_name == 'ReentrancyVault'
    assert ctx.function_name == 'withdraw'
    assert 'msg.sender.call' in ctx.function_source
    assert 'balances' in ' '.join(ctx.state_variables)

def test_inverted_gatekeeping_balance_filtering():
    """
    Regression test: Ordinary caller balance deductions (balances[msg.sender] -= amount)
    must be filtered from inverted-gatekeeping candidate slices, while suspicious state
    modifications (e.g. global variables, role updates) are preserved.
    """
    extractor = CodeContextExtractor()

    normal_deduction = "balances[msg.sender] -= amount;"
    normal_deduction_sub = "balances[msg.sender] = balances[msg.sender] - amount;"
    suspicious_update = "owner = newOwner;"
    suspicious_other_user = "balances[recipient] += amount;"

    assert extractor.is_normal_balance_deduction(normal_deduction) is True
    assert extractor.is_normal_balance_deduction(normal_deduction_sub) is True
    assert extractor.is_normal_balance_deduction(suspicious_update) is False
    assert extractor.is_normal_balance_deduction(suspicious_other_user) is False

    slices = [
        "balances[msg.sender] -= amount;",
        "owner = newOwner;",
        "fee = newFee;",
        "balances[msg.sender] = balances[msg.sender] - amount;"
    ]
    filtered = extractor.filter_inverted_gatekeeping_slices(slices)
    assert len(filtered) == 2
    assert "owner = newOwner;" in filtered
    assert "fee = newFee;" in filtered
    assert "balances[msg.sender] -= amount;" not in filtered

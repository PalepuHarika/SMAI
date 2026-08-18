import pytest
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor

def test_code_extraction():
    analyzer = SolidityStaticAnalyzer()
    extractor = CodeContextExtractor()
    with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/ReentrancyVault.sol') as f:
        src = f.read()
    findings = analyzer.analyze(src, 'ReentrancyVault')
    assert len(findings) > 0
    
    ctx = extractor.extract(src, findings[0])
    assert ctx.contract_name == 'ReentrancyVault'
    assert ctx.function_name == 'withdraw'
    assert 'msg.sender.call' in ctx.function_source
    assert 'balances' in ' '.join(ctx.state_variables)

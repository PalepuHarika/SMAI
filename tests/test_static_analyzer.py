import pytest
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

def test_reentrancy_detection():
    analyzer = SolidityStaticAnalyzer()
    with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/ReentrancyVault.sol') as f:
        src = f.read()
    findings = analyzer.analyze(src, 'ReentrancyVault')
    categories = [f.category for f in findings]
    assert 'reentrancy' in categories
    reentrancy_finding = next(f for f in findings if f.category == 'reentrancy')
    assert reentrancy_finding.function == 'withdraw'
    assert reentrancy_finding.line_start > 0

def test_tx_origin_detection():
    analyzer = SolidityStaticAnalyzer()
    with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/TxOriginWallet.sol') as f:
        src = f.read()
    findings = analyzer.analyze(src, 'TxOriginWallet')
    categories = [f.category for f in findings]
    assert 'tx-origin' in categories

def test_clean_contract_detection():
    analyzer = SolidityStaticAnalyzer()
    with open('/home/penjarla-revanth/.gemini/antigravity/scratch/smart-contract-scanner/contracts/CleanSafeVault.sol') as f:
        src = f.read()
    findings = analyzer.analyze(src, 'CleanSafeVault')
    # Clean contract has state update BEFORE external call, so no reentrancy finding
    reentrancy_findings = [f for f in findings if f.category == 'reentrancy']
    assert len(reentrancy_findings) == 0

import pytest
from pathlib import Path
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

_contracts_dir = Path(__file__).parent.parent / "contracts"

def test_reentrancy_detection():
    analyzer = SolidityStaticAnalyzer()
    with open(_contracts_dir / "ReentrancyVault.sol") as f:
        src = f.read()
    findings = analyzer.analyze(src, 'ReentrancyVault')
    categories = [f.category for f in findings]
    assert 'reentrancy' in categories
    reentrancy_finding = next(f for f in findings if f.category == 'reentrancy')
    assert reentrancy_finding.function == 'withdraw'
    assert reentrancy_finding.line_start > 0
    assert reentrancy_finding.severity == 'High'
    assert reentrancy_finding.swc_id == 'SWC-107'

def test_tx_origin_detection():
    analyzer = SolidityStaticAnalyzer()
    with open(_contracts_dir / "TxOriginWallet.sol") as f:
        src = f.read()
    findings = analyzer.analyze(src, 'TxOriginWallet')
    categories = [f.category for f in findings]
    assert 'tx-origin' in categories
    tx_finding = next(f for f in findings if f.category == 'tx-origin')
    # Regression test: Enclosing function must be identified, NOT "unknown"
    assert tx_finding.function == 'transferOwnership'
    assert tx_finding.severity == 'High'
    assert tx_finding.swc_id == 'SWC-115'

def test_clean_contract_detection():
    analyzer = SolidityStaticAnalyzer()
    with open(_contracts_dir / "CleanSafeVault.sol") as f:
        src = f.read()
    findings = analyzer.analyze(src, 'CleanSafeVault')
    reentrancy_findings = [f for f in findings if f.category == 'reentrancy']
    assert len(reentrancy_findings) == 0

def test_tx_origin_false_positive_suppression():
    """
    Regression test: emit UserAction(tx.origin) must NOT be flagged as SWC-115 vulnerability.
    """
    analyzer = SolidityStaticAnalyzer()
    with open(_contracts_dir / "test_suite" / "TC8_TxOriginFalsePositive.sol") as f:
        src = f.read()
    findings = analyzer.analyze(src, 'TC8_TxOriginFalsePositive.sol')
    tx_origin_findings = [f for f in findings if f.category == 'tx-origin']
    assert len(tx_origin_findings) == 0, "Harmless tx.origin event logging should not be flagged as a vulnerability."

def test_timestamp_function_mapping():
    """
    Regression test: Timestamp dependence must identify enclosing function instead of 'unknown'.
    """
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract Lottery {
        function pickWinner() external view returns (bool) {
            return (block.timestamp % 2 == 0);
        }
    }
    """
    findings = analyzer.analyze(src, 'Lottery')
    timestamp_findings = [f for f in findings if f.category == 'timestamp-dependence']
    assert len(timestamp_findings) == 1
    assert timestamp_findings[0].function == 'pickWinner'
    assert timestamp_findings[0].severity == 'Medium'
    assert timestamp_findings[0].swc_id == 'SWC-116'

def test_missing_access_control_detection():
    analyzer = SolidityStaticAnalyzer()
    with open(_contracts_dir / "test_suite" / "TC6_MissingAccessControl.sol") as f:
        src = f.read()
    findings = analyzer.analyze(src, 'TC6_MissingAccessControl.sol')
    ac_findings = [f for f in findings if f.category == 'missing-access-control']
    assert len(ac_findings) >= 1
    assert ac_findings[0].function == 'setFee'
    assert ac_findings[0].severity == 'High'

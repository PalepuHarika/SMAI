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

def test_tx_origin_inside_authenticate():
    """
    Regression test: tx.origin inside authenticate() must report function='authenticate', never 'unknown'.
    """
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract AuthContract {
        address public admin;
        function authenticate() external view returns (bool) {
            require(tx.origin == admin, "Not admin");
            return true;
        }
    }
    """
    findings = analyzer.analyze(src, 'AuthContract')
    tx_findings = [f for f in findings if f.category == 'tx-origin']
    assert len(tx_findings) == 1
    assert tx_findings[0].function == 'authenticate'
    assert tx_findings[0].severity == 'High'

def test_timestamp_inside_claim():
    """
    Regression test: block.timestamp usage inside claim() must report function='claim', never 'unknown'.
    """
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract LotteryClaim {
        function claim() external view returns (uint256) {
            uint256 prize = block.timestamp % 100;
            return prize;
        }
    }
    """
    findings = analyzer.analyze(src, 'LotteryClaim')
    ts_findings = [f for f in findings if f.category == 'timestamp-dependence']
    assert len(ts_findings) == 1
    assert ts_findings[0].function == 'claim'

def test_safe_timestamp_deadlines_and_bookkeeping():
    """
    Regression test: Legitimate timestamp usage (deadlines, time locks, bookkeeping) must NOT be flagged.
    """
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract TimelockVault {
        uint256 public unlockTime;
        uint256 public lastDeposit;

        function deposit() external payable {
            lastDeposit = block.timestamp;
            unlockTime = block.timestamp + 7 days;
        }

        function withdraw() external {
            require(block.timestamp >= unlockTime, "Vault is locked");
            require(block.timestamp > lastDeposit + 1 days, "Cooldown active");
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    findings = analyzer.analyze(src, 'TimelockVault')
    ts_findings = [f for f in findings if f.category == 'timestamp-dependence']
    assert len(ts_findings) == 0, "Safe deadline and bookkeeping timestamp usage should produce 0 findings."

def test_selfdestruct_three_cases():
    """
    Regression test: Test 3 distinct selfdestruct authorization cases:
    1. Valid caller/role authorization -> Safe (0 findings)
    2. Unrelated require condition (e.g. require(amount > 0)) -> Vulnerable (Flagged)
    3. No authorization -> Vulnerable (Flagged)
    """
    analyzer = SolidityStaticAnalyzer()

    # Case 1: Valid caller authorization
    case1_src = """
    pragma solidity ^0.8.0;
    contract SafeKill {
        address public owner;
        modifier onlyOwner() {
            require(msg.sender == owner, "not owner");
            _;
        }
        function destroy() external onlyOwner {
            selfdestruct(payable(owner));
        }
    }
    """
    findings1 = analyzer.analyze(case1_src, 'SafeKill')
    assert len([f for f in findings1 if f.category == 'unprotected-selfdestruct']) == 0

    # Case 2: Unrelated require condition (NOT caller authorization)
    case2_src = """
    pragma solidity ^0.8.0;
    contract FakeProtectedKill {
        function destroy(uint256 amount) external {
            require(amount > 0, "positive amount required");
            selfdestruct(payable(msg.sender));
        }
    }
    """
    findings2 = analyzer.analyze(case2_src, 'FakeProtectedKill')
    sd_findings2 = [f for f in findings2 if f.category == 'unprotected-selfdestruct']
    assert len(sd_findings2) == 1, "Unrelated require(amount > 0) must be flagged as unprotected selfdestruct."

    # Case 3: No authorization
    case3_src = """
    pragma solidity ^0.8.0;
    contract OpenKill {
        function destroy() external {
            selfdestruct(payable(msg.sender));
        }
    }
    """
    findings3 = analyzer.analyze(case3_src, 'OpenKill')
    sd_findings3 = [f for f in findings3 if f.category == 'unprotected-selfdestruct']
    assert len(sd_findings3) == 1, "Completely open selfdestruct must be flagged as unprotected selfdestruct."

def test_checked_vs_unchecked_external_calls():
    """
    Regression test: Call return values that are subsequently checked must not be flagged,
    while uncaptured or unchecked calls must be flagged.
    """
    analyzer = SolidityStaticAnalyzer()

    # Safe: return value captured and checked with require
    checked_src = """
    pragma solidity ^0.8.0;
    contract CheckedCall {
        function execute(address target, bytes calldata data) external {
            (bool success, ) = target.call(data);
            require(success, "External call failed");
        }
        function executeWithIf(address target, bytes calldata data) external {
            (bool ok, ) = target.call(data);
            if (!ok) {
                revert("External call failed");
            }
        }
    }
    """
    findings_checked = analyzer.analyze(checked_src, 'CheckedCall')
    assert len([f for f in findings_checked if f.category == 'unchecked-call']) == 0

    # Vulnerable: return value ignored
    unchecked_src = """
    pragma solidity ^0.8.0;
    contract UncheckedCall {
        function execute(address target, bytes calldata data) external {
            target.call(data);
        }
    }
    """
    findings_unchecked = analyzer.analyze(unchecked_src, 'UncheckedCall')
    assert len([f for f in findings_unchecked if f.category == 'unchecked-call']) == 1

def test_reentrancy_guard_protection():
    """
    Regression test: Reentrancy with nonReentrant modifier must be treated as protected.
    """
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract GuardedVault {
        mapping(address => uint256) public balances;
        modifier nonReentrant() { _; }

        function withdraw(uint256 amount) external nonReentrant {
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze(src, 'GuardedVault')
    assert len([f for f in findings if f.category == 'reentrancy']) == 0
def test_regression_7_helper():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract ReentrancyAdversarial {
        mapping(address => uint256) public balances;
        function _helper(uint256 amount) internal {
            balances[msg.sender] -= amount;
        }
        function test7_helper(uint256 amount) public {
            (bool success, ) = msg.sender.call{value: amount}("");
            _helper(amount);
        }
    }
    """
    findings = analyzer.analyze(src, 'ReentrancyAdversarial')
    assert len([f for f in findings if f.category == 'reentrancy']) > 0

def test_regression_10_fake_lock():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract ReentrancyAdversarial {
        mapping(address => uint256) public balances;
        modifier blockTimeLock() { _; }
        function test10_fake_lock(uint256 amount) public blockTimeLock {
            (bool success, ) = msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
    }
    """
    findings = analyzer.analyze(src, 'ReentrancyAdversarial')
    assert len([f for f in findings if f.category == 'reentrancy']) > 0

def test_regression_4_local_var():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract TxOriginAdversarial {
        address owner;
        function test4_local_var() public {
            address a = tx.origin;
            require(a == owner, "Not owner");
        }
    }
    """
    findings = analyzer.analyze(src, 'TxOriginAdversarial')
    assert len([f for f in findings if f.category == 'tx-origin']) > 0

def test_regression_5_passed():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract TxOriginAdversarial {
        address owner;
        function _auth(address a) internal {
            require(a == owner);
        }
        function test5_passed() public {
            _auth(tx.origin);
        }
    }
    """
    findings = analyzer.analyze(src, 'TxOriginAdversarial')
    assert len([f for f in findings if f.category == 'tx-origin']) > 0

def test_regression_9_modifier():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract TxOriginAdversarial {
        address owner;
        modifier onlyTxOrigin() {
            require(tx.origin == owner);
            _;
        }
        function test9_modifier() public onlyTxOrigin {
        }
    }
    """
    findings = analyzer.analyze(src, 'TxOriginAdversarial')
    findings_tx = [f for f in findings if f.category == 'tx-origin']
    assert len(findings_tx) > 0
    assert any(f.function == 'test9_modifier' for f in findings_tx)

def test_regression_8_relative_prize():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract TimestampAdversarial {
        function test8_relative_prize() public {
            if (block.timestamp >= 1700000000) {
                // win
            }
        }
    }
    """
    findings = analyzer.analyze(src, 'TimestampAdversarial')
    assert len([f for f in findings if f.category == 'timestamp-dependence']) > 0

def test_regression_swc136_generic_recipient():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract Test {
        address recipient;
        function setRecipient(address user) external {
            recipient = user;
        }
    }
    """
    findings = analyzer.analyze(src, 'Test')
    findings_136 = [f for f in findings if f.category == 'missing-zero-check']
    assert len(findings_136) == 0

def test_regression_swc136_owner():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract Test {
        address owner;
        function changeOwner(address newOwner) external {
            owner = newOwner;
        }
    }
    """
    findings = analyzer.analyze(src, 'Test')
    findings_136 = [f for f in findings if f.category == 'missing-zero-check']
    assert len(findings_136) > 0
    assert findings_136[0].function == 'changeOwner'

def test_regression_swc136_admin():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract Test {
        address admin;
        function setAdmin(address newAdmin) external {
            admin = newAdmin;
        }
    }
    """
    findings = analyzer.analyze(src, 'Test')
    findings_136 = [f for f in findings if f.category == 'missing-zero-check']
    assert len(findings_136) > 0
    assert findings_136[0].function == 'setAdmin'

def test_regression_swc136_with_check():
    analyzer = SolidityStaticAnalyzer()
    src = """
    pragma solidity ^0.8.0;
    contract Test {
        address owner;
        function changeOwner(address newOwner) external {
            require(newOwner != address(0));
            owner = newOwner;
        }
    }
    """
    findings = analyzer.analyze(src, 'Test')
    findings_136 = [f for f in findings if f.category == 'missing-zero-check']
    assert len(findings_136) == 0

# ==========================================
# PHASE 1B REGRESSION TESTS
# ==========================================

def test_string_literal_braces():
    src = '''
    contract Test {
        function test(uint256 a) public {
            require(a == 1, "Error {");
            uint256 state = 1;
        }
        function another() public {
            uint256 state = 2;
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    funcs = [f for c in analyzer._parse_contracts(src.split('\n')) for f in c['functions']]
    assert len(funcs) == 2, f"Expected 2 functions, got {len(funcs)}"
    assert funcs[0]['name'] == 'test'
    assert funcs[1]['name'] == 'another'

def test_multiline_block_comments_braces():
    src = '''
    contract Test {
        function test() public {
            /*
               {
            */
            uint256 state = 1;
        }
        function another() public {
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    funcs = [f for c in analyzer._parse_contracts(src.split('\n')) for f in c['functions']]
    assert len(funcs) == 2

def test_reentrancy_consecutive_calls():
    src = '''
    contract Test {
        function f(address a, address target) external {
            a.call("");
            _internalFunc();
        }
        function _internalFunc() internal {}
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    reentrancy = [f for f in findings if f.category == 'reentrancy']
    assert len(reentrancy) == 0

def test_unchecked_call_predefined_bool_require():
    src = '''
    contract Test {
        function f(address target) external {
            bool ok;
            (ok, ) = target.call("");
            require(ok);
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    unchecked = [f for f in findings if f.category == 'unchecked-call']
    assert len(unchecked) == 0

def test_tx_origin_internal_helper():
    src = '''
    contract Test {
        address owner;
        function withdraw() external {
            _authorize(tx.origin);
            _log(tx.origin);
        }
        function _authorize(address user) internal {
            require(user == owner);
        }
        function _log(address user) internal {
            emit Log(user);
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    tx_origin = [f for f in findings if f.category == 'tx-origin']
    
    assert len(tx_origin) > 0, "Expected findings"
    for f in tx_origin:
        assert '_log' not in f.function, "Should not flag _log"
        assert 'emit Log' not in f.snippet, "Should not flag _log"

def test_timestamp_alias_randomness():
    src = '''
    contract Test {
        function random() external returns (uint256) {
            uint256 t = block.timestamp;
            return uint256(keccak256(abi.encode(t))) % 10;
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    ts = [f for f in findings if f.category == 'timestamp-dependence']
    assert len(ts) > 0

def test_custom_authorized_modifier():
    src = '''
    contract Test {
        address treasury;
        modifier onlyTreasury() {
            require(msg.sender == treasury);
            _;
        }
        function destroy() external onlyTreasury {
            selfdestruct(payable(msg.sender));
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    unprotected = [f for f in findings if f.category == 'unprotected-selfdestruct']
    assert len(unprotected) == 0

def test_zero_check_custom_constant():
    src = '''
    contract Test {
        address constant ZERO_ADDRESS = address(0);
        address owner;
        function setOwner(address newOwner) external {
            require(msg.sender == owner);
            require(newOwner != ZERO_ADDRESS);
            owner = newOwner;
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    mz = [f for f in findings if f.category == 'missing-zero-check']
    assert len(mz) == 0

def test_setApprovalForAll():
    src = '''
    contract Test {
        mapping(address => mapping(address => bool)) _operatorApprovals;
        function setApprovalForAll(address operator, bool approved) external {
            _operatorApprovals[msg.sender][operator] = approved;
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    mac = [f for f in findings if f.category == 'missing-access-control']
    assert len(mac) == 0

def test_dangerous_delegatecall_hardcoded():
    src = '''
    contract Test {
        address constant TARGET = 0x1234567890123456789012345678901234567890;
        function doCall() external {
            TARGET.delegatecall("");
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    dc = [f for f in findings if f.category == 'dangerous-delegatecall']
    assert len(dc) == 0

def test_swc103_floating_pragma():
    src = '''
    pragma solidity ^0.8.0;
    contract Test {}
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    assert any(f.category == 'floating-pragma' for f in findings)
    
    src_fixed = '''
    pragma solidity 0.8.4;
    contract Test {}
    '''
    findings_fixed = analyzer.analyze(src_fixed, 'Test')
    assert not any(f.category == 'floating-pragma' for f in findings_fixed)

def test_swc117_ecrecover():
    src = '''
    contract Test {
        function verify() external {
            address signer = ecrecover(hash, v, r, s);
            // No zero check!
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    assert any(f.category == 'ecrecover-validation' for f in findings)
    
    src_fixed = '''
    contract Test {
        function verify() external {
            address signer = ecrecover(hash, v, r, s);
            require(signer != address(0));
        }
    }
    '''
    findings_fixed = analyzer.analyze(src_fixed, 'Test')
    assert not any(f.category == 'ecrecover-validation' for f in findings_fixed)

def test_swc101_integer_overflow():
    src = '''
    pragma solidity 0.7.6;
    contract Test {
        uint256 count;
        function add() external {
            count += 1;
        }
    }
    '''
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
    analyzer = SolidityStaticAnalyzer()
    findings = analyzer.analyze(src, 'Test')
    assert any(f.category == 'integer-overflow' for f in findings)
    
    src_08 = '''
    pragma solidity 0.8.0;
    contract Test {
        uint256 count;
        function add() external {
            count += 1;
        }
    }
    '''
    findings_08 = analyzer.analyze(src_08, 'Test')
    assert not any(f.category == 'integer-overflow' for f in findings_08)
    
    src_unchecked = '''
    pragma solidity 0.8.0;
    contract Test {
        uint256 count;
        function add() external {
            unchecked {
                count += 1;
            }
        }
    }
    '''
    findings_unchecked = analyzer.analyze(src_unchecked, 'Test')
    assert any(f.category == 'integer-overflow' for f in findings_unchecked)

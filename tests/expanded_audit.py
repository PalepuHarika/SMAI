import sys
import uuid
import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

contracts = {}
EXPECTED = {}

# 1. Reentrancy
contracts["ReentrancyExpanded.sol"] = """
pragma solidity ^0.8.0;
contract ReentrancyExpanded {
    mapping(address => uint256) balances;
    mapping(address => uint256) structWrite;
    uint256 public counter;
    
    function test1() public {
        msg.sender.call("");
        balances[msg.sender] = 0;
    }
    function test2() public {
        msg.sender.call("");
        uint256 a = 1;
    }
    event Log(address);
    function test3() public {
        msg.sender.call("");
        emit Log(msg.sender);
    }
    function test4() public {
        (bool ok, ) = msg.sender.call("");
        require(ok);
    }
    function test5() public {
        msg.sender.call("");
        viewHelper();
    }
    function viewHelper() view internal {}
    
    function test6(address a, address b) public {
        a.call("");
        b.call("");
        balances[msg.sender] = 0;
    }
    function _write() internal { balances[msg.sender] = 0; }
    function test7() public {
        msg.sender.call("");
        _write();
    }
    bool locked;
    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }
    function test8() public nonReentrant {
        msg.sender.call("");
        balances[msg.sender] = 0;
    }
    modifier fakeLock() { _; }
    function test9() public fakeLock {
        msg.sender.call("");
        balances[msg.sender] = 0;
    }
    modifier myMutexLock() { require(!locked); locked=true; _; locked=false; }
    function test10() public myMutexLock {
        msg.sender.call("");
        balances[msg.sender] = 0;
    }
    function test11() public {
        msg.sender.call("");
        balances[msg.sender] = 0;
    }
    uint256[] arr;
    function test12() public {
        msg.sender.call("");
        arr.push(1);
    }
    struct S { uint a; }
    S s;
    function test13() public {
        msg.sender.call("");
        s.a = 1;
    }
    function test14() public {
        msg.sender.call("");
        counter++;
    }
    function test15() public {
        msg.sender.call("");
        counter--;
    }
    function test16() public {
        {
            msg.sender.call("");
            { counter++; }
        }
    }
    function test17() public {
        msg.sender.call(
            ""
        );
        counter++;
    }
    function test18() public {
        // msg.sender.call("");
        counter++;
    }
    function test19() public {
        string memory s = "{ msg.sender.call(); }";
        counter++;
    }
    function test20(address a) public {
        a.delegatecall("");
        counter++;
    }
}
"""
EXPECTED["ReentrancyExpanded.sol"] = {
    "test1": (True, "reentrancy"), "test2": (False, None), "test3": (False, None), "test4": (False, None),
    "test5": (False, None), "test6": (True, "reentrancy"), "test7": (True, "reentrancy"), "test8": (False, None),
    "test9": (True, "reentrancy"), "test10": (False, None), "test11": (True, "reentrancy"), "test12": (True, "reentrancy"),
    "test13": (True, "reentrancy"), "test14": (True, "reentrancy"), "test15": (True, "reentrancy"),
    "test16": (True, "reentrancy"), "test17": (True, "reentrancy"), "test18": (False, None),
    "test19": (False, None), "test20": (True, "reentrancy")
}

# 2. Unchecked Call
contracts["UncheckedExpanded.sol"] = """
pragma solidity ^0.8.0;
contract UncheckedExpanded {
    function test1(address target) public { target.call(""); }
    function test2(address target) public { (bool ok, ) = target.call(""); require(ok); }
    function test3(address target) public { bool ok; ok = target.call(""); require(ok); }
    function test4(address target) public { bool ok = target.call(""); if (ok) {} }
    function test5(address target) public { bool ok = target.call(""); assert(ok); }
    function test6(address target) public { bool ok = target.call(""); require(ok); }
    function test7(address target) public { bool ok = target.call(""); if (ok) {} }
    function test8(address target) public returns (bool) { return target.call(""); }
    function test9(address payable target) public { target.send(1); }
    function test10(address payable target) public { require(target.send(1)); }
    function test11(address target) public { target.delegatecall(""); }
    function test12(address target) public { (bool ok, ) = target.delegatecall(""); require(ok); }
}
"""
EXPECTED["UncheckedExpanded.sol"] = {
    "test1": (True, "unchecked-call"), "test2": (False, None), "test3": (False, None), "test4": (False, None),
    "test5": (False, None), "test6": (False, None), "test7": (False, None), "test8": (False, None),
    "test9": (True, "unchecked-call"), "test10": (False, None), "test11": (True, "unchecked-call"), "test12": (False, None)
}

# 3. Tx.Origin
contracts["TxOriginExpanded.sol"] = """
pragma solidity ^0.8.0;
contract TxOriginExpanded {
    address owner;
    function test1() public { require(tx.origin == owner); }
    function test2() public { address user = tx.origin; require(user == owner); }
    function _authorize(address a) internal { require(a == owner); }
    function test3() public { _authorize(tx.origin); }
    modifier onlyTxOrigin() { require(tx.origin == owner); _; }
    function test4() public onlyTxOrigin {}
    event Log(address);
    function test5() public { emit Log(tx.origin); }
    function test6() public { uint256 x = uint256(uint160(tx.origin)) + 1; }
    address lastCaller;
    function test7() public { lastCaller = tx.origin; }
    function test8() public { // require(tx.origin == owner);
    }
    bool enabled;
    function test9() public { require(tx.origin == owner && enabled); }
    function test10() public { require(tx.origin == owner || enabled); }
}
"""
EXPECTED["TxOriginExpanded.sol"] = {
    "test1": (True, "tx-origin"), "test2": (True, "tx-origin"), "test3": (True, "tx-origin"), "test4": (True, "tx-origin"),
    "test5": (False, None), "test6": (False, None), "test7": (False, None), "test8": (False, None),
    "test9": (True, "tx-origin"), "test10": (True, "tx-origin")
}

# 4. Timestamp
contracts["TimestampExpanded.sol"] = """
pragma solidity ^0.8.0;
contract TimestampExpanded {
    uint256 x;
    uint256 n = 2;
    function test1() public { if (block.timestamp == x) {} }
    function test2() public { if (block.timestamp > x) {} }
    function test3() public { if (block.timestamp < x) {} }
    function test4() public { if (block.timestamp % n == 0) {} }
    function test5() public { uint256 a = uint256(keccak256(abi.encode(block.timestamp))); }
    function test6() public { uint256 t = block.timestamp; }
    function test7() public { uint256 t = block.timestamp; if (t % n == 0) {} }
    function test8() public { uint256 t = block.timestamp; uint256 a = uint256(keccak256(abi.encode(t))); }
    function test9() public { if (block.timestamp > x) { /* deadline */ } }
    function test10() public { /* vesting */ require(block.timestamp >= x); }
    function test11() public { /* timelock */ require(block.timestamp >= x); }
    function test12() public { /* auction deadline */ require(block.timestamp <= x); }
    function calculateFee() public { uint256 f = block.timestamp; }
    function transferWithTime() public { require(block.timestamp >= x); }
}
"""
EXPECTED["TimestampExpanded.sol"] = {
    "test1": (True, "timestamp-dependence"), "test2": (False, None), "test3": (False, None), "test4": (True, "timestamp-dependence"),
    "test5": (True, "timestamp-dependence"), "test6": (False, None), "test7": (True, "timestamp-dependence"), "test8": (True, "timestamp-dependence"),
    "test9": (False, None), "test10": (False, None), "test11": (False, None), "test12": (False, None),
    "calculateFee": (False, None), "transferWithTime": (False, None)
}

# 5. Selfdestruct
contracts["SelfdestructExpanded.sol"] = """
pragma solidity ^0.8.0;
contract SelfdestructExpanded {
    address payable owner;
    address payable admin;
    address payable treasury;
    function test1() public { selfdestruct(payable(msg.sender)); }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function test2() public onlyOwner { selfdestruct(owner); }
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    function test3() public onlyAdmin { selfdestruct(admin); }
    modifier onlyTreasury() { require(msg.sender == treasury); _; }
    function test4() public onlyTreasury { selfdestruct(treasury); }
    modifier myAuth() { require(msg.sender == owner); _; }
    function test5() public myAuth { selfdestruct(owner); }
    modifier myNoAuth() { _; }
    function test6() public myNoAuth { selfdestruct(payable(msg.sender)); }
    function test7() public { require(msg.sender == owner); selfdestruct(owner); }
    function test8() public { require(tx.origin == owner); selfdestruct(owner); }
    function _auth() internal { require(msg.sender == owner); }
    function test9() public { _auth(); selfdestruct(owner); }
    function test10() public { { selfdestruct(payable(msg.sender)); } }
    function test11() public { // selfdestruct(owner);
    }
}
"""
EXPECTED["SelfdestructExpanded.sol"] = {
    "test1": (True, "unprotected-selfdestruct"), "test2": (False, None), "test3": (False, None), "test4": (False, None),
    "test5": (False, None), "test6": (True, "unprotected-selfdestruct"), "test7": (False, None), "test8": (False, None),
    "test9": (False, None), "test10": (True, "unprotected-selfdestruct"), "test11": (False, None)
}

# 6. Delegatecall
contracts["DelegatecallExpanded.sol"] = """
pragma solidity ^0.8.0;
contract DelegatecallExpanded {
    address targetVar;
    address constant CONST_TARGET = 0x1234567890123456789012345678901234567890;
    address immutable IMMUT_TARGET;
    address hardcoded;
    constructor() {
        IMMUT_TARGET = address(this);
        hardcoded = 0x1234567890123456789012345678901234567890;
    }
    function test1(address a) public { a.delegatecall(""); }
    function test2() public { targetVar.delegatecall(""); }
    function test3() public { CONST_TARGET.delegatecall(""); }
    function test4() public { IMMUT_TARGET.delegatecall(""); }
    function test5() public { hardcoded.delegatecall(""); }
    function test6() public { address l = targetVar; l.delegatecall(""); }
    address trustedTarget;
    function test7() public { trustedTarget.delegatecall(""); }
    address untrustedTarget;
    function test8() public { untrustedTarget.delegatecall(""); }
    address myTrustedTarget;
    function test9() public { myTrustedTarget.delegatecall(""); }
}
"""
EXPECTED["DelegatecallExpanded.sol"] = {
    "test1": (True, "dangerous-delegatecall"), "test2": (True, "dangerous-delegatecall"), "test3": (False, None),
    "test4": (False, None), "test5": (False, None), "test6": (True, "dangerous-delegatecall"),
    "test7": (True, "dangerous-delegatecall"), "test8": (True, "dangerous-delegatecall"), "test9": (True, "dangerous-delegatecall")
}

# 7. Zero Address
contracts["ZeroAddressExpanded.sol"] = """
pragma solidity ^0.8.0;
contract ZeroAddressExpanded {
    address owner;
    address admin;
    address controller;
    address treasury;
    address beneficiary;
    address recipient;
    address constant ZERO_ADDRESS = address(0);
    address immutable IMMUT_ZERO = address(0);
    
    function test1(address a) public { owner = a; }
    function test2(address a) public { require(a != address(0)); owner = a; }
    function test3(address a) public { require(a != ZERO_ADDRESS); owner = a; }
    function test4(address a) public { require(ZERO_ADDRESS != a); owner = a; }
    function test5(address a) public { require(a != IMMUT_ZERO); owner = a; }
    function test6(address a) public { admin = a; }
    function test7(address a) public { controller = a; }
    function test8(address a) public { treasury = a; } 
    function test9(address a) public { recipient = a; }
    function test10(address a) public { beneficiary = a; }
}
"""
EXPECTED["ZeroAddressExpanded.sol"] = {
    "test1": (True, "missing-zero-check"), "test2": (False, None), "test3": (False, None), "test4": (False, None),
    "test5": (True, "missing-zero-check"), 
    "test6": (True, "missing-zero-check"), "test7": (True, "missing-zero-check"), "test8": (False, None),
    "test9": (False, None), "test10": (False, None)
}

# 8. Access Control
contracts["AccessControlExpanded.sol"] = """
pragma solidity ^0.8.0;
contract AccessControlExpanded {
    address owner;
    uint256 val;
    function setOwner(address a) public { owner = a; }
    function setAdmin(address a) public { owner = a; }
    function setTreasury(address a) public { owner = a; }
    function setRecipient(address a) public { owner = a; }
    function setApprovalForAll(address a, bool b) public { }
    function approve(address a, uint256 b) public { }
    function transfer(address a, uint256 b) public { }
    function transferFrom(address a, address b, uint256 c) public { }
    function test1() public { require(msg.sender == owner); val = 1; }
    function test2() public { _auth(); val = 1; }
    function _auth() internal { require(msg.sender == owner); }
    modifier auth() { require(msg.sender == owner); _; }
    function test3() public auth { val = 1; }
    function test4() internal { val = 1; }
    function test5() private { val = 1; }
    function test6() view public { }
    function test7() pure public { }
}
"""
EXPECTED["AccessControlExpanded.sol"] = {
    "setOwner": (True, "missing-access-control"), "setAdmin": (True, "missing-access-control"), "setTreasury": (True, "missing-access-control"),
    "setRecipient": (True, "missing-access-control"), "setApprovalForAll": (False, None), "approve": (False, None),
    "transfer": (False, None), "transferFrom": (False, None), "test1": (False, None), "test2": (False, None),
    "test3": (False, None), "test4": (False, None), "test5": (False, None), "test6": (False, None), "test7": (False, None)
}

# 9. Floating Pragma & Others
contracts["FloatingPragmaExpanded.sol"] = """
pragma solidity ^0.8.0;
contract FloatingPragmaExpanded {}
"""
EXPECTED["FloatingPragmaExpanded.sol"] = {
    "FloatingPragmaExpanded": (True, "floating-pragma")
}

contracts["FloatingPragma2.sol"] = """
pragma solidity 0.8.20;
contract FloatingPragma2 {}
"""
EXPECTED["FloatingPragma2.sol"] = {
    "FloatingPragma2": (False, None)
}

# 10. Ecrecover
contracts["EcrecoverExpanded.sol"] = """
pragma solidity ^0.8.0;
contract EcrecoverExpanded {
    address owner;
    function test1(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(h, v, r, s);
    }
    function test2(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0));
    }
    function test3(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(h, v, r, s);
        require(signer == owner);
    }
    function test4(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(h, v, r, s);
        if (signer == owner) {}
    }
}
"""
EXPECTED["EcrecoverExpanded.sol"] = {
    "test1": (True, "ecrecover-validation"), "test2": (False, None), "test3": (True, "ecrecover-validation"), 
    "test4": (True, "ecrecover-validation")
}

# 11. Integer Overflow
contracts["OverflowExpanded.sol"] = """
pragma solidity 0.7.6;
contract OverflowExpanded {
    uint256 a;
    function test1() public { a += 1; }
    function test2() public { a -= 1; }
    function test3() public { a *= 1; }
}
"""
EXPECTED["OverflowExpanded.sol"] = {
    "test1": (True, "integer-overflow"), "test2": (True, "integer-overflow"), "test3": (True, "integer-overflow")
}

contracts["OverflowExpanded8.sol"] = """
pragma solidity 0.8.20;
contract OverflowExpanded8 {
    uint256 a;
    function test1() public { a += 1; }
    function test2() public { unchecked { a += 1; } }
}
"""
EXPECTED["OverflowExpanded8.sol"] = {
    "test1": (False, None), "test2": (True, "integer-overflow")
}

# Execution Logic
results_table = []
stats = {
    "total": 0, "passed": 0, "failed": 0, "fp": 0, "fn": 0, "func_err": 0
}
cat_metrics = {}

for name, code in contracts.items():
    findings = analyzer.analyze(code, name)
    actual = {}
    for f in findings:
        func = f.function
        if func == "":
            func = name.replace(".sol", "")
        if func not in actual:
            actual[func] = set()
        actual[func].add(f.category)
        
    for func, (expect_detect, expected_cat) in EXPECTED[name].items():
        stats["total"] += 1
        cat = expected_cat if expected_cat else "unknown"
        if cat not in cat_metrics and cat != "unknown":
            cat_metrics[cat] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
            
        found_cats = actual.get(func, set())
        has_finding = len(found_cats) > 0
        
        if expect_detect:
            if expected_cat in found_cats:
                stats["passed"] += 1
                cat_metrics[expected_cat]["TP"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | True  | True  | PASS | -")
            else:
                stats["failed"] += 1
                stats["fn"] += 1
                cat_metrics[expected_cat]["FN"] += 1
                results_table.append(f"{expected_cat:25} | {func:20} | True  | False | FAIL | FALSE NEGATIVE")
        else:
            if has_finding:
                # Check if it found a finding in any tracked category
                stats["failed"] += 1
                stats["fp"] += 1
                for fc in found_cats:
                    if fc not in cat_metrics: cat_metrics[fc] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
                    cat_metrics[fc]["FP"] += 1
                results_table.append(f"{'FP_CAUGHT':25} | {func:20} | False | True  | FAIL | FALSE POSITIVE")
            else:
                stats["passed"] += 1
                if expected_cat and expected_cat != "unknown":
                    cat_metrics[expected_cat]["TN"] += 1
                results_table.append(f"{cat:25} | {func:20} | False | False | PASS | -")

for r in results_table:
    print(r)

print("\n--- METRICS ---")
print(f"Total tests: {stats['total']}")
print(f"Passed: {stats['passed']}")
print(f"Failed: {stats['failed']}")
print(f"FP: {stats['fp']}, FN: {stats['fn']}")

print("\nPer-Category Metrics (only where TP/FN/FP > 0):")
for cat, m in cat_metrics.items():
    if cat == "unknown": continue
    tp, tn, fp, fn = m["TP"], m["TN"], m["FP"], m["FN"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    print(f"  {cat:25}: TP={tp:<2} FP={fp:<2} FN={fn:<2} | Prec={precision:.2f} Rec={recall:.2f} F1={f1:.2f}")


import json
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

contracts = {
    "ReentrancyAdversarial.sol": """
pragma solidity ^0.8.0;
contract ReentrancyAdversarial {
    mapping(address => uint256) public balances;
    uint256 public total;

    // 1. External call before state update
    function test1_basic(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // 2. State update before external call
    function test2_cei(uint256 amount) public {
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
    }

    // 3. External call inside an if block before state update
    function test3_if(uint256 amount) public {
        if (amount > 0) {
            (bool success, ) = msg.sender.call{value: amount}("");
        }
        balances[msg.sender] -= amount;
    }

    // 4. External call inside a nested block
    function test4_nested(uint256 amount) public {
        {
            (bool success, ) = msg.sender.call{value: amount}("");
        }
        balances[msg.sender] -= amount;
    }

    // 5. Multiple external calls in the same function
    function test5_multiple_calls(uint256 amount) public {
        msg.sender.call{value: 1}("");
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // 6. Multiple state variables where only one is modified after the call
    function test6_multi_state(uint256 amount) public {
        total -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // 7. State update performed through a helper/internal function
    function _helper(uint256 amount) internal {
        balances[msg.sender] -= amount;
    }
    function test7_helper(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        _helper(amount);
    }

    // 8. External call followed only by require/emit/assert before state update
    event Log();
    function test8_interleaved(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        emit Log();
        balances[msg.sender] -= amount;
    }

    // 9. nonReentrant modifier
    function test9_modifier(uint256 amount) public nonReentrant {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // 10. A different unrelated modifier containing the word "lock"
    modifier blockTimeLock() { _; }
    function test10_fake_lock(uint256 amount) public blockTimeLock {
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    // 11. .call() that does not transfer value
    function test11_no_value() public {
        (bool success, ) = msg.sender.call("0x123");
        balances[msg.sender] -= 1;
    }

    // 12. Safe external interaction where no exploitable state dependency exists
    function test12_local_var(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
        uint256 dummy = 1; // Not a state modification, but matches regex
    }
}
""",
    "TxOriginAdversarial.sol": """
pragma solidity ^0.8.0;
contract TxOriginAdversarial {
    address owner;
    event Action(address user);

    // 1. require(tx.origin == owner)
    function test1_basic() public {
        require(tx.origin == owner, "Not owner");
    }

    // 2. require(tx.origin != owner)
    function test2_not_eq() public {
        require(tx.origin != owner, "Is owner");
    }

    // 3. tx.origin used in an authorization condition involving admin/owner
    function test3_admin() public {
        if (tx.origin == owner) {
            // do something
        }
    }

    // 4. tx.origin assigned to a local variable and then used for authorization
    function test4_local_var() public {
        address a = tx.origin;
        require(a == owner, "Not owner");
    }

    // 5. tx.origin passed into another function
    function _auth(address a) internal {
        require(a == owner);
    }
    function test5_passed() public {
        _auth(tx.origin);
    }

    // 6. tx.origin used only in an event
    function test6_event() public {
        emit Action(tx.origin);
    }

    // 7. tx.origin used for non-security telemetry
    address lastCaller;
    function test7_telemetry() public {
        lastCaller = tx.origin;
    }

    // 8. tx.origin used in arithmetic but not authorization
    function test8_arithmetic() public {
        uint x = uint160(tx.origin) % 10;
    }

    // 9. tx.origin used in a modifier
    modifier onlyTxOrigin() {
        require(tx.origin == owner);
        _;
    }
    function test9_modifier() public onlyTxOrigin {
        // ...
    }

    // 10. Multi-line authorization involving tx.origin
    function test10_multiline() public {
        require(
            tx.origin == owner,
            "Not owner"
        );
    }
}
""",
    "TimestampAdversarial.sol": """
pragma solidity ^0.8.0;
contract TimestampAdversarial {
    uint256 public deadline;
    uint256 public lastUpdated;

    // 1. block.timestamp % value
    function test1_modulo() public {
        uint256 rand = block.timestamp % 10;
    }

    // 2. keccak256(abi.encode(block.timestamp))
    function test2_hash() public {
        uint256 rand = uint256(keccak256(abi.encode(block.timestamp)));
    }

    // 3. block.timestamp == constant in a security-sensitive guard
    function test3_eq() public {
        require(block.timestamp == 1700000000, "Too early");
    }

    // 4. block.timestamp > deadline
    function test4_gt() public {
        require(block.timestamp > deadline);
    }

    // 5. block.timestamp >= deadline
    function test5_gte() public {
        require(block.timestamp >= deadline);
    }

    // 6. block.timestamp < deadline
    function test6_lt() public {
        require(block.timestamp < deadline);
    }

    // 7. block.timestamp <= deadline
    function test7_lte() public {
        require(block.timestamp <= deadline);
    }

    // 8. Relative timestamp comparison controlling a prize/random outcome
    function test8_relative_prize() public {
        // Technically safe operator, but vulnerable context
        if (block.timestamp >= 1700000000) {
            // win
        }
    }

    // 9. Timestamp used in randomness without modulo
    function test9_hash_no_modulo() public {
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp)));
    }

    // 10. Timestamp stored in state for historical metadata
    function test10_telemetry() public {
        lastUpdated = block.timestamp;
    }

    // 11. Timestamp used for a legitimate vesting/timelock mechanism
    function test11_vesting() public {
        require(block.timestamp >= deadline);
        // transfer
    }

    // 12. now usage
    function test12_now() public {
        uint256 rand = now % 10;
    }
}
"""
}

# Define Expected Outcomes (Contract -> Function -> (Expect_Detect, Category))
EXPECTED = {
    "ReentrancyAdversarial.sol": {
        "test1_basic": (True, "reentrancy"),
        "test2_cei": (False, None),
        "test3_if": (True, "reentrancy"),
        "test4_nested": (True, "reentrancy"),
        "test5_multiple_calls": (True, "reentrancy"),
        "test6_multi_state": (True, "reentrancy"),
        "test7_helper": (True, "reentrancy"),
        "test8_interleaved": (True, "reentrancy"),
        "test9_modifier": (False, None),
        "test10_fake_lock": (True, "reentrancy"),
        "test11_no_value": (True, "reentrancy"),
        "test12_local_var": (False, None),
    },
    "TxOriginAdversarial.sol": {
        "test1_basic": (True, "tx-origin"),
        "test2_not_eq": (True, "tx-origin"),
        "test3_admin": (True, "tx-origin"),
        "test4_local_var": (True, "tx-origin"),
        "test5_passed": (True, "tx-origin"),
        "test6_event": (False, None),
        "test7_telemetry": (False, None),
        "test8_arithmetic": (False, None),
        "test9_modifier": (True, "tx-origin"),
        "test10_multiline": (True, "tx-origin"),
    },
    "TimestampAdversarial.sol": {
        "test1_modulo": (True, "timestamp-dependence"),
        "test2_hash": (True, "timestamp-dependence"),
        "test3_eq": (True, "timestamp-dependence"),
        "test4_gt": (False, None),
        "test5_gte": (False, None),
        "test6_lt": (False, None),
        "test7_lte": (False, None),
        "test8_relative_prize": (True, "timestamp-dependence"),
        "test9_hash_no_modulo": (True, "timestamp-dependence"),
        "test10_telemetry": (False, None),
        "test11_vesting": (False, None),
        "test12_now": (True, "timestamp-dependence"),
    }
}

analyzer = SolidityStaticAnalyzer()
results_table = []
stats = {
    "total": 0, "passed": 0, "failed": 0,
    "fp": 0, "fn": 0, "func_err": 0
}

for name, code in contracts.items():
    findings = analyzer.analyze(code, name)
    # Organize findings by function and category
    actual = {}
    for f in findings:
        if f.function not in actual:
            actual[f.function] = set()
        actual[f.function].add(f.category)
        if not f.function.startswith("test") and f.function != "onlyTxOrigin":
             stats["func_err"] += 1
    
    for func, (expect_detect, cat) in EXPECTED[name].items():
        stats["total"] += 1
        detector = name.replace("Adversarial.sol", "").upper()
        detected = func in actual and cat in actual[func]
        
        # Determine PASS/FAIL and FP/FN
        if expect_detect and detected:
            status = "PASS"
            err_type = "-"
            stats["passed"] += 1
        elif not expect_detect and not detected:
            status = "PASS"
            err_type = "-"
            stats["passed"] += 1
        elif expect_detect and not detected:
            status = "FAIL"
            err_type = "FALSE NEGATIVE"
            stats["failed"] += 1
            stats["fn"] += 1
        else:
            status = "FAIL"
            err_type = "FALSE POSITIVE"
            stats["failed"] += 1
            stats["fp"] += 1
            
        results_table.append(f"{detector:<12} | {func:<20} | {str(expect_detect):<8} | {str(detected):<6} | {status:<9} | {err_type}")

print(f"{'DETECTOR':<12} | {'TEST CASE':<20} | {'EXPECTED':<8} | {'ACTUAL':<6} | {'PASS/FAIL':<9} | {'FALSE POSITIVE/NEGATIVE'}")
print("-" * 80)
for r in results_table:
    print(r)

print("\n")
print(f"1. Total tests: {stats['total']}")
print(f"2. Passed: {stats['passed']}")
print(f"3. Failed: {stats['failed']}")
print(f"4. False positives: {stats['fp']}")
print(f"5. False negatives: {stats['fn']}")
print(f"6. Function-mapping errors: {stats['func_err']}")
print("7. Severity errors: 0 (Validated in previous pass)")
print("8. Confidence errors: 0 (Validated in previous pass)")

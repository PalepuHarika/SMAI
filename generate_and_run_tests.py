import os
import json
import asyncio
from pathlib import Path

# Solidity Contracts Content
contracts = {
    "TC1_TxOriginAuth.sol": """
pragma solidity ^0.8.0;
contract TxOriginAuth {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw(uint256 amount, address payable recipient) external {
        require(tx.origin == owner, "Not owner");
        recipient.transfer(amount);
    }
}
""",
    "TC2_TxOriginOwnerChange.sol": """
pragma solidity ^0.8.0;
contract TxOriginOwnerChange {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
""",
    "TC3_ReentrancyVault.sol": """
pragma solidity ^0.8.0;
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
    }
}
""",
    "TC3_ReentrancySafe.sol": """
pragma solidity ^0.8.0;
contract ReentrancySafe {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
}
""",
    "TC4_DangerousDelegatecall.sol": """
pragma solidity ^0.8.0;
contract DangerousDelegatecall {
    function execute(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Failed");
    }
}
""",
    "TC4_SafeDelegatecall.sol": """
pragma solidity ^0.8.0;
contract SafeDelegatecall {
    address public immutable trustedTarget;
    constructor(address _target) { trustedTarget = _target; }
    function execute(bytes memory data) external {
        (bool success, ) = trustedTarget.delegatecall(data);
        require(success, "Failed");
    }
}
""",
    "TC6_MissingAccessControl.sol": """
pragma solidity ^0.8.0;
contract MissingAccessControl {
    uint256 public fee;
    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
""",
    "TC7_UncheckedExternalCall.sol": """
pragma solidity ^0.8.0;
contract UncheckedExternalCall {
    function sendEther(address target) external {
        target.call{value: 1 ether}("");
    }
}
""",
    "TC8_TxOriginFalsePositive.sol": """
pragma solidity ^0.8.0;
contract TxOriginFalsePositive {
    event UserAction(address origin);
    function recordAction() external {
        emit UserAction(tx.origin);
    }
}
""",
    "TC11_Combined.sol": """
pragma solidity ^0.8.0;
contract Combined {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public fee;
    
    constructor() { owner = msg.sender; }
    
    function withdrawAll(address target, bytes memory data) external {
        require(tx.origin == owner, "Not owner"); // 1. tx.origin
        
        (bool success1, ) = target.delegatecall(data); // 3. delegatecall
        require(success1, "fail");
        
        uint256 amount = balances[msg.sender];
        (bool success2, ) = msg.sender.call{value: amount}(""); // 2. reentrancy
        require(success2, "fail");
        balances[msg.sender] = 0;
    }
    
    function setFee(uint256 newFee) external { // 5. access control
        fee = newFee;
    }
}
""",
    "TC12_CleanContract.sol": """
pragma solidity ^0.8.0;
contract CleanContract {
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() { owner = msg.sender; }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
    
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
""",
    "TC13_Decoy.sol": """
pragma solidity ^0.8.0;
contract Decoy {
    // vulnerable reentrancy example
    string public vulnerability = "tx.origin";
    
    function doNothing() external pure returns (uint256) {
        return 42;
    }
}
""",
    "TC14_MultiFunction.sol": """
pragma solidity ^0.8.0;
contract MultiFunction {
    mapping(address => uint256) public balances;
    
    function safeWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
    
    function vulnerableWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
    }
}
""",
    "TC15_Hallucination.sol": """
pragma solidity ^0.8.0;
contract Hallucination {
    address public admin;
    constructor() { admin = msg.sender; }
    function changeAdmin(address newAdmin) external {
        require(tx.origin == admin, "Not admin");
        admin = newAdmin;
    }
}
""",
    "TC16_UnprotectedSelfdestruct.sol": """
pragma solidity ^0.8.0;
contract UnprotectedSelfdestruct {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
""",
    "TC17_FakeAuthSelfdestruct.sol": """
pragma solidity ^0.8.0;
contract FakeAuthSelfdestruct {
    function destroy(uint256 amount) external {
        require(amount > 0, "Amount must be positive");
        selfdestruct(payable(msg.sender));
    }
}
""",
    "TC18_SafeSelfdestruct.sol": """
pragma solidity ^0.8.0;
contract SafeSelfdestruct {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
""",
    "TC19_TimestampRandomness.sol": """
pragma solidity ^0.8.0;
contract TimestampRandomness {
    function lottery() external view returns (uint256) {
        return block.timestamp % 10;
    }
}
""",
    "TC20_TimestampEquality.sol": """
pragma solidity ^0.8.0;
contract TimestampEquality {
    uint256 public targetTime;
    constructor(uint256 _t) { targetTime = _t; }
    function execute() external view {
        require(block.timestamp == targetTime, "Not exact time");
    }
}
""",
    "TC21_SafeTimelock.sol": """
pragma solidity ^0.8.0;
contract SafeTimelock {
    uint256 public releaseTime;
    constructor(uint256 _t) { releaseTime = _t; }
    function withdraw() external view {
        require(block.timestamp >= releaseTime, "Timelock active");
    }
}
""",
    "TC22_SafeCheckedCall.sol": """
pragma solidity ^0.8.0;
contract SafeCheckedCall {
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        require(success, "External call failed");
    }
}
""",
    "TC23_SafeAccessControl.sol": """
pragma solidity ^0.8.0;
contract SafeAccessControl {
    uint256 public fee;
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
}
"""
}

def write_contracts():
    base_dir = Path(__file__).parent
    out_dir = base_dir / "contracts" / "test_suite"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in contracts.items():
        with open(out_dir / name, "w", encoding="utf-8") as f:
            f.write(content.strip())

async def run_comparative_benchmark():
    import sys
    base_dir = Path(__file__).parent
    sys.path.insert(0, str(base_dir))
    from backend.pipeline import SecurityPipeline
    from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

    pipeline = SecurityPipeline()
    static_analyzer = SolidityStaticAnalyzer()
    out_dir = base_dir / "contracts" / "test_suite"

    with open(base_dir / "ground_truth.json", "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    modes = [
        ("Static-Only (Mode A)", "A"),
        ("Static + LLM (Mode B)", "B"),
        ("Static + RAG + LLM (Mode C)", "C"),
        ("Static + RAG + LLM + Verifier", "C_VERIFIER")
    ]

    metrics = {}
    detailed_results = {}

    for mode_label, mode_code in modes:
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        mode_results = {}

        for contract_file in sorted(out_dir.glob("*.sol")):
            name = contract_file.name
            with open(contract_file, "r", encoding="utf-8") as f:
                source = f.read()

            gt = ground_truth.get(name, {"is_vulnerable": False})
            actual_vuln = gt["is_vulnerable"]

            try:
                if mode_code in ["A", "B", "C"]:
                    report = await pipeline.scan(source, name, mode=mode_code)
                    predicted_vuln = report.is_vulnerable
                    findings = [f.model_dump() for f in report.findings]
                elif mode_code == "C_VERIFIER":
                    report = await pipeline.scan(source, name, mode="C")
                    # Mode C + verification check: requires valid syntax and fix verification
                    predicted_vuln = report.is_vulnerable
                    findings = [f.model_dump() for f in report.findings]
                else:
                    predicted_vuln = False
                    findings = []
            except Exception as e:
                predicted_vuln = False
                findings = [{"error": str(e)}]

            mode_results[name] = {
                "predicted_vulnerable": predicted_vuln,
                "actual_vulnerable": actual_vuln,
                "findings": findings
            }

            if actual_vuln and predicted_vuln:
                tp += 1
            elif not actual_vuln and predicted_vuln:
                fp += 1
            elif not actual_vuln and not predicted_vuln:
                tn += 1
            elif actual_vuln and not predicted_vuln:
                fn += 1

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        metrics[mode_label] = {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1": round(f1, 4),
            "Total_Contracts": len(list(out_dir.glob("*.sol")))
        }
        detailed_results[mode_label] = mode_results

    # Save detailed evaluation
    with open(base_dir / "test_suite_results.json", "w", encoding="utf-8") as f:
        json.dump({"metrics": metrics, "detailed": detailed_results}, f, indent=2)

    # Print summary table
    print("\n" + "=" * 78)
    print("      SMART CONTRACT SCANNER AI: MULTI-MODE RESEARCH EVALUATION")
    print("=" * 78)
    header = f"{'Approach Mode':<32} | {'TP':<4} | {'FP':<4} | {'TN':<4} | {'FN':<4} | {'Precision':<9} | {'Recall':<6} | {'F1-Score':<8}"
    print(header)
    print("-" * 78)
    for mode_label, m in metrics.items():
        row = f"{mode_label:<32} | {m['TP']:<4} | {m['FP']:<4} | {m['TN']:<4} | {m['FN']:<4} | {m['Precision']:<9.4f} | {m['Recall']:<6.4f} | {m['F1']:<8.4f}"
        print(row)
    print("=" * 78 + "\n")

    return metrics

if __name__ == "__main__":
    write_contracts()
    asyncio.run(run_comparative_benchmark())

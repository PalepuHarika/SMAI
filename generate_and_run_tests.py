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
"""
}

def write_contracts():
    base_dir = Path(__file__).parent
    out_dir = base_dir / "contracts" / "test_suite"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in contracts.items():
        with open(out_dir / name, "w", encoding="utf-8") as f:
            f.write(content.strip())

async def scanner():
    import sys
    base_dir = Path(__file__).parent
    sys.path.insert(0, str(base_dir))
    from backend.pipeline import SecurityPipeline
    
    pipeline = SecurityPipeline()
    out_dir = base_dir / "contracts" / "test_suite"
    results = {}
    
    for contract_file in sorted(out_dir.glob("*.sol")):
        print(f"Scanning {contract_file.name}...")
        with open(contract_file, "r", encoding="utf-8") as f:
            source = f.read()
        try:
            report = await pipeline.scan(source, contract_file.name)
            results[contract_file.name] = [f.model_dump() for f in report.findings]
        except Exception as e:
            print(f"Error scanning {contract_file.name}: {e}")
            results[contract_file.name] = {"error": str(e)}
            
    with open(base_dir / "test_suite_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    write_contracts()
    asyncio.run(scanner())

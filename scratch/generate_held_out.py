import os
import json

base_dir = "datasets/held_out"
os.makedirs(base_dir, exist_ok=True)

contracts = {
    "Eval_Reentrancy_01.sol": """
pragma solidity ^0.8.0;
contract Eval_Reentrancy_01 {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send");
        balances[msg.sender] = 0;
    }
}
""",
    "Eval_Safe_01.sol": """
pragma solidity ^0.8.0;
contract Eval_Safe_01 {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender] = 0;
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send");
    }
}
""",
    "Eval_TxOrigin_01.sol": """
pragma solidity ^0.8.0;
contract Eval_TxOrigin_01 {
    address owner;
    constructor() { owner = msg.sender; }
    function withdrawAll(address payable _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(address(this).balance);
    }
}
""",
    "Eval_Timestamp_01.sol": """
pragma solidity ^0.8.0;
contract Eval_Timestamp_01 {
    function play() public payable {
        require(msg.value == 1 ether);
        if (block.timestamp % 15 == 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
""",
    "Eval_UncheckedCall_01.sol": """
pragma solidity ^0.8.0;
contract Eval_UncheckedCall_01 {
    function sendTokens(address target) public {
        target.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 100));
    }
}
""",
    "Eval_MissingAccessControl_01.sol": """
pragma solidity ^0.8.0;
contract Eval_MissingAccessControl_01 {
    address public owner;
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
""",
    "Eval_Safe_MissingAccessControl_02.sol": """
pragma solidity ^0.8.0;
contract Eval_Safe_MissingAccessControl_02 {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
""",
    "Eval_Delegatecall_01.sol": """
pragma solidity ^0.8.0;
contract Eval_Delegatecall_01 {
    function execute(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
""",
    "Eval_Selfdestruct_01.sol": """
pragma solidity ^0.8.0;
contract Eval_Selfdestruct_01 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
""",
    "Eval_Safe_02.sol": """
pragma solidity ^0.8.0;
contract Eval_Safe_02 {
    uint256 public counter;
    // this contract simulates a tx-origin vulnerability but is actually safe
    function increment() public {
        require(msg.sender == tx.origin); // standard anti-contract check
        counter++;
    }
}
"""
}

for name, code in contracts.items():
    with open(os.path.join(base_dir, name), "w") as f:
        f.write(code.strip())

ground_truth = {
    "Eval_Reentrancy_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["reentrancy"],
        "expected_severities": ["High"]
    },
    "Eval_Safe_01.sol": {
        "is_vulnerable": False,
        "expected_vulnerabilities": [],
        "expected_severities": []
    },
    "Eval_TxOrigin_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["tx-origin"],
        "expected_severities": ["High"]
    },
    "Eval_Timestamp_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["timestamp-dependence"],
        "expected_severities": ["Medium"]
    },
    "Eval_UncheckedCall_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["unchecked-call"],
        "expected_severities": ["Medium"]
    },
    "Eval_MissingAccessControl_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["missing-access-control"],
        "expected_severities": ["High"]
    },
    "Eval_Safe_MissingAccessControl_02.sol": {
        "is_vulnerable": False,
        "expected_vulnerabilities": [],
        "expected_severities": []
    },
    "Eval_Delegatecall_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["dangerous-delegatecall"],
        "expected_severities": ["Critical"]
    },
    "Eval_Selfdestruct_01.sol": {
        "is_vulnerable": True,
        "expected_vulnerabilities": ["unprotected-selfdestruct"],
        "expected_severities": ["Critical"]
    },
    "Eval_Safe_02.sol": {
        "is_vulnerable": False,
        "expected_vulnerabilities": [],
        "expected_severities": []
    }
}

with open(os.path.join(base_dir, "ground_truth.json"), "w") as f:
    json.dump(ground_truth, f, indent=2)

print("Generated held-out dataset.")

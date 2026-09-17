import os
import json

def generate_corpus():
    held_out_dir = "datasets/held_out"
    os.makedirs(held_out_dir, exist_ok=True)
    
    contracts = {}
    if os.path.exists(os.path.join(held_out_dir, 'ground_truth.json')):
        with open(os.path.join(held_out_dir, 'ground_truth.json'), 'r') as f:
            ground_truth = json.load(f)
    else:
        ground_truth = {}
    
    def add_contract(name, code, is_vuln, vulns, sevs):
        contracts[name] = code
        ground_truth[name] = {
            "is_vulnerable": is_vuln,
            "expected_vulnerabilities": vulns,
            "expected_severities": sevs
        }

    # 1. SWC-107 Reentrancy (15 vuln, 10 safe)
    for i in range(15):
        add_contract(f"Phase4_Reentrancy_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract ReentrancyVuln{i} {{
    mapping(address => uint) balances{i};
    function withdraw{i}() public {{
        uint bal = balances{i}[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{{value: bal}}("");
        require(success);
        balances{i}[msg.sender] = 0;
    }}
}}
        """, True, ["reentrancy"], ["High"])
        
    for i in range(10):
        add_contract(f"Phase4_Reentrancy_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract ReentrancySafe{i} {{
    mapping(address => uint) balances{i};
    function withdraw{i}() public {{
        uint bal = balances{i}[msg.sender];
        require(bal > 0);
        balances{i}[msg.sender] = 0;
        (bool success, ) = msg.sender.call{{value: bal}}("");
        require(success);
    }}
}}
        """, False, [], [])

    # 2. SWC-104 Unchecked Call (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_UncheckedCall_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract UncheckedCallVuln{i} {{
    function sendTokens{i}(address target) public {{
        target.call(abi.encodeWithSignature("transfer()"));
    }}
}}
        """, True, ["unchecked-call"], ["Medium"])

    for i in range(5):
        add_contract(f"Phase4_UncheckedCall_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract UncheckedCallSafe{i} {{
    function sendTokens{i}(address target) public {{
        (bool success, ) = target.call(abi.encodeWithSignature("transfer()"));
        require(success, "Failed");
    }}
}}
        """, False, [], [])

    # 3. SWC-115 tx.origin (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_TxOrigin_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract TxOriginVuln{i} {{
    address owner;
    function withdrawAll() public {{
        require(tx.origin == owner);
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
        """, True, ["tx-origin"], ["High"])

    for i in range(5):
        add_contract(f"Phase4_TxOrigin_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract TxOriginSafe{i} {{
    address owner;
    function withdrawAll() public {{
        require(msg.sender == owner);
        // tx.origin is intentionally left here in comments to trick regex
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
        """, False, [], [])

    # 4. SWC-116 Timestamp (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_Timestamp_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract TimestampVuln{i} {{
    function play() public {{
        if (block.timestamp % 10 == 0) {{
            payable(msg.sender).transfer(1 ether);
        }}
    }}
}}
        """, True, ["timestamp-dependence"], ["Medium"])
        
    for i in range(5):
        add_contract(f"Phase4_Timestamp_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract TimestampSafe{i} {{
    uint256 lastUpdate;
    function update() public {{
        require(block.timestamp > lastUpdate + 1 days);
        lastUpdate = block.timestamp;
    }}
}}
        """, False, [], [])

    # 5. SWC-106 Unprotected SELFDESTRUCT (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_Selfdestruct_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract SelfdestructVuln{i} {{
    function kill() public {{
        selfdestruct(payable(msg.sender));
    }}
}}
        """, True, ["unprotected-selfdestruct"], ["Critical"])

    for i in range(5):
        add_contract(f"Phase4_Selfdestruct_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract SelfdestructSafe{i} {{
    address owner;
    function kill() public {{
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }}
}}
        """, False, [], [])

    # 6. SWC-112 Dangerous Delegatecall (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_Delegatecall_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract DelegatecallVuln{i} {{
    function proxy(address target, bytes memory data) public {{
        target.delegatecall(data);
    }}
}}
        """, True, ["dangerous-delegatecall"], ["Critical"])

    for i in range(5):
        add_contract(f"Phase4_Delegatecall_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract DelegatecallSafe{i} {{
    address lib;
    function proxy(bytes memory data) public {{
        lib.delegatecall(data); // safe target
    }}
}}
        """, False, [], [])

    # 7. SWC-105 Missing Access Control (10 vuln, 5 safe)
    for i in range(10):
        add_contract(f"Phase4_AccessControl_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract AccessControlVuln{i} {{
    address public owner;
    function setOwner(address newOwner) public {{
        owner = newOwner;
    }}
}}
        """, True, ["missing-access-control"], ["High"])

    for i in range(5):
        add_contract(f"Phase4_AccessControl_Safe_{i}.sol", f"""
pragma solidity ^0.8.0;
contract AccessControlSafe{i} {{
    address public owner;
    function setOwner(address newOwner) internal {{
        owner = newOwner;
    }}
}}
        """, False, [], [])

    # 8. Floating Pragma SWC-103 (5 vuln)
    for i in range(5):
        add_contract(f"Phase4_FloatingPragma_Vuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract FloatingPragmaVuln{i} {{
    uint256 x;
}}
        """, True, ["floating-pragma"], ["Informational"])

    # 9. Multi-vulnerability (10 contracts)
    for i in range(10):
        add_contract(f"Phase4_MultiVuln_{i}.sol", f"""
pragma solidity ^0.8.0;
contract MultiVuln{i} {{
    mapping(address => uint) balances;
    address owner;
    function withdrawAll() public {{
        require(tx.origin == owner); // tx.origin
        uint bal = balances[msg.sender];
        msg.sender.call{{value: bal}}(""); // reentrancy + unchecked
        balances[msg.sender] = 0;
    }}
    function kill() public {{
        selfdestruct(payable(msg.sender)); // selfdestruct
    }}
}}
        """, True, ["tx-origin", "reentrancy", "unchecked-call", "unprotected-selfdestruct"], ["High", "High", "Medium", "Critical"])

    for name, code in contracts.items():
        with open(os.path.join(held_out_dir, name), "w") as f:
            f.write(code.strip())

    with open(os.path.join(held_out_dir, "ground_truth.json"), "w") as f:
        json.dump(ground_truth, f, indent=2)

if __name__ == "__main__":
    generate_corpus()
    print("Corpus generated.")

import json

with open("backend/data/knowledge_base.json", "r", encoding="utf-8") as f:
    data = json.load(f)

new_entries = [
  {
    "id": "SWC-103",
    "name": "Floating Pragma",
    "category": "floating-pragma",
    "severity": "Low",
    "cwe": "CWE-664",
    "description": "Contracts should be deployed with the same compiler version and flags that they have been tested with. Locking the pragma helps to ensure that contracts do not accidentally get deployed using, for example, an outdated compiler version that might introduce bugs that affect the contract system negatively.",
    "exploit_pattern": "Using a floating pragma like ^0.8.0 or >=0.8.0 <0.9.0 allows the contract to be compiled with versions that may contain undiscovered compiler bugs.",
    "mitigation": "Lock the pragma to a specific compiler version, e.g., pragma solidity 0.8.20;",
    "example_vulnerable": "pragma solidity ^0.8.0;\npragma solidity >=0.8.0 <0.9.0;",
    "example_fixed": "pragma solidity 0.8.20;"
  },
  {
    "id": "SWC-117",
    "name": "Signature Malleability / Ecrecover Validation",
    "category": "ecrecover-validation",
    "severity": "High",
    "cwe": "CWE-347",
    "description": "The ecrecover function returns an address recovered from the signature. If the signature is malformed or invalid, ecrecover returns the zero address (address(0)) instead of throwing an error. Failing to check for the zero address can allow attackers to bypass signature validation by providing an invalid signature when the expected signer is set to zero.",
    "exploit_pattern": "Attacker provides an invalid signature. ecrecover returns address(0). If the contract does not explicitly check for address(0), and maps the zero address to a valid state, the check passes.",
    "mitigation": "Always require that the result of ecrecover is not address(0), or use OpenZeppelin's ECDSA library.",
    "example_vulnerable": "address signer = ecrecover(hash, v, r, s);\nrequire(signer == expectedSigner);",
    "example_fixed": "address signer = ecrecover(hash, v, r, s);\nrequire(signer != address(0), 'Invalid signature');\nrequire(signer == expectedSigner);"
  },
  {
    "id": "SWC-101",
    "name": "Integer Overflow and Underflow",
    "category": "integer-overflow",
    "severity": "High",
    "cwe": "CWE-190",
    "description": "An integer overflow or underflow occurs when an arithmetic operation reaches the maximum or minimum size of the type. In Solidity < 0.8.0, this wraps around. In Solidity >= 0.8.0, arithmetic is checked by default and reverts on overflow, unless placed inside an unchecked { ... } block.",
    "exploit_pattern": "Attacker triggers an underflow (e.g., 0 - 1 = 2^256 - 1) to bypass balance checks or mint infinite tokens in Solidity < 0.8.0 or inside unchecked blocks.",
    "mitigation": "Use Solidity 0.8.0 or higher. For older versions, use SafeMath. Do not use unchecked blocks for balances or untrusted input.",
    "example_vulnerable": "unchecked { balances[msg.sender] -= amount; }\n// Or in Solidity 0.7:\nbalances[msg.sender] -= amount;",
    "example_fixed": "// In Solidity 0.8:\nbalances[msg.sender] -= amount;\n// Or using SafeMath in 0.7:\nbalances[msg.sender] = balances[msg.sender].sub(amount);"
  }
]

data.extend(new_entries)

with open("backend/data/knowledge_base.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print("Added SWC-103, SWC-117, SWC-101")

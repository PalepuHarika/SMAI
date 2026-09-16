import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract ReentrancyExpanded {
    mapping(address => uint256) structWrite;
    uint256 public counter;
    
    function test10() public {
        require(msg.sender.call(""));
        uint256 b = 2;
    }
    
    function test12() public {
        msg.sender.call("");
        structWrite[msg.sender] = 1;
    }
}
"""

findings = analyzer.analyze(code, "ReentrancyExpanded")
for f in findings:
    if f.category == "reentrancy":
        print("reentrancy:", f.function)

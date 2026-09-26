import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract ReentrancyExpanded {
      uint256 public counter;
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

findings = analyzer.analyze(code, "ReentrancyExpanded")
for f in findings:
    if f.category == "reentrancy":
        print("reentrancy:", f.function)

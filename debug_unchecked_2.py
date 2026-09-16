import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract UncheckedExpanded {
    function test3(address target) public { bool ok; ok = target.call(""); require(ok); }
}
"""

print(analyzer.analyze(code, "UncheckedExpanded"))

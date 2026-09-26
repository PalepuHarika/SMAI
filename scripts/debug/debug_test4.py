import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract UncheckedExpanded {
    function test4(address target) public { bool ok = target.call(""); if (ok) {} }
}
"""
print(analyzer.analyze(code, "UncheckedExpanded"))

import sys
import uuid
import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract UncheckedExpanded {
    function test1(address target) public { target.call(""); }
    function test2(address target) public { (bool ok, ) = target.call(""); require(ok); }
    function test3(address target) public { bool ok; ok = target.call(""); require(ok); }
    function test4(address target) public { bool ok = target.call(""); if (ok) {} }
    function test5(address target) public { bool ok = target.call(""); assert(ok); }
    function test6(address target) public { bool ok = target.call(""); require(ok); }
    function test7(address target) public { bool ok = target.call(""); if (ok) {} }
    function test8(address target) public returns (bool) { return target.call(""); }
    function test9(address payable target) public { target.send(1); }
    function test10(address payable target) public { require(target.send(1)); }
    function test11(address target) public { target.delegatecall(""); }
    function test12(address target) public { (bool ok, ) = target.delegatecall(""); require(ok); }
}
"""
findings = analyzer.analyze(code, "UncheckedExpanded")
for f in findings:
    print(f.function, f.category)

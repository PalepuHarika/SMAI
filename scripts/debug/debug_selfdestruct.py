import sys
import uuid
import re
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer

analyzer = SolidityStaticAnalyzer()

code = """
pragma solidity ^0.8.0;
contract SelfdestructExpanded {
    address payable owner;
    address payable admin;
    address payable treasury;
    function test1() public { selfdestruct(payable(msg.sender)); }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function test2() public onlyOwner { selfdestruct(owner); }
    modifier onlyAdmin() { require(msg.sender == admin); _; }
    function test3() public onlyAdmin { selfdestruct(admin); }
    modifier onlyTreasury() { require(msg.sender == treasury); _; }
    function test4() public onlyTreasury { selfdestruct(treasury); }
    modifier myAuth() { require(msg.sender == owner); _; }
    function test5() public myAuth { selfdestruct(owner); }
    modifier myNoAuth() { _; }
    function test6() public myNoAuth { selfdestruct(payable(msg.sender)); }
    function test7() public { require(msg.sender == owner); selfdestruct(owner); }
    function test8() public { require(tx.origin == owner); selfdestruct(owner); }
    function _auth() internal { require(msg.sender == owner); }
    function test9() public { _auth(); selfdestruct(owner); }
    function test10() public { { selfdestruct(payable(msg.sender)); } }
    function test11() public { // selfdestruct(owner);
    }
}
"""
findings = analyzer.analyze(code, "SelfdestructExpanded")
for f in findings:
    print(f.function, f.category)

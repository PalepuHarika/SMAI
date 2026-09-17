pragma solidity ^0.8.0;
contract Eval_Safe_MissingAccessControl_02 {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
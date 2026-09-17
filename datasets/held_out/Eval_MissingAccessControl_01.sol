pragma solidity ^0.8.0;
contract Eval_MissingAccessControl_01 {
    address public owner;
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
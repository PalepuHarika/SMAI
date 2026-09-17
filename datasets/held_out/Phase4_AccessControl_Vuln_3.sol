pragma solidity ^0.8.0;
contract AccessControlVuln3 {
    address public owner;
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
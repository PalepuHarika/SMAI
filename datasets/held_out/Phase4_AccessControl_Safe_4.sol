pragma solidity ^0.8.0;
contract AccessControlSafe4 {
    address public owner;
    function setOwner(address newOwner) internal {
        owner = newOwner;
    }
}
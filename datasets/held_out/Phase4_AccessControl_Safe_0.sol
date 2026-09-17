pragma solidity ^0.8.0;
contract AccessControlSafe0 {
    address public owner;
    function setOwner(address newOwner) internal {
        owner = newOwner;
    }
}
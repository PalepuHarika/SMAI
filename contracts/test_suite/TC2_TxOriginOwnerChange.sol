pragma solidity ^0.8.0;
contract TxOriginOwnerChange {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
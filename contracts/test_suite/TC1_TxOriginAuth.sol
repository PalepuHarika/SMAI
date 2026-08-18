pragma solidity ^0.8.0;
contract TxOriginAuth {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw(uint256 amount, address payable recipient) external {
        require(tx.origin == owner, "Not owner");
        recipient.transfer(amount);
    }
}
pragma solidity ^0.8.0;
contract SafeAccessControl {
    uint256 public fee;
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
}
pragma solidity ^0.8.0;
contract MissingAccessControl {
    uint256 public fee;
    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
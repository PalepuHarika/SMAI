pragma solidity ^0.8.0;
contract TimestampEquality {
    uint256 public targetTime;
    constructor(uint256 _t) { targetTime = _t; }
    function execute() external view {
        require(block.timestamp == targetTime, "Not exact time");
    }
}
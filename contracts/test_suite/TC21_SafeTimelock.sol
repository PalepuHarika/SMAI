pragma solidity ^0.8.0;
contract SafeTimelock {
    uint256 public releaseTime;
    constructor(uint256 _t) { releaseTime = _t; }
    function withdraw() external view {
        require(block.timestamp >= releaseTime, "Timelock active");
    }
}
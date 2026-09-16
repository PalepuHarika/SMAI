pragma solidity ^0.8.0;
contract TimestampRandomness {
    function lottery() external view returns (uint256) {
        return block.timestamp % 10;
    }
}
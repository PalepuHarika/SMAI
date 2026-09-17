pragma solidity ^0.8.0;
contract TimestampSafe4 {
    uint256 lastUpdate;
    function update() public {
        require(block.timestamp > lastUpdate + 1 days);
        lastUpdate = block.timestamp;
    }
}
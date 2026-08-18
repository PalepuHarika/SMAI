pragma solidity ^0.8.0;
contract Decoy {
    // vulnerable reentrancy example
    string public vulnerability = "tx.origin";
    
    function doNothing() external pure returns (uint256) {
        return 42;
    }
}
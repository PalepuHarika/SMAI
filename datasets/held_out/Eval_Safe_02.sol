pragma solidity ^0.8.0;
contract Eval_Safe_02 {
    uint256 public counter;
    // this contract simulates a tx-origin vulnerability but is actually safe
    function increment() public {
        require(msg.sender == tx.origin); // standard anti-contract check
        counter++;
    }
}
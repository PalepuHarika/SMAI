pragma solidity ^0.8.0;
contract TxOriginFalsePositive {
    event UserAction(address origin);
    function recordAction() external {
        emit UserAction(tx.origin);
    }
}
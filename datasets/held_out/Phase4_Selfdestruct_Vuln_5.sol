pragma solidity ^0.8.0;
contract SelfdestructVuln5 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
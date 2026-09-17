pragma solidity ^0.8.0;
contract SelfdestructVuln2 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
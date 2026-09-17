pragma solidity ^0.8.0;
contract SelfdestructVuln0 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
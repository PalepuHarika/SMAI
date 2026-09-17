pragma solidity ^0.8.0;
contract SelfdestructVuln6 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
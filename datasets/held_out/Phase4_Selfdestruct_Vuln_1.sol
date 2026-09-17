pragma solidity ^0.8.0;
contract SelfdestructVuln1 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
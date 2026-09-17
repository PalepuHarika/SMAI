pragma solidity ^0.8.0;
contract SelfdestructSafe4 {
    address owner;
    function kill() public {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}
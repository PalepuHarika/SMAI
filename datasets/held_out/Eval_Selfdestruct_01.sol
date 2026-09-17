pragma solidity ^0.8.0;
contract Eval_Selfdestruct_01 {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
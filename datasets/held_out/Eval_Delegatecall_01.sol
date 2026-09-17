pragma solidity ^0.8.0;
contract Eval_Delegatecall_01 {
    function execute(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
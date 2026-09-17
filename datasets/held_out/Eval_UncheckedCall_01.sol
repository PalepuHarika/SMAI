pragma solidity ^0.8.0;
contract Eval_UncheckedCall_01 {
    function sendTokens(address target) public {
        target.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, 100));
    }
}
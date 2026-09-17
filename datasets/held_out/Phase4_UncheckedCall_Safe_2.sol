pragma solidity ^0.8.0;
contract UncheckedCallSafe2 {
    function sendTokens2(address target) public {
        (bool success, ) = target.call(abi.encodeWithSignature("transfer()"));
        require(success, "Failed");
    }
}
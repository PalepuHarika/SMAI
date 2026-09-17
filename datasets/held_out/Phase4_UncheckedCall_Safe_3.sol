pragma solidity ^0.8.0;
contract UncheckedCallSafe3 {
    function sendTokens3(address target) public {
        (bool success, ) = target.call(abi.encodeWithSignature("transfer()"));
        require(success, "Failed");
    }
}
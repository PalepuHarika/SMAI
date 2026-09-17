pragma solidity ^0.8.0;
contract UncheckedCallSafe0 {
    function sendTokens0(address target) public {
        (bool success, ) = target.call(abi.encodeWithSignature("transfer()"));
        require(success, "Failed");
    }
}
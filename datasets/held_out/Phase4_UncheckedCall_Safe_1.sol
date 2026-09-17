pragma solidity ^0.8.0;
contract UncheckedCallSafe1 {
    function sendTokens1(address target) public {
        (bool success, ) = target.call(abi.encodeWithSignature("transfer()"));
        require(success, "Failed");
    }
}
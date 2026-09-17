pragma solidity ^0.8.0;
contract UncheckedCallVuln7 {
    function sendTokens7(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
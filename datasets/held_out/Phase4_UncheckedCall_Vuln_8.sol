pragma solidity ^0.8.0;
contract UncheckedCallVuln8 {
    function sendTokens8(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
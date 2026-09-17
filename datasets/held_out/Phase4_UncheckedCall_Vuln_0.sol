pragma solidity ^0.8.0;
contract UncheckedCallVuln0 {
    function sendTokens0(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
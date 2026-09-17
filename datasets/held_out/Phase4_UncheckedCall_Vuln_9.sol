pragma solidity ^0.8.0;
contract UncheckedCallVuln9 {
    function sendTokens9(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
pragma solidity ^0.8.0;
contract UncheckedCallVuln2 {
    function sendTokens2(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
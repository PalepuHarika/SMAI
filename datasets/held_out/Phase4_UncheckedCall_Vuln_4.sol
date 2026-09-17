pragma solidity ^0.8.0;
contract UncheckedCallVuln4 {
    function sendTokens4(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
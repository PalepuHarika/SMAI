pragma solidity ^0.8.0;
contract UncheckedCallVuln6 {
    function sendTokens6(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
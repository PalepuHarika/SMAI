pragma solidity ^0.8.0;
contract UncheckedCallVuln5 {
    function sendTokens5(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
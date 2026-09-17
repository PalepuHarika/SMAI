pragma solidity ^0.8.0;
contract UncheckedCallVuln3 {
    function sendTokens3(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
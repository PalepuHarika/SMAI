pragma solidity ^0.8.0;
contract UncheckedCallVuln1 {
    function sendTokens1(address target) public {
        target.call(abi.encodeWithSignature("transfer()"));
    }
}
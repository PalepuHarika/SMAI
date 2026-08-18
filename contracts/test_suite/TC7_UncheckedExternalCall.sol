pragma solidity ^0.8.0;
contract UncheckedExternalCall {
    function sendEther(address target) external {
        target.call{value: 1 ether}("");
    }
}
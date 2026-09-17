pragma solidity ^0.8.0;
contract DelegatecallVuln7 {
    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
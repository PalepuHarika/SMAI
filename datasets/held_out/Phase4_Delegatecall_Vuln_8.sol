pragma solidity ^0.8.0;
contract DelegatecallVuln8 {
    function proxy(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
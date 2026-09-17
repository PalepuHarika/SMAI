pragma solidity ^0.8.0;
contract DelegatecallSafe0 {
    address lib;
    function proxy(bytes memory data) public {
        lib.delegatecall(data); // safe target
    }
}
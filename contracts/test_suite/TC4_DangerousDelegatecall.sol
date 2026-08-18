pragma solidity ^0.8.0;
contract DangerousDelegatecall {
    function execute(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Failed");
    }
}
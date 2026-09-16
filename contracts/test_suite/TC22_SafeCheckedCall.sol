pragma solidity ^0.8.0;
contract SafeCheckedCall {
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        require(success, "External call failed");
    }
}
pragma solidity ^0.8.0;
contract SafeDelegatecall {
    address public immutable trustedTarget;
    constructor(address _target) { trustedTarget = _target; }
    function execute(bytes memory data) external {
        (bool success, ) = trustedTarget.delegatecall(data);
        require(success, "Failed");
    }
}
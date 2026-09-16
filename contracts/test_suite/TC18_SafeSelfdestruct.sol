pragma solidity ^0.8.0;
contract SafeSelfdestruct {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
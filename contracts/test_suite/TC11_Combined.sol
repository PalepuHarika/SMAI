pragma solidity ^0.8.0;
contract Combined {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public fee;
    
    constructor() { owner = msg.sender; }
    
    function withdrawAll(address target, bytes memory data) external {
        require(tx.origin == owner, "Not owner"); // 1. tx.origin
        
        (bool success1, ) = target.delegatecall(data); // 3. delegatecall
        require(success1, "fail");
        
        uint256 amount = balances[msg.sender];
        (bool success2, ) = msg.sender.call{value: amount}(""); // 2. reentrancy
        require(success2, "fail");
        balances[msg.sender] = 0;
    }
    
    function setFee(uint256 newFee) external { // 5. access control
        fee = newFee;
    }
}
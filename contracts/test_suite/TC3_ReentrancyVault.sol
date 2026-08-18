pragma solidity ^0.8.0;
contract ReentrancyVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
    }
}
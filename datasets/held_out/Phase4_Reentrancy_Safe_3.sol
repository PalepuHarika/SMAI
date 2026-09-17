pragma solidity ^0.8.0;
contract ReentrancySafe3 {
    mapping(address => uint) balances3;
    function withdraw3() public {
        uint bal = balances3[msg.sender];
        require(bal > 0);
        balances3[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
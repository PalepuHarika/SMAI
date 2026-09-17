pragma solidity ^0.8.0;
contract ReentrancyVuln3 {
    mapping(address => uint) balances3;
    function withdraw3() public {
        uint bal = balances3[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances3[msg.sender] = 0;
    }
}
pragma solidity ^0.8.0;
contract ReentrancyVuln1 {
    mapping(address => uint) balances1;
    function withdraw1() public {
        uint bal = balances1[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances1[msg.sender] = 0;
    }
}
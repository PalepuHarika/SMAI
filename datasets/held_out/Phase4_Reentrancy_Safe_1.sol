pragma solidity ^0.8.0;
contract ReentrancySafe1 {
    mapping(address => uint) balances1;
    function withdraw1() public {
        uint bal = balances1[msg.sender];
        require(bal > 0);
        balances1[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
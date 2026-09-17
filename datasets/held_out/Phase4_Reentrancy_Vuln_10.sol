pragma solidity ^0.8.0;
contract ReentrancyVuln10 {
    mapping(address => uint) balances10;
    function withdraw10() public {
        uint bal = balances10[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances10[msg.sender] = 0;
    }
}
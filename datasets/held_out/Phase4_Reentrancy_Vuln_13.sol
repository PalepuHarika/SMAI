pragma solidity ^0.8.0;
contract ReentrancyVuln13 {
    mapping(address => uint) balances13;
    function withdraw13() public {
        uint bal = balances13[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances13[msg.sender] = 0;
    }
}
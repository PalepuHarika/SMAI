pragma solidity ^0.8.0;
contract ReentrancyVuln0 {
    mapping(address => uint) balances0;
    function withdraw0() public {
        uint bal = balances0[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances0[msg.sender] = 0;
    }
}
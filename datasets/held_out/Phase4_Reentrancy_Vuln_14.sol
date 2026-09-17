pragma solidity ^0.8.0;
contract ReentrancyVuln14 {
    mapping(address => uint) balances14;
    function withdraw14() public {
        uint bal = balances14[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances14[msg.sender] = 0;
    }
}
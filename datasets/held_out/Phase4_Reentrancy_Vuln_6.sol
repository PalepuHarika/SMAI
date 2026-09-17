pragma solidity ^0.8.0;
contract ReentrancyVuln6 {
    mapping(address => uint) balances6;
    function withdraw6() public {
        uint bal = balances6[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances6[msg.sender] = 0;
    }
}
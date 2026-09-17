pragma solidity ^0.8.0;
contract ReentrancyVuln11 {
    mapping(address => uint) balances11;
    function withdraw11() public {
        uint bal = balances11[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances11[msg.sender] = 0;
    }
}
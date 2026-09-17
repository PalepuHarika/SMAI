pragma solidity ^0.8.0;
contract ReentrancyVuln4 {
    mapping(address => uint) balances4;
    function withdraw4() public {
        uint bal = balances4[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances4[msg.sender] = 0;
    }
}
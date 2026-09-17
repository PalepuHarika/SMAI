pragma solidity ^0.8.0;
contract ReentrancyVuln2 {
    mapping(address => uint) balances2;
    function withdraw2() public {
        uint bal = balances2[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances2[msg.sender] = 0;
    }
}
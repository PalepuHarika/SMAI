pragma solidity ^0.8.0;
contract ReentrancyVuln12 {
    mapping(address => uint) balances12;
    function withdraw12() public {
        uint bal = balances12[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances12[msg.sender] = 0;
    }
}
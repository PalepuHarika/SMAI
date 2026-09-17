pragma solidity ^0.8.0;
contract ReentrancyVuln8 {
    mapping(address => uint) balances8;
    function withdraw8() public {
        uint bal = balances8[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances8[msg.sender] = 0;
    }
}
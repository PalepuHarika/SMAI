pragma solidity ^0.8.0;
contract ReentrancySafe0 {
    mapping(address => uint) balances0;
    function withdraw0() public {
        uint bal = balances0[msg.sender];
        require(bal > 0);
        balances0[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
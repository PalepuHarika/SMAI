pragma solidity ^0.8.0;
contract ReentrancySafe8 {
    mapping(address => uint) balances8;
    function withdraw8() public {
        uint bal = balances8[msg.sender];
        require(bal > 0);
        balances8[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
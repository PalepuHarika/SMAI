pragma solidity ^0.8.0;
contract ReentrancySafe9 {
    mapping(address => uint) balances9;
    function withdraw9() public {
        uint bal = balances9[msg.sender];
        require(bal > 0);
        balances9[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
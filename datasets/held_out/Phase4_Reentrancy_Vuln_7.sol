pragma solidity ^0.8.0;
contract ReentrancyVuln7 {
    mapping(address => uint) balances7;
    function withdraw7() public {
        uint bal = balances7[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances7[msg.sender] = 0;
    }
}
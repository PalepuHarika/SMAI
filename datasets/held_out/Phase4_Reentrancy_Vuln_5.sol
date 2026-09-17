pragma solidity ^0.8.0;
contract ReentrancyVuln5 {
    mapping(address => uint) balances5;
    function withdraw5() public {
        uint bal = balances5[msg.sender];
        require(bal > 0);
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
        balances5[msg.sender] = 0;
    }
}
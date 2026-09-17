pragma solidity ^0.8.0;
contract ReentrancySafe5 {
    mapping(address => uint) balances5;
    function withdraw5() public {
        uint bal = balances5[msg.sender];
        require(bal > 0);
        balances5[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}
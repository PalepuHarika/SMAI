pragma solidity ^0.8.0;
contract Eval_Safe_01 {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender] = 0;
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send");
    }
}
pragma solidity ^0.8.0;
contract MultiVuln1 {
    mapping(address => uint) balances;
    address owner;
    function withdrawAll() public {
        require(tx.origin == owner); // tx.origin
        uint bal = balances[msg.sender];
        msg.sender.call{value: bal}(""); // reentrancy + unchecked
        balances[msg.sender] = 0;
    }
    function kill() public {
        selfdestruct(payable(msg.sender)); // selfdestruct
    }
}
pragma solidity ^0.8.0;
contract Eval_TxOrigin_01 {
    address owner;
    constructor() { owner = msg.sender; }
    function withdrawAll(address payable _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(address(this).balance);
    }
}
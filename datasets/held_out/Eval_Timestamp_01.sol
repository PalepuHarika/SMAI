pragma solidity ^0.8.0;
contract Eval_Timestamp_01 {
    function play() public payable {
        require(msg.value == 1 ether);
        if (block.timestamp % 15 == 0) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}
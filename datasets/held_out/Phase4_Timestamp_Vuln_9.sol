pragma solidity ^0.8.0;
contract TimestampVuln9 {
    function play() public {
        if (block.timestamp % 10 == 0) {
            payable(msg.sender).transfer(1 ether);
        }
    }
}
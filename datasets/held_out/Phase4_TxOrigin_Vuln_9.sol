pragma solidity ^0.8.0;
contract TxOriginVuln9 {
    address owner;
    function withdrawAll() public {
        require(tx.origin == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
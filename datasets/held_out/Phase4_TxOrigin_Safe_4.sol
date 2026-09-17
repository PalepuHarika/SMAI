pragma solidity ^0.8.0;
contract TxOriginSafe4 {
    address owner;
    function withdrawAll() public {
        require(msg.sender == owner);
        // tx.origin is intentionally left here in comments to trick regex
        payable(msg.sender).transfer(address(this).balance);
    }
}
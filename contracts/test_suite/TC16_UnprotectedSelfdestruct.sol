pragma solidity ^0.8.0;
contract UnprotectedSelfdestruct {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
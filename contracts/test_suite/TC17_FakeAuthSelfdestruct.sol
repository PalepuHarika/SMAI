pragma solidity ^0.8.0;
contract FakeAuthSelfdestruct {
    function destroy(uint256 amount) external {
        require(amount > 0, "Amount must be positive");
        selfdestruct(payable(msg.sender));
    }
}
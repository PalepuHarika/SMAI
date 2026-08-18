pragma solidity ^0.8.0;
contract Hallucination {
    address public admin;
    constructor() { admin = msg.sender; }
    function changeAdmin(address newAdmin) external {
        require(tx.origin == admin, "Not admin");
        admin = newAdmin;
    }
}
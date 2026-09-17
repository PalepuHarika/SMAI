import asyncio
from backend.pipeline import SecurityPipeline

async def main():
    p = SecurityPipeline()
    code = """pragma solidity 0.8.24;
contract SafeVault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}"""
    print(await p.scan(code, 'SafeVault.sol', 'C'))

asyncio.run(main())

import asyncio
from backend.pipeline import SecurityPipeline

async def main():
    p = SecurityPipeline()
    code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] -= amount;
    }
}
"""
    r = await p.scan(code, 'Vault.sol', mode='C')
    print('Scan finished.')
    print('Total findings:', len(r.findings))
    print('Score:', r.security_score, 'Risk:', r.risk_level)
    for f in r.findings:
        print(f"[{f.severity}] {f.vulnerability} -> Status: {f.verification_status}, Fix verified: {f.fix_verified}, Fixed code: {f.fixed_code[:40] if f.fixed_code else 'None'}")
    if r.corrected_contract:
        print("Corrected contract generated! Length:", len(r.corrected_contract))
    else:
        print("No corrected contract.")

if __name__ == "__main__":
    asyncio.run(main())

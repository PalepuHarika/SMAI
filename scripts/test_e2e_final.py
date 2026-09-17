"""
E2E test that properly waits for the async pipeline to complete.
Polls every 2s with a 120s timeout per contract.
"""
import asyncio
import time
import uuid
import httpx


BASE = "http://localhost:8001"


async def register_and_login(client: httpx.AsyncClient) -> str:
    email = f"test_{uuid.uuid4().hex[:6]}@smai.test"
    reg = await client.post(f"{BASE}/auth/register",
                            json={"email": email, "password": "password123"},
                            headers={"Content-Type": "application/json"})
    data = reg.json()
    token = data.get("access_token") or data.get("detail", "")
    if not data.get("access_token"):
        print(f"Register failed: {data}")
        raise SystemExit(1)
    return token


async def run_contract(client: httpx.AsyncClient, name: str, code: str) -> None:
    print(f"\n{'='*50}")
    print(f"TEST: {name}")
    print('='*50)

    t0 = time.time()
    resp = await client.post(f"{BASE}/api/analysis",
                             json={"contract_name": name, "source_code": code, "mode": "C"})
    resp.raise_for_status()
    analysis_id = resp.json()["analysis_id"]
    print(f"Analysis ID: {analysis_id}")

    # Poll until completed or failed (max 120s)
    deadline = time.time() + 120
    while time.time() < deadline:
        await asyncio.sleep(2)
        r = await client.get(f"{BASE}/api/analysis/{analysis_id}")
        data = r.json()
        status = data.get("status")
        if status == "PENDING":
            print(f"  … still pending ({int(time.time()-t0)}s)")
            continue
        if status == "FAILED":
            print(f"  ✗ Pipeline reported FAILED after {time.time()-t0:.1f}s")
            return
        # COMPLETED — data is the full report
        break
    else:
        print("  ✗ Timed out waiting for analysis")
        return

    elapsed = time.time() - t0
    print(f"Execution Time: {elapsed:.2f}s")
    print(f"Security Score: {data.get('security_score', 'N/A')}")
    print(f"Risk Level:     {data.get('risk_level', 'N/A')}")
    findings = data.get("findings", [])
    if not findings:
        print("Static Findings: NONE (safe contract — no issues detected)")
    else:
        print(f"Static Findings: {len(findings)} found")
        for f in findings:
            print(f"\n  ► {f['vulnerability']} ({f.get('swc_id','?')})")
            print(f"    Severity:    {f['severity']}")
            rag = f.get("retrieved_knowledge", [])
            if rag:
                print(f"    RAG:         {len(rag)} chunk(s), top match: {rag[0].get('name','?')}")
            else:
                print("    RAG:         none")
            print(f"    AI Status:   {f.get('verification_status','?')}")
            print(f"    Confidence:  {f.get('confidence','?')}")


async def main():
    print("Verifying services...")
    async with httpx.AsyncClient(timeout=600.0) as client:
        # Check Ollama
        v = await client.get("http://localhost:11434/api/version")
        print(f"  Ollama: {v.json()['version']}")

        # Check Backend
        bk = await client.get(f"{BASE}/docs")
        print(f"  Backend: HTTP {bk.status_code}")

        token = await register_and_login(client)
        client.headers["Authorization"] = f"Bearer {token}"

        safe = """pragma solidity 0.8.24;
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

        reentrancy = """pragma solidity ^0.8.0;
contract ReentrancyTest {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}"""

        multi = """pragma solidity ^0.8.0;
contract MultiVuln {
    mapping(address => uint) balances;
    address public owner;
    constructor() { owner = msg.sender; }
    function withdrawAll() public {
        require(tx.origin == owner);
        uint bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}"""

        await run_contract(client, "SafeVault.sol", safe)
        await run_contract(client, "ReentrancyTest.sol", reentrancy)
        await run_contract(client, "MultiVuln.sol", multi)

    print("\n\nDONE")


if __name__ == "__main__":
    asyncio.run(main())

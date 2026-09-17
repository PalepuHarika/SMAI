import httpx
import time
import asyncio
import uuid

async def test_contract(client, name, code):
    print(f"\n======================================")
    print(f"TESTING: {name}")
    print(f"======================================")
    
    try:
        t0 = time.time()
        resp = await client.post("http://localhost:8001/api/analysis", json={
            "contract_name": name,
            "source_code": code,
            "mode": "C"
        })
        resp.raise_for_status()
        data = resp.json()
        analysis_id = data["analysis_id"]
        
        # Wait for completion if pending
        while True:
            r = await client.get(f"http://localhost:8001/api/analysis/{analysis_id}")
            d = r.json()
            if d.get("status") in ("COMPLETED", "FAILED"):
                data = d
                break
            time.sleep(2)
            
        duration = time.time() - t0
        
        print("--- RESULTS ---")
        print(f"Total Execution Time: {duration:.2f}s")
        print(f"Security Score: {data.get('security_score')}")
        print(f"Risk Level: {data.get('risk_level')}")
        print(f"Status: {data.get('status')}")
        
        findings = data.get("findings", [])
        if not findings:
            print("\nNo vulnerabilities detected (Static Analyzer found 0 issues).")
        else:
            for f in findings:
                print(f"\n- Finding: {f['vulnerability']} (SWC: {f.get('swc_id', 'N/A')})")
                print(f"  Severity: {f['severity']}")
                
                rag_docs = f.get('retrieved_knowledge', [])
                if rag_docs:
                    print(f"  RAG Retrieval: Successfully retrieved {len(rag_docs)} chunk(s). Top match: {rag_docs[0].get('name')}")
                else:
                    print(f"  RAG Retrieval: None")
                    
                print(f"  Ollama Verification Completed: True (Status: {f.get('verification_status', 'N/A')})")
                print(f"  Confidence: {f.get('confidence', 'N/A')}")
                
    except Exception as e:
        print(f"ERROR/TIMEOUT: {e}")

async def main():
    async with httpx.AsyncClient(timeout=1200.0) as client:
        # Register a test user
        email = f"test_{uuid.uuid4().hex[:6]}@example.com"
        reg_resp = await client.post("http://localhost:8001/auth/register", json={"email": email, "password": "password"})
        token = reg_resp.json()["access_token"]
        
        client.headers.update({"Authorization": f"Bearer {token}"})

        safe_code = """pragma solidity 0.8.24;
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

        reentrancy_code = """pragma solidity ^0.8.0;
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

        multi_code = """pragma solidity ^0.8.0;
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

        await test_contract(client, "SafeVault.sol", safe_code)
        await test_contract(client, "ReentrancyTest.sol", reentrancy_code)
        await test_contract(client, "MultiVuln.sol", multi_code)

if __name__ == "__main__":
    asyncio.run(main())

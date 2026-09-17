"""
Script to test the 3 Analysis Modes on ReentrancyVault.sol via the real running API.
- Mode 'rag': RAG Only (no Ollama call, RAG knowledge attached)
- Mode 'ai': AI Only (Ollama called, RAG knowledge empty)
- Mode 'hybrid': RAG + AI (Ollama called with RAG context)
"""
import httpx
import time
import uuid

API_BASE = "http://localhost:8001"

def test_modes():
    # 1. Register test user
    email = f"mode_test_{uuid.uuid4().hex[:6]}@example.com"
    reg = httpx.post(f"{API_BASE}/auth/register", json={"email": email, "password": "password123"}, timeout=10.0)
    assert reg.status_code == 201, f"Registration failed: {reg.text}"
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    with open("contracts/ReentrancyVault.sol", "r") as f:
        source_code = f.read()

    modes = [
        ("RAG ONLY", "rag"),
        ("AI ONLY", "ai"),
        ("RAG + AI (HYBRID)", "hybrid")
    ]

    for label, mode_val in modes:
        print(f"\n==========================================")
        print(f" TESTING MODE: {label} (mode='{mode_val}')")
        print(f"==========================================")

        sub = httpx.post(
            f"{API_BASE}/api/analysis",
            json={"contract_name": "ReentrancyVault.sol", "source_code": source_code, "mode": mode_val},
            headers=headers,
            timeout=10.0
        )
        print(f"HTTP Submit Status: {sub.status_code}")
        assert sub.status_code == 202, f"Submit failed: {sub.text}"
        aid = sub.json()["analysis_id"]

        print(f"Analysis ID: {aid}")
        print("Polling for completion...")

        start_time = time.time()
        completed = False
        while time.time() - start_time < 300: # 5 minute timeout per test
            time.sleep(2)
            res = httpx.get(f"{API_BASE}/api/analysis/{aid}", headers=headers, timeout=10.0)
            data = res.json()
            if data.get("status") in ["PENDING"]:
                continue
            elif data.get("status") == "FAILED":
                print(f"FAILED: {data}")
                break
            else:
                completed = True
                elapsed = time.time() - start_time
                print(f"Finished in {elapsed:.1f}s")
                print(f"Security Score: {data.get('security_score')}")
                print(f"Risk Level: {data.get('risk_level')}")
                print(f"Total Findings: {data.get('total_findings')}")

                findings = data.get("findings", [])
                for idx, f in enumerate(findings):
                    print(f"\n--- Finding {idx+1} ---")
                    print(f"Category: {f.get('vulnerability')} (SWC: {f.get('swc_id')})")
                    print(f"Severity: {f.get('severity')}")
                    print(f"Verification Status: {f.get('verification_status')}")
                    print(f"Is Vulnerable: {f.get('is_vulnerable')}")
                    print(f"Model Used: {f.get('model_used')}")
                    print(f"Confidence: {f.get('confidence')}")

                    rag_items = f.get("retrieved_knowledge") or []
                    print(f"RAG Items Count: {len(rag_items)}")
                    if rag_items:
                        print(f"RAG Item 1 ID/Title: {rag_items[0].get('id', rag_items[0].get('vulnerability', 'N/A'))}")

                    print(f"Explanation: {f.get('explanation')[:120]}...")
                break

        if not completed:
            print("TIMED OUT polling analysis status")

if __name__ == "__main__":
    test_modes()

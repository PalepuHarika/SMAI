"""
E2E test: verify sequential pipeline with real Ollama via API.
Tests SafeVault, Reentrancy, MultiVulnerable.
"""
import httpx
import time
import uuid
import json

API_BASE = "http://localhost:8001"

def run():
    email = f"e2e_{uuid.uuid4().hex[:6]}@test.com"
    r = httpx.post(f"{API_BASE}/auth/register", json={"email": email, "password": "pass12345"})
    assert r.status_code == 201, f"Registration failed: {r.text}"
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    contracts = [
        ("SafeVault", "contracts/CleanSafeVault.sol"),
        ("Reentrancy", "contracts/ReentrancyVault.sol"),
        ("MultiVulnerable", "contracts/test_suite/TC11_Combined.sol"),
    ]

    for name, path in contracts:
        print(f"\n{'='*60}")
        print(f"CONTRACT: {name}")
        print(f"{'='*60}")
        with open(path) as f:
            code = f.read()

        r = httpx.post(
            f"{API_BASE}/api/analysis",
            json={"contract_name": f"{name}.sol", "source_code": code, "mode": "C"},
            headers=headers, timeout=30.0
        )
        assert r.status_code == 202, f"Submit failed: {r.text}"
        aid = r.json()["analysis_id"]
        print(f"Analysis ID: {aid}")
        print("Polling for result (sequential Ollama, may take a while)...")

        start = time.time()
        status = "PENDING"
        for _ in range(600):  # up to 20 minutes
            time.sleep(2)
            p = httpx.get(f"{API_BASE}/api/analysis/{aid}", headers=headers, timeout=30.0)
            data = p.json()
            if data.get("status") in ("PENDING",):
                elapsed = time.time() - start
                if int(elapsed) % 20 == 0:
                    print(f"  Still running... {elapsed:.0f}s")
                continue
            elif data.get("status") == "FAILED":
                print(f"RESULT: FAILED after {time.time()-start:.1f}s")
                status = "FAILED"
                break
            else:
                status = "COMPLETED"
                elapsed = time.time() - start
                print(f"RESULT: COMPLETED in {elapsed:.1f}s")
                findings = data.get("findings", [])
                print(f"Total findings: {len(findings)}")
                for f in findings:
                    print(f"  - Category: {f.get('category')} | SWC: {f.get('swc_id')} | Severity: {f.get('severity')}")
                    print(f"    is_vulnerable={f.get('is_vulnerable')} | status={f.get('verification_status')} | confidence={f.get('confidence'):.3f}")
                    print(f"    fallback_used={f.get('fallback_used')} | model_used={f.get('model_used')}")
                    rag = f.get("retrieved_knowledge") or []
                    print(f"    RAG entries retrieved: {len(rag)}")
                print(f"\nSecurity Score: {data.get('security_score')}/100")
                print(f"Risk Level: {data.get('risk_level')}")
                print(f"Summary: {data.get('summary','')[:120]}")
                break
        else:
            print("TIMED OUT")

if __name__ == "__main__":
    run()

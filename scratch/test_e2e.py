import httpx
import time
import json
import uuid

API_BASE = "http://localhost:8001"

def run_tests():
    # 1. Register a temporary user
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    password = "password123"
    
    print(f"Registering user {email}...")
    reg_res = httpx.post(f"{API_BASE}/auth/register", json={"email": email, "password": password})
    if reg_res.status_code != 201:
        print("Registration failed:", reg_res.text)
        return
        
    token = reg_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    contracts = {
        "SafeVault": "contracts/CleanSafeVault.sol",
        "Reentrancy": "contracts/ReentrancyVault.sol",
        "MultiVulnerable": "contracts/test_suite/TC11_Combined.sol"
    }
    
    for name, path in contracts.items():
        print(f"\n--- Testing {name} ({path}) ---")
        try:
            with open(path, "r") as f:
                source_code = f.read()
        except FileNotFoundError:
            print(f"File {path} not found!")
            continue
            
        print("Submitting for analysis...")
        scan_req = httpx.post(
            f"{API_BASE}/api/analysis",
            json={"contract_name": name + ".sol", "source_code": source_code, "mode": "C"},
            headers=headers,
            timeout=30.0
        )
        
        if scan_req.status_code != 202:
            print("Failed to submit:", scan_req.text)
            continue
            
        analysis_id = scan_req.json()["analysis_id"]
        print(f"Analysis started. ID: {analysis_id}")
        
        # Poll for results
        status = "PENDING"
        for i in range(120): # wait up to 240 seconds
            time.sleep(2)
            poll_res = httpx.get(f"{API_BASE}/api/analysis/{analysis_id}", headers=headers, timeout=30.0)
            if poll_res.status_code != 200:
                print(f"Polling error: {poll_res.status_code} - {poll_res.text}")
                break
                
            data = poll_res.json()
            if "status" in data and data["status"] in ["PENDING", "FAILED"]:
                status = data["status"]
                if status == "FAILED":
                    print("Analysis FAILED.")
                    break
            else:
                status = "COMPLETED"
                # Parse and print results
                print("Analysis COMPLETED.")
                
                # Report formatting
                print("=== FINDINGS ===")
                findings = data.get("findings", [])
                if not findings:
                    print("No findings.")
                for f in findings:
                    print(f"- Category: {f.get('category')} (SWC: {f.get('swc_id')})")
                    print(f"  Severity: {f.get('severity')}")
                    print(f"  Static Finding: {f.get('message')}")
                    
                    print(f"  AI Verification Result (Vulnerable?): {f.get('is_vulnerable')}")
                    print(f"  Confidence: {f.get('confidence')}")
                    # If there's rag retrieval data
                    if 'rag_context' in f or 'retrieval' in f:
                         print(f"  RAG Retrieval: Present")
                    else:
                         print(f"  RAG Retrieval: (Check implementation for RAG inclusion)")
                
                print(f"\nSecurity Score: {data.get('security_score')}")
                print(f"Risk Level: {data.get('risk_level')}")
                break
                
        if status == "PENDING":
            print("Analysis timed out!")
            
if __name__ == "__main__":
    run_tests()

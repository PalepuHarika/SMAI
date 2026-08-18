import pytest
from fastapi.testclient import TestClient

# 1. Update this import to match your FastAPI app entrypoint:
from backend.main import app 

client = TestClient(app)

SAMPLE_VULNERABLE_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""

def test_full_subagent_pipeline_e2e():
    # Step 1: Coordinator (API & Auth)
    response = client.post("/api/analysis/scan", json={"source_code": SAMPLE_VULNERABLE_CONTRACT})
    assert response.status_code in [200, 202], f"Coordinator failed: {response.text}"
    data = response.json()

    # Step 2: Analyzer (Static Detection)
    findings = data.get("findings", [])
    assert len(findings) > 0, "Analyzer failed: No findings detected"
    assert any("107" in str(f.get("swc_id", "")) or "reentrancy" in str(f.get("category", "")).lower() for f in findings)

    # Step 3: Librarian (RAG Context)
    assert any(f.get("rag_context") or f.get("recommendation") for f in findings), "Librarian failed: Missing RAG context"

    # Step 4: Skeptic (LLM Reasoning & Fix)
    assert any(f.get("attack_scenario") and f.get("fixed_code") for f in findings), "Skeptic failed: Missing attack scenario or fixed code"

    # Step 5: Presentation (UI Schema Compatibility)
    assert "severity" in findings[0] or "severity" in data, "Presentation failed: Missing severity formatting"


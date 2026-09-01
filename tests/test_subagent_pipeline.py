import pytest
import uuid
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.db.database import init_db
from backend.analyzer.static_analyzer import SolidityStaticAnalyzer
from backend.analyzer.code_extractor import CodeContextExtractor
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.llm.reasoner import LLMReasoner

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_subagent_pipeline_e2e():
    """
    Implements the 5-step A-to-Z Multi-Agent Verification Topology:
    Step 1: Coordinator (FastAPI)
    Step 2: Analyzer (Static Analysis Agent)
    Step 3: Librarian (RAG Agent)
    Step 4: Skeptic (LLM Reasoning Agent)
    Step 5: Presentation (React UI Payload Match)
    """
    
    # ---------------------------------------------------------
    # Setup: Load vulnerable smart contract
    # ---------------------------------------------------------
    from pathlib import Path
    contract_path = Path(__file__).parent.parent / "contracts" / "ReentrancyVault.sol"
    with open(contract_path, 'r') as f:
        vulnerable_code = f.read()
        
    # ---------------------------------------------------------
    # [Step 2] Analyzer -> Verify Valid Line Extraction & SWC Mapping
    # ---------------------------------------------------------
    analyzer = SolidityStaticAnalyzer()
    raw_findings = analyzer.analyze(vulnerable_code, "ReentrancyVault.sol")
    
    assert len(raw_findings) > 0, "Analyzer: Expected at least one static finding."
    
    swc_107_finding = next((f for f in raw_findings if "107" in f.category or "reentrancy" in f.category.lower()), None)
    assert swc_107_finding is not None, "Analyzer: Failed to detect SWC-107 Reentrancy pattern."
    assert swc_107_finding.line_start > 0, "Analyzer: Line extraction failed (invalid line number)."
    
    # Extract Context
    extractor = CodeContextExtractor()
    context = extractor.extract(vulnerable_code, swc_107_finding)
    assert context is not None, "Analyzer: Context extraction failed."
    assert "withdraw" in context.function_name.lower() or "reentrancy" in context.function_source.lower(), "Analyzer: Did not extract the correct function context."

    # ---------------------------------------------------------
    # [Step 3] Librarian -> Verify Top-K Vector Retrieval Match
    # ---------------------------------------------------------
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    knowledge = retriever.retrieve(swc_107_finding, context, top_k=2)
    
    assert len(knowledge) > 0, "Librarian: Knowledge retrieval returned empty."
    # Check if SWC-107 specific knowledge was retrieved
    retrieved_swc_107 = any("107" in str(k.get("id", "")) or "Reentrancy" in str(k.get("name", "")) for k in knowledge)
    assert retrieved_swc_107, "Librarian: Did not retrieve exact SWC-107 mitigation context."

    # ---------------------------------------------------------
    # [Step 4] Skeptic -> Verify Valid JSON Output / Pydantic Object
    # ---------------------------------------------------------
    reasoner = LLMReasoner()
    verified_finding = await reasoner.verify_finding(swc_107_finding, context, knowledge)
    
    assert verified_finding.severity in ["Critical", "High", "Medium", "Low", "Informational"], "Skeptic: Invalid severity rating."
    assert verified_finding.verification_status in ["CONFIRMED", "REJECTED", "UNVERIFIED"], "Skeptic: Invalid verification status."
    json_dump = verified_finding.model_dump()
    assert json_dump is not None, "Skeptic: Failed to parse reasoning output to JSON schema."
    assert json_dump["vulnerability"] is not None

    # ---------------------------------------------------------
    # [Step 1] Coordinator & [Step 5] Presentation (End-to-End API)
    # ---------------------------------------------------------
    _run_id = uuid.uuid4().hex[:8]
    transport = ASGITransport(app=app)
    
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Coordinator (Auth & Submit)
        auth_response = await client.post("/auth/register", json={
            "email": f"coordinator_{_run_id}@pipeline.com",
            "password": "PipelinePassword123!",
            "role": "USER"
        })
        assert auth_response.status_code == 201, "Coordinator: RBAC Registration failed."
        token = auth_response.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        scan_response = await client.post("/api/analysis", json={
            "contract_name": "ReentrancyVault.sol",
            "source_code": vulnerable_code
        }, headers=headers)
        
        assert scan_response.status_code == 202, "Coordinator: Analysis payload submission failed."
        import asyncio
        for _ in range(10):
            poll = await client.get(f"/api/analysis/{scan_response.json()['analysis_id']}", headers=headers)
            if poll.json().get("status") != "PENDING":
                break
            await asyncio.sleep(0.5)
        scan_response = await client.get(f"/api/analysis/{scan_response.json()['analysis_id']}", headers=headers)
        
        # Step 5: Presentation (UI Agent Payload Match)
        scan_payload = scan_response.json()
        
        # Verify schema matches React UI expectations
        assert "analysis_id" in scan_payload, "Presentation: Missing analysis_id in payload."
        assert scan_payload["is_vulnerable"] is True, "Presentation: UI expected is_vulnerable to be True."
        assert "severity_counts" in scan_payload, "Presentation: Missing severity_counts map."
        assert "findings" in scan_payload, "Presentation: Missing findings array."
        assert len(scan_payload["findings"]) > 0, "Presentation: Findings array empty."
        
        ui_finding = scan_payload["findings"][0]
        # Check required Presentation UI fields
        required_ui_fields = [
            "finding_id", "vulnerability", "severity", "confidence", 
            "affected_lines", "explanation", "attack_scenario", 
            "recommendation", "fixed_code", "static_evidence", "original_code"
        ]
        for field in required_ui_fields:
            assert field in ui_finding, f"Presentation: Expected field '{field}' missing from React UI payload."
            
        print("\n[✓] A-to-Z Subagent Pipeline Verification Completed Successfully.")

import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

kb = SecurityKnowledgeBase()
retriever = RAGRetriever(kb)

# Test empty strings
finding = StaticFinding(
    id="finding1",
    category="",
    swc_id="",
    severity="High",
    confidence=0.9,
    contract="Test",
    file_path="test.sol",
    line_start=1,
    line_end=1,
    line_numbers=[1],
    function="",
    message="",
    snippet=""
)
context = CodeContext(
    file_path="test.sol",
    contract_name="Test",
    function_name="",
    function_source="function test() {}",
    line_start=1,
    line_end=1,
    modifiers=[],
    state_variables=[],
    full_source=""
)

try:
    results = retriever.retrieve(finding, context)
    print("Empty strings: Handled. Results count:", len(results))
except Exception as e:
    print(f"Empty strings: Crash - {type(e).__name__}: {e}")

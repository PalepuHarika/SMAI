import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

kb = SecurityKnowledgeBase()
retriever = RAGRetriever(kb)

def test_query(category, message, snippet):
    finding = StaticFinding(
        id="finding1",
        category=category,
        swc_id="",
        severity="High",
        confidence=0.9,
        contract="Test",
        file_path="test.sol",
        line_start=1,
        line_end=1,
        line_numbers=[1],
        function="test",
        message=message,
        snippet=snippet
    )
    context = CodeContext(
        file_path="test.sol",
        contract_name="Test",
        function_name="test",
        function_source="function test() {}",
        line_start=1,
        line_end=1,
        modifiers=[],
        state_variables=[],
        full_source=""
    )
    results = retriever.retrieve(finding, context, top_k=3)
    return [r['category'] for r in results]

print("Injection test:", test_query("integer-overflow", "overflow detected", "string memory text = 'reentrancy unchecked call tx.origin';"))

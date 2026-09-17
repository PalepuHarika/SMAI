import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

# Force KB missing
kb = SecurityKnowledgeBase(json_path="nonexistent.json")
retriever = RAGRetriever(kb)

finding = StaticFinding(
    id="f1", category="reentrancy", swc_id="", severity="High", confidence=0.9,
    contract="Test", file_path="test.sol", line_start=1, line_end=1, line_numbers=[1],
    function="test", message="test", snippet="test"
)

context = CodeContext(
    file_path="test.sol", contract_name="Test", function_name="test",
    function_source="function test() { }", line_start=1, line_end=1,
    modifiers=[], state_variables=[], full_source=""
)

results = retriever.retrieve(finding, context, top_k=3)
print("Missing KB results count:", len(results))

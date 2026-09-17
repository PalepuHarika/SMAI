import json
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

kb = SecurityKnowledgeBase()
retriever = RAGRetriever(kb)

finding = StaticFinding(
    id="f1",
    category="reentrancy",
    swc_id="SWC-107",
    severity="High",
    confidence=0.9,
    contract="Test",
    file_path="test.sol",
    line_start=1,
    line_end=1,
    line_numbers=[1],
    function="test",
    message="external call occurs before state update",
    snippet="msg.sender.call"
)

# Introduce hundreds of tokens of unrelated concepts
noise = " delegatecall timestamp tx.origin overflow unchecked " * 200

context = CodeContext(
    file_path="test.sol",
    contract_name="Test",
    function_name="test",
    function_source="function test() { " + noise + " }",
    line_start=1,
    line_end=1,
    modifiers=[],
    state_variables=[],
    full_source=""
)

results = retriever.retrieve(finding, context, top_k=3)
print("Contamination Test:")
for r in results:
    print(r['id'], r['similarity_score'])

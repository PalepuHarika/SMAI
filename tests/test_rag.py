import pytest
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

def test_rag_retrieval():
    kb = SecurityKnowledgeBase()
    assert len(kb.get_all()) > 0
    retriever = RAGRetriever(kb)
    
    finding = StaticFinding(
        id='f-1',
        contract='Vault',
        function='withdraw',
        line_start=10,
        line_end=15,
        category='reentrancy',
        confidence=0.9,
        message='External call occurs before state update',
        snippet='(bool success, ) = msg.sender.call{value: amount}("");'
    )
    context = CodeContext(
        contract_name='Vault',
        function_name='withdraw',
        function_source='function withdraw() { msg.sender.call(); balances[msg.sender] = 0; }',
        line_start=10,
        line_end=15,
        state_variables=['mapping(address => uint) balances']
    )
    
    results = retriever.retrieve(finding, context, top_k=2)
    assert len(results) > 0
    assert results[0]['id'] == 'SWC-107'
    assert 'similarity_score' in results[0]
    assert 0.0 <= results[0]['similarity_score'] <= 1.0
    assert 'relevance_reason' in results[0]

    # Test explainability summary
    top_score, expl = retriever.get_explainability_summary(results)
    assert top_score is not None
    assert "SWC-107" in expl

    # Test LLM context formatting
    formatted = retriever.format_kb_context_for_llm(results)
    assert "SWC-107" in formatted
    assert "Exploit Pattern" in formatted
    assert "Mitigation" in formatted

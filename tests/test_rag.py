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
        message='External call occurs before state update'
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

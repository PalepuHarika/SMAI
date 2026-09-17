import pytest
import json
from unittest.mock import patch, mock_open
from backend.rag.knowledge_base import SecurityKnowledgeBase
from backend.rag.retriever import RAGRetriever
from backend.core.finding import StaticFinding, CodeContext

def create_finding(category="test-category"):
    return StaticFinding(
        id="f1",
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
        message="test",
        snippet="test"
    )

def create_context():
    return CodeContext(
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

def test_kb_duplicate_entries():
    kb = SecurityKnowledgeBase()
    # Mock duplicate
    entry = {"id": "SWC-107", "category": "reentrancy", "description": "test"}
    kb.entries = [entry, entry.copy()]
    retriever = RAGRetriever(kb)
    results = retriever.retrieve(create_finding("reentrancy"), create_context())
    assert len(results) == 1  # Should deduplicate via seen_ids

def test_kb_missing_fields():
    kb = SecurityKnowledgeBase()
    # Mock missing SWC, missing category, wrong types
    kb.entries = [
        {"id": "SWC-999"}, # Missing category
        {"category": "test1"}, # Missing id
        {"id": "SWC-888", "category": "test2", "description": 123}, # Wrong type for description
    ]
    retriever = RAGRetriever(kb)
    results = retriever.retrieve(create_finding("test2"), create_context())
    assert len(results) >= 0 # Should not crash

def test_kb_empty_list():
    kb = SecurityKnowledgeBase()
    kb.entries = []
    retriever = RAGRetriever(kb)
    results = retriever.retrieve(create_finding(), create_context())
    assert len(results) == 0

def test_kb_unknown_category():
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    results = retriever.retrieve(create_finding("unknown-category"), create_context())
    assert isinstance(results, list) # Should fall back to TF-IDF or return empty

def test_empty_invalid_queries():
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    context = create_context()
    
    # Test empty query strings inside the finding
    empty_finding = StaticFinding(
        id="f1",
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
    results = retriever.retrieve(empty_finding, context)
    assert isinstance(results, list)

    whitespace_finding = StaticFinding(
        id="f1", category=" ", swc_id=" ", severity="High", confidence=0.9,
        contract="Test", file_path="test.sol", line_start=1, line_end=1, line_numbers=[1],
        function=" ", message=" \n ", snippet=" "
    )
    results2 = retriever.retrieve(whitespace_finding, context)
    assert isinstance(results2, list)

    long_finding = StaticFinding(
        id="f1", category="reentrancy", swc_id="", severity="High", confidence=0.9,
        contract="Test", file_path="test.sol", line_start=1, line_end=1, line_numbers=[1],
        function="A"*10000, message="B"*10000, snippet="C"*10000
    )
    results3 = retriever.retrieve(long_finding, context)
    assert isinstance(results3, list)

def test_cross_vulnerability_confusion():
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    context = create_context()

    f_reen = create_finding("")
    f_reen.message = "external call occurs before state update msg.sender.call"
    r_reen = retriever.retrieve(f_reen, context)
    
    f_unc = create_finding("")
    f_unc.message = "return value of low level call is ignored msg.sender.call"
    r_unc = retriever.retrieve(f_unc, context)

    # They should retrieve different top-1
    if r_reen and r_unc:
        assert r_reen[0]['id'] != r_unc[0]['id']

def test_negative_retrieval():
    kb = SecurityKnowledgeBase()
    retriever = RAGRetriever(kb)
    context = create_context()
    
    # Safe code
    f_safe = create_finding("")
    f_safe.message = "uses checked arithmetic in Solidity 0.8"
    f_safe.snippet = "balances[msg.sender] -= amount"
    r_safe = retriever.retrieve(f_safe, context)
    
    # It might retrieve integer-overflow because of keyword overlap, but similarity should be low
    if r_safe:
        assert r_safe[0]['similarity_score'] < 0.60
